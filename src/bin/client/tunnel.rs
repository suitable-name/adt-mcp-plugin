//! The `/tunnel` WebSocket (`docs/plan-e2e-envelope.md` §2, P4): one persistent connection
//! per client process, authenticated with the profile's relay certificate, multiplexing any
//! number of streams. The client chooses the stream IDs.
//!
//! Two tasks own the socket: a reader that routes control and data frames to the stream they
//! belong to, and a writer that drains one outgoing queue, so no stream can stall another's
//! sends. A [`Stream`] sees its frames as [`Event`]s, in order, and ends (`next` returns
//! `None`) when the peer closes it or the tunnel dies.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, anyhow};
use async_tungstenite::{WebSocketReceiver, WebSocketSender, client_async, tungstenite::Message};
use futures_rustls::{TlsConnector, client::TlsStream};
use futures_util::StreamExt;
use rustls::pki_types::ServerName;
use smol::{
    Task,
    channel::{self, Receiver, Sender},
    net::TcpStream,
};

use crate::{
    rt,
    transport::{Profile, endpoint},
    tunnel_proto::{Control, decode_data, encode_data_chunks},
};

/// TCP, TLS and WebSocket handshake together.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
/// Frames queued towards the relay before senders wait.
const OUTGOING_FRAMES: usize = 64;
/// Events queued for one stream before the reader waits for it.
const STREAM_EVENTS: usize = 256;
/// How long `shutdown` waits for the writer to flush.
const FLUSH_TIMEOUT: Duration = Duration::from_secs(5);

type Socket = TlsStream<TcpStream>;

/// What a stream receives, in the order the relay sent it.
#[derive(Debug)]
pub enum Event {
    Control(Control),
    /// Payload of one data frame: inner TLS bytes.
    Data(Vec<u8>),
}

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

struct Shared {
    outgoing: Sender<Message>,
    streams: Mutex<HashMap<u32, Sender<Event>>>,
    next_id: AtomicU32,
    closed: AtomicBool,
}

impl Shared {
    fn new(outgoing: Sender<Message>) -> Self {
        Self {
            outgoing,
            streams: Mutex::new(HashMap::new()),
            next_id: AtomicU32::new(1),
            closed: AtomicBool::new(false),
        }
    }

    fn sender(&self, id: u32) -> Option<Sender<Event>> {
        locked(&self.streams).get(&id).cloned()
    }

    async fn deliver(&self, id: u32, event: Event) {
        if let Some(sender) = self.sender(id) {
            // A stream that no longer listens has already left the registry.
            let _ = sender.send(event).await;
        }
    }

    fn forget(&self, id: u32) {
        locked(&self.streams).remove(&id);
    }

    /// The socket is gone: every stream ends and nothing more is sent.
    fn fail_all(&self) {
        self.closed.store(true, Ordering::Release);
        locked(&self.streams).clear();
        self.outgoing.close();
    }

    async fn send(&self, message: Message) -> Result<()> {
        self.outgoing
            .send(message)
            .await
            .map_err(|_| anyhow!("The relay tunnel is closed."))
    }
}

async fn read_loop(mut receiver: WebSocketReceiver<Socket>, shared: Arc<Shared>) {
    while let Some(Ok(message)) = receiver.next().await {
        match message {
            Message::Text(text) => match Control::decode(text.as_str()) {
                Ok(control) => {
                    let (id, closing) =
                        (control.stream(), matches!(control, Control::Close { .. }));
                    shared.deliver(id, Event::Control(control)).await;
                    if closing {
                        shared.forget(id);
                    }
                }
                Err(error) => {
                    eprintln!("The relay sent an invalid tunnel frame: {error}");
                    break;
                }
            },
            Message::Binary(bytes) => match decode_data(&bytes[..]) {
                Ok((id, payload)) => shared.deliver(id, Event::Data(payload.to_vec())).await,
                Err(error) => {
                    eprintln!("The relay sent an invalid tunnel frame: {error}");
                    break;
                }
            },
            Message::Close(_) => break,
            // The relay pings every 30 s. Answer through the writer so an idle socket
            // still flushes the pong.
            Message::Ping(payload) => {
                if shared.send(Message::Pong(payload)).await.is_err() {
                    break;
                }
            }
            _ => {}
        }
    }
    shared.fail_all();
}

async fn write_loop(
    mut sender: WebSocketSender<Socket>,
    outgoing: Receiver<Message>,
    shared: Arc<Shared>,
) {
    while let Ok(message) = outgoing.recv().await {
        if sender.send(message).await.is_err() {
            shared.fail_all();
            return;
        }
    }
    let _ = sender.close(None).await;
}

/// One WebSocket to the relay's `/tunnel`.
#[derive(Clone)]
pub struct Tunnel {
    shared: Arc<Shared>,
    tasks: Arc<Mutex<Vec<Task<()>>>>,
}

impl Tunnel {
    /// Connects with the profile's mutual-TLS credentials.
    ///
    /// # Errors
    /// The relay is unreachable, refuses the certificate or does not serve `/tunnel`.
    pub async fn connect(profile: &Profile) -> Result<Self> {
        let config = profile.tls_config()?;
        let mut url = endpoint(&profile.server, "/tunnel")?;
        url.set_scheme("wss")
            .map_err(|()| anyhow!("Cannot derive the tunnel URL."))?;
        let host = url
            .host_str()
            .context("The relay URL has no host.")?
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned();
        let port = url
            .port_or_known_default()
            .context("The relay URL has no port.")?;
        let name = ServerName::try_from(host.clone())
            .map_err(|_| anyhow!("The relay host name is not valid."))?;
        let socket = rt::timeout(
            CONNECT_TIMEOUT,
            Box::pin(async {
                // `std` sockets are not inheritable on Windows, unlike the ones async-io connects.
                let std_stream =
                    smol::unblock(move || std::net::TcpStream::connect((host.as_str(), port)))
                        .await?;
                std_stream.set_nodelay(true)?;
                let stream = TcpStream::try_from(std_stream)?;
                let tls = TlsConnector::from(Arc::new(config))
                    .connect(name, stream)
                    .await?;
                let (socket, _) = client_async(url.as_str(), tls).await?;
                anyhow::Ok(socket)
            }),
        )
        .await
        .map_err(|_| anyhow!("Timed out connecting to the relay tunnel."))?
        .context("Could not open the relay tunnel over mutual TLS.")?;
        let (sender, receiver) = socket.split();
        let (outgoing, queue) = channel::bounded(OUTGOING_FRAMES);
        let shared = Arc::new(Shared::new(outgoing));
        let tasks = vec![
            rt::spawn(read_loop(receiver, shared.clone())),
            rt::spawn(write_loop(sender, queue, shared.clone())),
        ];
        Ok(Self {
            shared,
            tasks: Arc::new(Mutex::new(tasks)),
        })
    }

    /// Whether the socket is still up.
    #[must_use]
    pub fn is_open(&self) -> bool {
        !self.shared.closed.load(Ordering::Acquire)
    }

    /// Opens a stream to the Eclipse `endpoint` (an endpoint ID). The relay checks the grant;
    /// a refusal arrives as a `Close` event.
    ///
    /// # Errors
    /// The tunnel is closed.
    pub async fn open_stream(&self, endpoint: &str) -> Result<Stream> {
        let id = self.shared.next_id.fetch_add(1, Ordering::Relaxed);
        let (events_in, events) = channel::bounded(STREAM_EVENTS);
        locked(&self.shared.streams).insert(id, events_in);
        let stream = Stream {
            id,
            shared: self.shared.clone(),
            events,
        };
        stream
            .control(&Control::Open {
                stream: id,
                endpoint: endpoint.to_owned(),
                desktop: None,
                label: None,
            })
            .await?;
        Ok(stream)
    }

    /// Flushes what is queued, closes the socket and stops both tasks.
    pub async fn shutdown(&self) {
        self.shared.outgoing.close();
        let tasks = std::mem::take(&mut *locked(&self.tasks));
        let mut tasks = tasks.into_iter();
        // Reader first in the list, writer last: wait for the writer to flush and close.
        let reader = tasks.next();
        if let Some(writer) = tasks.next() {
            let _ = rt::timeout(FLUSH_TIMEOUT, writer).await;
        }
        drop(reader);
        self.shared.fail_all();
    }
}

#[cfg(test)]
impl Tunnel {
    /// A tunnel with no socket: the test reads what the client sends from the returned queue
    /// and plays the relay with [`Self::inject`].
    pub fn detached() -> (Self, Receiver<Message>) {
        let (outgoing, queue) = channel::bounded(OUTGOING_FRAMES);
        let tunnel = Self {
            shared: Arc::new(Shared::new(outgoing)),
            tasks: Arc::new(Mutex::new(Vec::new())),
        };
        (tunnel, queue)
    }

    /// Delivers `event` to `stream` as if the relay had sent it.
    pub async fn inject(&self, stream: u32, event: Event) {
        self.shared.deliver(stream, event).await;
    }
}

/// One multiplexed stream. Dropping it closes it.
pub struct Stream {
    id: u32,
    shared: Arc<Shared>,
    events: Receiver<Event>,
}

impl Stream {
    /// Sends a control frame for this stream.
    ///
    /// # Errors
    /// The frame is too large or the tunnel is closed.
    pub async fn control(&self, control: &Control) -> Result<()> {
        let text = control.encode()?;
        self.shared.send(Message::Text(text.into())).await
    }

    /// Sends `bytes` as data frames of at most 64 KiB.
    ///
    /// # Errors
    /// The tunnel is closed.
    pub async fn data(&self, bytes: &[u8]) -> Result<()> {
        for frame in encode_data_chunks(self.id, bytes) {
            self.shared.send(Message::Binary(frame.into())).await?;
        }
        Ok(())
    }

    /// The next frame for this stream; `None` once the stream or the tunnel has ended.
    pub async fn recv(&self) -> Option<Event> {
        self.events.recv().await.ok()
    }

    #[must_use]
    pub const fn id(&self) -> u32 {
        self.id
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        self.shared.forget(self.id);
        let close = Control::Close {
            stream: self.id,
            reason: "done".into(),
        };
        if let Ok(text) = close.encode() {
            let _ = self.shared.outgoing.try_send(Message::Text(text.into()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel_proto::MAX_DATA_PAYLOAD;

    fn detached() -> (Tunnel, Receiver<Message>) {
        Tunnel::detached()
    }

    fn text(message: &Message) -> Control {
        match message {
            Message::Text(text) => Control::decode(text.as_str()).unwrap(),
            other => panic!("expected a control frame, got {other:?}"),
        }
    }

    #[test]
    fn streams_get_client_chosen_ids_and_receive_only_their_frames() {
        smol::block_on(async {
            let (tunnel, queue) = detached();
            let endpoint = "ab".repeat(32);
            let first = tunnel.open_stream(&endpoint).await.unwrap();
            let second = tunnel.open_stream(&endpoint).await.unwrap();
            assert_eq!((first.id(), second.id()), (1, 2));
            assert!(matches!(
                text(&queue.recv().await.unwrap()),
                Control::Open { stream: 1, .. }
            ));
            queue.recv().await.unwrap();
            tunnel.shared.deliver(2, Event::Data(vec![1, 2, 3])).await;
            tunnel.shared.deliver(1, Event::Data(vec![9])).await;
            assert!(matches!(second.recv().await, Some(Event::Data(bytes)) if bytes == [1, 2, 3]));
            assert!(matches!(first.recv().await, Some(Event::Data(bytes)) if bytes == [9]));
        });
    }

    #[test]
    fn data_is_split_into_frames_and_a_dropped_stream_sends_close() {
        smol::block_on(async {
            let (tunnel, queue) = detached();
            let stream = tunnel.open_stream(&"cd".repeat(32)).await.unwrap();
            queue.recv().await.unwrap();
            stream.data(&vec![7; MAX_DATA_PAYLOAD + 10]).await.unwrap();
            for expected in [MAX_DATA_PAYLOAD, 10] {
                match queue.recv().await.unwrap() {
                    Message::Binary(frame) => {
                        let (id, payload) = decode_data(&frame[..]).unwrap();
                        assert_eq!((id, payload.len()), (1, expected));
                    }
                    other => panic!("expected data, got {other:?}"),
                }
            }
            drop(stream);
            assert!(matches!(
                text(&queue.recv().await.unwrap()),
                Control::Close { stream: 1, .. }
            ));
        });
    }

    #[test]
    fn a_dead_tunnel_ends_every_stream() {
        smol::block_on(async {
            let (tunnel, _queue) = detached();
            let stream = tunnel.open_stream(&"ab".repeat(32)).await.unwrap();
            assert!(tunnel.is_open());
            tunnel.shared.fail_all();
            assert!(!tunnel.is_open());
            assert!(stream.recv().await.is_none());
            assert!(
                stream
                    .control(&Control::Close {
                        stream: 1,
                        reason: String::new()
                    })
                    .await
                    .is_err()
            );
        });
    }
}
