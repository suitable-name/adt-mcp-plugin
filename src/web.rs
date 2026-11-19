//! Small HTTP helpers on top of `trillium-http`: a buffered response type and
//! an I/O wrapper that replays bytes the HTTP parser already read.

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use serde::Serialize;
use smol::io::{AsyncRead, AsyncWrite};
use trillium_http::{Conn, HeaderName, HeaderValues, Headers, KnownHeaderName, Status};

/// A complete, buffered HTTP response.
pub struct Reply {
    status: Status,
    headers: Headers,
    body: Vec<u8>,
}

impl From<Status> for Reply {
    fn from(status: Status) -> Self {
        Self {
            status,
            headers: Headers::new(),
            body: Vec::new(),
        }
    }
}

impl Reply {
    /// A plain-text response.
    pub fn text(status: Status, body: &str) -> Self {
        let mut reply = Self::from(status);
        reply.body = body.as_bytes().to_vec();
        reply.with_header(KnownHeaderName::ContentType, "text/plain; charset=utf-8")
    }

    /// A JSON response. A value that cannot be serialized yields a 500.
    pub fn json<T: Serialize + ?Sized>(status: Status, value: &T) -> Self {
        serde_json::to_vec(value).map_or_else(
            |_| Self::from(Status::InternalServerError),
            |body| {
                let mut reply = Self::from(status);
                reply.body = body;
                reply.with_header(KnownHeaderName::ContentType, "application/json")
            },
        )
    }

    /// Set a response header, replacing any earlier value.
    #[must_use]
    pub fn with_header(
        mut self,
        name: impl Into<HeaderName<'static>>,
        value: impl Into<HeaderValues>,
    ) -> Self {
        self.headers.insert(name, value);
        self
    }

    /// Write this response onto the connection.
    pub fn into_conn<T>(self, mut conn: Conn<T>) -> Conn<T>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    {
        conn.set_status(self.status);
        conn.response_headers_mut().insert_all(self.headers);
        if !self.body.is_empty() {
            conn.set_response_body(self.body);
        }
        conn
    }
}

/// Whether the media type of the `Content-Type` header is `application/json`.
pub fn is_json(headers: &Headers) -> bool {
    headers
        .get_str(KnownHeaderName::ContentType)
        .and_then(|media| media.split(';').next())
        .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"))
}

/// An I/O stream that first yields bytes the HTTP parser had already read
/// from it, then reads from the stream itself.
pub struct Prefixed<T> {
    prefix: Vec<u8>,
    offset: usize,
    inner: T,
}

impl<T> Prefixed<T> {
    pub const fn new(prefix: Vec<u8>, inner: T) -> Self {
        Self {
            prefix,
            offset: 0,
            inner,
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for Prefixed<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if this.offset < this.prefix.len() {
            let pending = &this.prefix[this.offset..];
            let count = pending.len().min(buf.len());
            buf[..count].copy_from_slice(&pending[..count]);
            this.offset += count;
            return Poll::Ready(Ok(count));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Prefixed<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}
