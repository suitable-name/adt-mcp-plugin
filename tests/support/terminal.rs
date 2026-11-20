use std::{
    io::{self, Read, Write},
    num::NonZero,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::Duration,
};

use anyhow::{Result, bail};
use portable_pty::{MasterPty, PtySize};
use smol::Timer;

type Keyboard = Arc<Mutex<Box<dyn Write + Send>>>;

struct ScreenState {
    contents: String,
    closed: bool,
}

/// The latest rendered terminal text, shared between the reader thread and the test.
#[derive(Clone)]
pub struct Screen {
    state: Arc<Mutex<ScreenState>>,
}

impl Screen {
    fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(ScreenState {
                contents: String::new(),
                closed: false,
            })),
        }
    }

    fn lock(&self) -> MutexGuard<'_, ScreenState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn publish(&self, contents: String) {
        self.lock().contents = contents;
    }

    fn close(&self) {
        self.lock().closed = true;
    }

    /// Wait until `ready` accepts the screen text; fails once the terminal output has ended.
    pub(super) async fn wait_for(
        &self,
        mut ready: impl FnMut(&str) -> bool + Send,
    ) -> Result<String> {
        loop {
            {
                let state = self.lock();
                if ready(&state.contents) {
                    return Ok(state.contents.clone());
                }
                if state.closed {
                    bail!("The terminal output ended.");
                }
            }
            Timer::after(Duration::from_millis(25)).await;
        }
    }
}

pub struct Terminal {
    pub(super) screen: Screen,
    keyboard: Keyboard,
}

impl Terminal {
    /// Attach before spawning the child. `ConPTY` can request the cursor position during startup.
    pub(super) fn attach(master: &dyn MasterPty, size: PtySize) -> Result<Self> {
        let (Some(rows), Some(cols)) = (NonZero::new(size.rows), NonZero::new(size.cols)) else {
            bail!("The test terminal needs at least one row and one column.");
        };
        let mut reader = master.try_clone_reader()?;
        let keyboard = Arc::new(Mutex::new(master.take_writer()?));
        let replies = Arc::clone(&keyboard);
        let screen = Screen::new();
        let output = screen.clone();
        std::thread::Builder::new()
            .name("test-terminal".into())
            .spawn(move || {
                let mut terminal = vt100::Parser::new(rows, cols, 0);
                let mut matched = 0;
                let mut bytes = [0; 8192];
                loop {
                    let length = match reader.read(&mut bytes) {
                        Ok(0) => break,
                        Ok(length) => length,
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        Err(_) => break,
                    };
                    if process(&mut terminal, &bytes[..length], &mut matched, &replies).is_err() {
                        break;
                    }
                    // Drain the pipe through shutdown even if the observer has already exited.
                    output.publish(terminal.screen().contents());
                }
                output.close();
            })?;
        Ok(Self { screen, keyboard })
    }

    pub(super) fn keys(&self, bytes: &[u8]) -> Result<()> {
        Ok(write_input(&self.keyboard, bytes)?)
    }
}

fn write_input(keyboard: &Keyboard, bytes: &[u8]) -> io::Result<()> {
    let mut writer = keyboard
        .lock()
        .map_err(|_| io::Error::other("Terminal input lock was poisoned."))?;
    writer.write_all(bytes)?;
    writer.flush()
}

fn process(
    terminal: &mut vt100::Parser,
    bytes: &[u8],
    matched: &mut usize,
    keyboard: &Keyboard,
) -> io::Result<()> {
    const QUERY: &[u8] = b"\x1b[6n";
    let mut start = 0;
    for (index, &byte) in bytes.iter().enumerate() {
        if byte == QUERY[*matched] {
            *matched += 1;
            if *matched == QUERY.len() {
                terminal.process(&bytes[start..=index]);
                let (row, column) = terminal.screen().cursor_position();
                let report = format!("\x1b[{};{}R", row + 1, column + 1);
                write_input(keyboard, report.as_bytes())?;
                *matched = 0;
                start = index + 1;
            }
        } else {
            *matched = usize::from(byte == QUERY[0]);
        }
    }
    terminal.process(&bytes[start..]);
    Ok(())
}
