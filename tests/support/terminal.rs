use std::{
    io::{self, Read, Write},
    sync::{Arc, Mutex},
};

use anyhow::Result;
use portable_pty::{MasterPty, PtySize};
use tokio::sync::watch;

type Keyboard = Arc<Mutex<Box<dyn Write + Send>>>;

pub struct Terminal {
    pub(super) screen: watch::Receiver<String>,
    keyboard: Keyboard,
}

impl Terminal {
    /// Attach before spawning the child. `ConPTY` can request the cursor position during startup.
    pub(super) fn attach(master: &dyn MasterPty, size: PtySize) -> Result<Self> {
        let mut reader = master.try_clone_reader()?;
        let keyboard = Arc::new(Mutex::new(master.take_writer()?));
        let replies = Arc::clone(&keyboard);
        let (output, screen) = watch::channel(String::new());
        std::thread::Builder::new()
            .name("test-terminal".into())
            .spawn(move || {
                let mut terminal = vt100::Parser::new(size.rows, size.cols, 0);
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
                    let _ = output.send(terminal.screen().contents());
                }
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
