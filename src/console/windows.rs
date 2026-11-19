use std::{
    fs::{File, OpenOptions},
    io::{self, Write},
    os::windows::io::AsRawHandle,
    ptr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, TryRecvError},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use windows_sys::Win32::System::{
    Console::{GetConsoleMode, ReadConsoleW, WriteConsoleW},
    IO::CancelSynchronousIo,
};
use zeroize::Zeroizing;

use super::ReadEvent;

pub(super) struct Output(File);

impl Write for Output {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let text = std::str::from_utf8(bytes).map_err(io::Error::other)?;
        let mut units = Zeroizing::new(Vec::with_capacity(text.len()));
        for unit in text.encode_utf16() {
            if unit == u16::from(b'\n') {
                units.push(u16::from(b'\r'));
            }
            units.push(unit);
        }
        let mut tail = units.as_slice();
        while !tail.is_empty() {
            let len = u32::try_from(tail.len()).map_err(io::Error::other)?;
            let mut written = 0;
            // SAFETY: the owned output handle and UTF-16 buffer remain valid through this
            // synchronous call. written points to writable DWORD storage.
            let ok = unsafe {
                WriteConsoleW(
                    self.0.as_raw_handle(),
                    tail.as_ptr(),
                    len,
                    &raw mut written,
                    ptr::null(),
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            if written == 0 {
                return Err(io::Error::from(io::ErrorKind::WriteZero));
            }
            tail = &tail[written as usize..];
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        // WriteConsoleW writes directly to the active console screen buffer.
        Ok(())
    }
}

fn console_device(name: &str, write: bool) -> io::Result<File> {
    let file = OpenOptions::new().read(true).write(write).open(name)?;
    let mut mode = 0;
    // SAFETY: both the owned device handle and output value remain valid for GetConsoleMode.
    if unsafe { GetConsoleMode(file.as_raw_handle(), &raw mut mode) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(file)
}

fn read_console(file: &File) -> io::Result<ReadEvent> {
    let mut units = [0_u16; 256];
    let mut count = 0;
    // SAFETY: ReadConsoleW receives the number of UTF-16 units available in the buffer,
    // a valid CONIN$ handle, and writable storage for the resulting unit count.
    let ok = unsafe {
        ReadConsoleW(
            file.as_raw_handle(),
            units.as_mut_ptr().cast(),
            256,
            &raw mut count,
            ptr::null(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    if count == 0 || units[0] == 26 {
        return Ok(ReadEvent::End);
    }
    // The operator command language is ASCII; preserve invalid characters as an invalid byte.
    Ok(ReadEvent::Data(
        units[..count as usize]
            .iter()
            .map(|&c| u8::try_from(c).unwrap_or(255))
            .collect(),
    ))
}

pub(super) struct Input {
    inbox: Option<Receiver<io::Result<ReadEvent>>>,
    thread: JoinHandle<()>,
    stop: Arc<AtomicBool>,
}

pub(super) fn open() -> io::Result<(Input, Output)> {
    let source = console_device("CONIN$", false)?;
    let output = Output(console_device("CONOUT$", true)?);
    let (sender, inbox) = mpsc::sync_channel(1);
    let stop = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&stop);
    // Cooked console input provides native line editing. This reader owns no enrollment
    // state, credentials, or output handle. Screen output never waits for a command.
    let thread = thread::Builder::new()
        .name("enrollment-input".into())
        .spawn(move || {
            while !signal.load(Ordering::Acquire) {
                let event = read_console(&source);
                let last = !matches!(event, Ok(ReadEvent::Data(_)));
                if sender.send(event).is_err() || last {
                    break;
                }
            }
        })?;
    Ok((
        Input {
            inbox: Some(inbox),
            thread,
            stop,
        },
        output,
    ))
}

impl Input {
    pub(super) fn read_event(&mut self) -> io::Result<ReadEvent> {
        let inbox = self
            .inbox
            .as_mut()
            .ok_or_else(|| io::Error::other("The console reader is closed."))?;
        match inbox.try_recv() {
            Ok(event) => event,
            Err(TryRecvError::Empty) => Ok(ReadEvent::Idle),
            Err(TryRecvError::Disconnected) => Ok(ReadEvent::End),
        }
    }
}

impl Drop for Input {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        // Wake a worker blocked on a full channel; also cancel a pending cooked console read.
        drop(self.inbox.take());
        for _ in 0..8 {
            if self.thread.is_finished() {
                break;
            }
            // SAFETY: JoinHandle retains a valid OS thread handle for this entire loop.
            // ERROR_NOT_FOUND is normal if cancellation races the start/end of the read.
            unsafe {
                CancelSynchronousIo(self.thread.as_raw_handle());
            }
            thread::sleep(Duration::from_millis(5));
        }
        // Never block process shutdown waiting for an operator to press Enter.
    }
}
