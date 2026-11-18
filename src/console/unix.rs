use std::{
    fs::{File, OpenOptions},
    io::{self, IsTerminal, Read},
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
};

use super::ReadEvent;

pub(super) type Output = File;
pub(super) struct Input(File);

fn check_foreground(file: &File) -> io::Result<()> {
    // SAFETY: the file owns this descriptor throughout both calls. Neither function changes it.
    let foreground = unsafe { libc::tcgetpgrp(file.as_raw_fd()) };
    if foreground == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: getpgrp reads this process's group ID and has no arguments.
    if foreground != unsafe { libc::getpgrp() } {
        return Err(io::Error::other("Run the approval console in the foreground."));
    }
    Ok(())
}

pub(super) fn open() -> io::Result<(Input, Output)> {
    let terminal = OpenOptions::new().read(true).write(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY).open("/dev/tty")?;
    if !terminal.is_terminal() {
        return Err(io::Error::other("The controlling device is not a terminal."));
    }
    check_foreground(&terminal)?;
    Ok((Input(terminal.try_clone()?), terminal))
}

impl Input {
    pub(super) fn read_event(&mut self) -> io::Result<ReadEvent> {
        check_foreground(&self.0)?;
        let mut bytes = [0; 512];
        match self.0.read(&mut bytes) {
            Ok(0) => Ok(ReadEvent::End),
            Ok(len) => Ok(ReadEvent::Data(bytes[..len].to_vec())),
            Err(err) if matches!(err.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => Ok(ReadEvent::Idle),
            Err(err) => Err(err),
        }
    }
}
