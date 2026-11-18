//! Line-oriented enrollment for a headless server with an attached operator.
//! Both directions use the controlling terminal independently of standard I/O.

#[cfg(unix)]
#[path = "console/unix.rs"]
mod device;
#[cfg(windows)]
#[path = "console/windows.rs"]
mod device;

use std::{
    future::Future,
    io::Write,
    sync::{Arc, atomic::{AtomicBool, Ordering}},
    time::Duration,
};

use anyhow::{Context, Result};
use device::{Input, Output};

use crate::enrollment::{ApplicantRow, Enrollment};

const HELP: &str = "Commands: pending, approve <number>, deny <number>, open, close, help, quit.";
const MAX_LINE: usize = 256;

/// A read yields a short chunk, an idle terminal, or terminal EOF.
enum ReadEvent {
    Data(Vec<u8>),
    Idle,
    End,
}

struct Operator {
    gate: Enrollment,
    shown: Vec<ApplicantRow>,
    output: Output,
}

impl Drop for Operator {
    fn drop(&mut self) {
        self.gate.set_open(false);
    }
}

impl Operator {
    fn display(&mut self, all: bool) -> Result<()> {
        let (open, rows) = self.gate.snapshot();
        if all {
            writeln!(self.output, "Enrollment is {}.", if open { "open" } else { "closed" })?;
            if rows.is_empty() {
                writeln!(self.output, "No pending requests.")?;
            }
        }
        let mut printed = false;
        for row in &rows {
            if all || !self.shown.contains(row) {
                writeln!(self.output, "Pending {} role={} label={:?} peer={} number={}", row.id, row.role, row.label, row.peer, row.number)?;
                printed = true;
            }
        }
        if printed {
            writeln!(self.output, "Compare the full ID, role, and label with the requester. Enter approve <number> or deny <number>.")?;
        }
        self.output.flush()?;
        self.shown = rows;
        Ok(())
    }

    fn decide(&mut self, text: &str, approve: bool) -> Result<()> {
        let number = text.parse::<u64>().ok();
        let Some(row) = self.shown.iter().find(|row| Some(row.number) == number) else {
            writeln!(self.output, "No displayed request has that number. Enter pending to review requests.")?;
            return Ok(());
        };
        let result = if approve {
            self.gate.approve_to(row, &mut self.output)
        } else {
            self.gate.deny(row)
        };
        match result {
            Ok(()) if approve => writeln!(self.output, "Give the token to the verified requester over a trusted channel. It expires in 180 seconds.")?,
            Ok(()) => writeln!(self.output, "Request denied.")?,
            Err(error) => writeln!(self.output, "Decision failed. {error}")?,
        }
        self.output.flush()?;
        Ok(())
    }

    fn command(&mut self, text: &str) -> Result<bool> {
        let mut fields = text.split_ascii_whitespace();
        match (fields.next(), fields.next(), fields.next()) {
            (None, _, _) => {}
            (Some("approve"), Some(number), None) => self.decide(number, true)?,
            (Some("deny"), Some(number), None) => self.decide(number, false)?,
            (Some("pending"), None, None) => self.display(true)?,
            (Some(command @ ("open" | "close")), None, None) => {
                self.gate.set_open(command == "open");
                self.display(true)?;
            }
            (Some("quit"), None, None) => return Ok(false),
            _ => writeln!(self.output, "{HELP}")?,
        }
        self.output.flush()?;
        Ok(true)
    }

    fn interact(&mut self, input: &mut Input, stop: &AtomicBool) -> Result<()> {
        let mut line = String::new();
        let mut invalid = false;
        while !stop.load(Ordering::Acquire) {
            // Process input only against the rows already shown. Each decision also verifies
            // the original generation under the enrollment lock before it can issue a token.
            match input.read_event()? {
                ReadEvent::Data(bytes) => {
                    for byte in bytes {
                        match byte {
                            b'\n' | b'\r' => {
                                if invalid {
                                    writeln!(self.output, "Enter an ASCII command of up to {MAX_LINE} characters.")?;
                                } else if !self.command(&line)? {
                                    return Ok(());
                                }
                                line.clear();
                                invalid = false;
                            }
                            b' '..=b'~' if line.len() < MAX_LINE => line.push(char::from(byte)),
                            _ => invalid = true,
                        }
                    }
                }
                ReadEvent::End => return Ok(()),
                ReadEvent::Idle => {
                    self.display(false)?;
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
        Ok(())
    }
}

struct Stop(Arc<AtomicBool>);

impl Drop for Stop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

pub async fn run(enrollment: Enrollment, service: impl Future<Output = Result<()>>) -> Result<()> {
    // Validate the actual OS terminal, including a successful write, before binding either listener.
    let (mut input, mut output) = device::open().context("Headless enrollment requires a controlling terminal.")?;
    writeln!(output, "Enrollment approval console ready.")?;
    writeln!(output, "{HELP}")?;
    output.flush()?;
    let stop = Stop(Arc::new(AtomicBool::new(false)));
    let signal = Arc::clone(&stop.0);
    let mut task = tokio::task::spawn_blocking(move || {
        let mut operator = Operator { gate: enrollment, shown: Vec::new(), output };
        operator.interact(&mut input, &signal)
    });
    tokio::select! {
        result = &mut task => result?,
        result = service => {
            drop(stop);
            task.await??;
            result
        }
    }
}
