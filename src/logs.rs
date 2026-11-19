use std::{
    collections::VecDeque,
    io::{self, Write},
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

use tracing_subscriber::fmt::MakeWriter;

const MAX_ENTRIES: usize = 512;
const MAX_ENTRY_BYTES: usize = 2048;

#[derive(Clone, Default)]
pub struct Logs(Arc<Mutex<VecDeque<String>>>);

impl Logs {
    fn entries(&self) -> MutexGuard<'_, VecDeque<String>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn visible(&self, limit: usize, offset: &mut usize) -> Vec<String> {
        let entries = self.entries();
        *offset = (*offset).min(entries.len().saturating_sub(limit));
        let end = entries.len() - *offset;
        entries
            .range(end.saturating_sub(limit)..end)
            .cloned()
            .collect()
    }
}

pub struct Record<'a> {
    logs: &'a Logs,
    bytes: Vec<u8>,
}

impl<'a> MakeWriter<'a> for Logs {
    type Writer = Record<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        Record {
            logs: self,
            bytes: Vec::new(),
        }
    }
}

impl Write for Record<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let keep = bytes.len().min(MAX_ENTRY_BYTES - self.bytes.len());
        self.bytes.extend_from_slice(&bytes[..keep]);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for Record<'_> {
    fn drop(&mut self) {
        let raw = String::from_utf8_lossy(&self.bytes);
        let lower = raw.to_ascii_lowercase();
        let entry = if ["gw1-", "private key", "authorization:", "bearer "]
            .iter()
            .any(|&s| lower.contains(s))
        {
            "A sensitive log entry was redacted.".into()
        } else {
            raw.trim_end()
                .chars()
                .map(|c| if c.is_control() { ' ' } else { c })
                .collect()
        };
        let mut entries = self.logs.entries();
        if entries.len() == MAX_ENTRIES {
            entries.pop_front();
        }
        entries.push_back(entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_are_bounded_and_credentials_are_redacted_across_writes() {
        let logs = Logs::default();
        for i in 0..MAX_ENTRIES {
            writeln!(logs.make_writer(), "Event {i}").unwrap();
        }
        {
            let mut writer = logs.make_writer();
            writer.write_all(b"GW").unwrap();
            writer.write_all(b"1-example").unwrap();
        }
        let events = logs.visible(MAX_ENTRIES, &mut 0);
        assert_eq!(events.len(), MAX_ENTRIES);
        assert_eq!(events[0], "Event 1");
        assert_eq!(
            events.last().unwrap(),
            "A sensitive log entry was redacted."
        );
    }
}
