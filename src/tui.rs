mod endpoints;
mod render;
mod rules;

use std::{
    future::Future,
    io::{self, IsTerminal, Write},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use crossterm::{
    cursor::Show,
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};
use zeroize::Zeroizing;

use crate::{
    enrollment::{ApplicantRow, Enrollment},
    logs::Logs,
    policy::PolicyStore,
    security::{EnrolledClient, Pki},
};
use endpoints::EndpointEditor;
use rules::Editor;

const MIN_COLUMNS: u16 = 54;
const MIN_ROWS: u16 = 18;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Enrollment,
    Clients,
    Rules,
    Logs,
}

impl Tab {
    const ALL: [Self; 4] = [Self::Enrollment, Self::Clients, Self::Rules, Self::Logs];

    const fn title(self) -> &'static str {
        match self {
            Self::Enrollment => "Enrollment",
            Self::Clients => "Clients",
            Self::Rules => "Access Rules",
            Self::Logs => "Logs",
        }
    }
}

enum Dialog {
    Request { row: ApplicantRow, approve: bool },
    Revoke(EnrolledClient),
    Token(Zeroizing<String>),
    Rules(Editor),
    Endpoints(EndpointEditor),
}

struct Ui {
    enrollment: Enrollment,
    pki: Arc<Pki>,
    policy: Arc<PolicyStore>,
    logs: Logs,
    tab: usize,
    selected: usize,
    pending: Vec<ApplicantRow>,
    open: bool,
    /// Requests refused while registration was closed, and the latest peer.
    refused: (u64, Option<std::net::SocketAddr>),
    clients: Vec<EnrolledClient>,
    log_offset: usize,
    log_column: usize,
    dialog: Option<Dialog>,
    status: String,
}

impl Ui {
    fn refresh_pending(&mut self) {
        (self.open, self.pending) = self.enrollment.snapshot();
        self.refused = self.enrollment.closed_refusals();
    }

    fn refresh_clients(&mut self) -> Result<()> {
        self.clients.clear();
        self.clients = self.pki.clients()?;
        self.clients
            .sort_by(|a, b| (&a.label, &a.fingerprint).cmp(&(&b.label, &b.fingerprint)));
        Ok(())
    }

    fn desktops(&self) -> impl Iterator<Item = &EnrolledClient> {
        self.clients
            .iter()
            .filter(|client| client.role == "desktop")
    }

    fn count(&self) -> usize {
        match Tab::ALL[self.tab] {
            Tab::Enrollment => self.pending.len(),
            Tab::Clients => self.clients.len(),
            Tab::Rules => 1 + self.desktops().count(),
            Tab::Logs => 0,
        }
    }

    fn switch(&mut self, backwards: bool) -> Result<()> {
        let count = Tab::ALL.len();
        self.tab = (self.tab + if backwards { count - 1 } else { 1 }) % count;
        self.selected = 0;
        self.status.clear();
        if matches!(Tab::ALL[self.tab], Tab::Clients | Tab::Rules) {
            self.refresh_clients()?;
        }
        Ok(())
    }

    fn key(&mut self, key: KeyEvent) -> Result<bool> {
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            return Ok(false);
        }
        if self.dialog.is_some() {
            self.dialog_key(key)?;
            return Ok(true);
        }
        let tab = Tab::ALL[self.tab];
        match key.code {
            KeyCode::Char('q') => return Ok(false),
            KeyCode::BackTab => self.switch(true)?,
            KeyCode::Tab => self.switch(false)?,
            KeyCode::F(5) if matches!(tab, Tab::Clients | Tab::Rules) => self.refresh_clients()?,
            KeyCode::Up | KeyCode::PageUp if tab == Tab::Logs => {
                self.log_offset =
                    self.log_offset
                        .saturating_add(if key.code == KeyCode::Up { 1 } else { 10 });
            }
            KeyCode::Down | KeyCode::PageDown if tab == Tab::Logs => {
                self.log_offset = self
                    .log_offset
                    .saturating_sub(if key.code == KeyCode::Down { 1 } else { 10 });
            }
            KeyCode::End if tab == Tab::Logs => self.log_offset = 0,
            KeyCode::Right if tab == Tab::Logs => self.log_column = (self.log_column + 8).min(2048),
            KeyCode::Left if tab == Tab::Logs => {
                self.log_column = self.log_column.saturating_sub(8);
            }
            KeyCode::Up => self.selected = self.selected.saturating_sub(1),
            KeyCode::Down => {
                self.selected = (self.selected + 1).min(self.count().saturating_sub(1));
            }
            KeyCode::Char('o') if tab == Tab::Enrollment => {
                self.enrollment.set_open(!self.open);
                self.refresh_pending();
                self.status = if self.open {
                    "Enrollment opened."
                } else {
                    "Enrollment closed. Pending requests and tokens were discarded."
                }
                .into();
            }
            KeyCode::Char('a' | 'd') if tab == Tab::Enrollment => {
                if let Some(row) = self.pending.get(self.selected) {
                    self.dialog = Some(Dialog::Request {
                        row: row.clone(),
                        approve: key.code == KeyCode::Char('a'),
                    });
                    self.status.clear();
                }
            }
            KeyCode::Char('r') if tab == Tab::Clients => {
                if let Some(client) = self.clients.get(self.selected) {
                    self.dialog = Some(Dialog::Revoke(client.clone()));
                    self.status.clear();
                }
            }
            KeyCode::Enter if tab == Tab::Rules => {
                let target = self
                    .selected
                    .checked_sub(1)
                    .and_then(|index| self.desktops().nth(index))
                    .cloned();
                self.dialog = Some(Dialog::Rules(Editor::open(&self.policy, target)?));
                self.status.clear();
            }
            KeyCode::Char('e') if tab == Tab::Rules => {
                let desktop = self
                    .selected
                    .checked_sub(1)
                    .and_then(|index| self.desktops().nth(index))
                    .cloned();
                if let Some(desktop) = desktop {
                    self.dialog = Some(Dialog::Endpoints(EndpointEditor::open(
                        &self.policy,
                        &self.pki,
                        desktop,
                    )?));
                    self.status.clear();
                }
            }
            _ => {}
        }
        Ok(true)
    }

    fn dialog_key(&mut self, key: KeyEvent) -> Result<()> {
        let Some(dialog) = self.dialog.take() else {
            return Ok(());
        };
        match dialog {
            Dialog::Endpoints(mut editor) => match editor.key(key, &self.policy, &self.pki) {
                Ok(Some(status)) => self.status = status.into(),
                other => {
                    self.dialog = Some(Dialog::Endpoints(editor));
                    let _ = other?;
                }
            },
            Dialog::Rules(mut editor) => {
                let result = editor.key(key, &self.policy);
                match result {
                    Ok(Some(status)) => self.status = status.into(),
                    other => {
                        self.dialog = Some(Dialog::Rules(editor));
                        let _ = other?;
                    }
                }
            }
            _ if key.code == KeyCode::Esc => self.status.clear(),
            Dialog::Token(token) if key.code == KeyCode::Char('c') => {
                // Clipboard writes are explicit. Keep this escape sequence out of all log writers.
                let encoded = Zeroizing::new(STANDARD.encode(token.as_bytes()));
                self.dialog = Some(Dialog::Token(token));
                let mut output = io::stdout().lock();
                write!(output, "\x1b]52;c;{}\x07", encoded.as_str())?;
                output.flush()?;
                self.status = "Clipboard copy requested. Terminal support is required.".into();
            }
            Dialog::Request { row, approve } if key.code == KeyCode::Enter => {
                if approve {
                    self.dialog = Some(Dialog::Token(self.enrollment.approve(&row)?));
                } else {
                    self.enrollment.deny(&row)?;
                    self.status = "Request denied.".into();
                }
            }
            Dialog::Revoke(client) if key.code == KeyCode::Enter => {
                self.pki.revoke(&client.role, &client.fingerprint)?;
                tracing::info!(role = %client.role, "Operator revoked a certificate.");
                self.refresh_clients()?;
                self.status = "Certificate revoked.".into();
            }
            other => self.dialog = Some(other),
        }
        Ok(())
    }
}

struct Screen;

struct StopOnDrop(Arc<AtomicBool>);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

impl Drop for Ui {
    fn drop(&mut self) {
        self.enrollment.set_open(false);
    }
}

impl Drop for Screen {
    fn drop(&mut self) {
        let _ = execute!(io::stdout(), Show, LeaveAlternateScreen);
        let _ = disable_raw_mode();
    }
}

fn interact(ui: &mut Ui, stop: &AtomicBool) -> Result<()> {
    ensure!(
        io::stdin().is_terminal() && io::stdout().is_terminal(),
        "The operator interface requires a terminal. Use --headless to serve existing clients."
    );
    enable_raw_mode()?;
    let _screen = Screen;
    execute!(io::stdout(), EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    while !stop.load(Ordering::Acquire) {
        ui.refresh_pending();
        ui.selected = ui.selected.min(ui.count().saturating_sub(1));
        let area = terminal.draw(|frame| render::draw(frame, ui))?.area;
        if event::poll(Duration::from_millis(200))?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            if area.width < MIN_COLUMNS || area.height < MIN_ROWS {
                if key.code == KeyCode::Char('q')
                    || (key.code == KeyCode::Char('c')
                        && key.modifiers.contains(KeyModifiers::CONTROL))
                {
                    break;
                }
                continue;
            }
            match ui.key(key) {
                Ok(false) => break,
                Ok(true) => {}
                Err(error) => ui.status = error.to_string(),
            }
        }
    }
    Ok(())
}

pub async fn run(
    enrollment: Enrollment,
    pki: Arc<Pki>,
    policy: Arc<PolicyStore>,
    logs: Logs,
    service: impl Future<Output = Result<()>>,
) -> Result<()> {
    let stop = StopOnDrop(Arc::new(AtomicBool::new(false)));
    let signal = Arc::clone(&stop.0);
    let mut terminal = tokio::task::spawn_blocking(move || {
        let mut ui = Ui {
            enrollment,
            pki,
            policy,
            logs,
            tab: 0,
            selected: 0,
            pending: Vec::new(),
            open: false,
            refused: (0, None),
            clients: Vec::new(),
            log_offset: 0,
            log_column: 0,
            dialog: None,
            status: String::new(),
        };
        interact(&mut ui, &signal)
    });
    tokio::select! {
        result = &mut terminal => result?,
        result = service => {
            drop(stop);
            terminal.await??;
            result
        }
    }
}
