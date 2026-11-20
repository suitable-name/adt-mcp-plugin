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
    bridge::{BridgeRow, Registry},
    enrollment::{EnrolledRow, Enrollment, LinkRow},
    link::Role,
    logs::Logs,
    policy::{E2eSettings, PolicyStore},
    security::{EnrolledClient, Pki},
    tunnel::StreamRow,
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
    Connections,
    Logs,
}

impl Tab {
    const ALL: [Self; 5] = [
        Self::Enrollment,
        Self::Clients,
        Self::Rules,
        Self::Connections,
        Self::Logs,
    ];

    const fn title(self) -> &'static str {
        match self {
            Self::Enrollment => "Enrollment",
            Self::Clients => "Clients",
            Self::Rules => "Access Rules",
            Self::Connections => "Connections",
            Self::Logs => "Logs",
        }
    }
}

/// The "New link" dialog: a role and a label.
struct LinkForm {
    role: Role,
    label: String,
}

enum FormAction {
    Pending,
    Cancel,
    Create,
}

impl LinkForm {
    const MAX_LABEL: usize = 64;

    fn key(&mut self, key: KeyEvent) -> FormAction {
        match key.code {
            KeyCode::Esc => return FormAction::Cancel,
            KeyCode::Enter if !self.label.trim().is_empty() => return FormAction::Create,
            KeyCode::Left | KeyCode::Right => {
                self.role = match self.role {
                    Role::Desktop => Role::Eclipse,
                    Role::Eclipse => Role::Desktop,
                };
            }
            KeyCode::Backspace => {
                self.label.pop();
            }
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.label.clear();
            }
            KeyCode::Char(c)
                if (c.is_ascii_graphic() || c == ' ')
                    && !key.modifiers.contains(KeyModifiers::CONTROL)
                    && self.label.len() < Self::MAX_LABEL =>
            {
                self.label.push(c);
            }
            _ => {}
        }
        FormAction::Pending
    }
}

enum Dialog {
    NewLink(LinkForm),
    Link(Zeroizing<String>),
    Revoke(EnrolledClient),
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
    /// Outstanding enrollment links and the latest enrollments, refreshed with every frame.
    links: Vec<LinkRow>,
    enrolled: Vec<EnrolledRow>,
    clients: Vec<EnrolledClient>,
    registry: Registry,
    /// Live Eclipse bridges and desktop sessions, refreshed with every frame.
    connections: Vec<BridgeRow>,
    /// Live end-to-end streams, refreshed with every frame.
    streams: Vec<StreamRow>,
    /// The end-to-end requirement (global and per endpoint), reloaded on refresh and after edits.
    e2e: E2eSettings,
    /// First line shown on the Connections tab.
    connections_scroll: u16,
    /// The next frame scrolls the Connections tab to keep the selected bridge visible.
    connections_follow: bool,
    log_offset: usize,
    log_column: usize,
    dialog: Option<Dialog>,
    status: String,
}

impl Ui {
    fn refresh_pending(&mut self) {
        (self.links, self.enrolled) = self.enrollment.snapshot();
        self.connections = self.registry.snapshot();
        self.streams = self.registry.stream_snapshot();
    }

    /// Reload the end-to-end requirement from the policy file; keeps the old value on error.
    fn reload_e2e(&mut self) {
        if let Ok(document) = self.policy.snapshot() {
            self.e2e = document.e2e();
        }
    }

    /// Scroll the Connections tab; the renderer clamps the offset to its content.
    const fn scroll_connections(&mut self, key: KeyCode) {
        self.connections_follow = false;
        self.connections_scroll = match key {
            KeyCode::PageUp => self.connections_scroll.saturating_sub(10),
            KeyCode::PageDown => self.connections_scroll.saturating_add(10),
            _ => 0,
        };
    }

    /// Move the selected bridge on the Connections tab and scroll it into view.
    fn select_connection(&mut self, key: KeyCode) {
        self.selected = if key == KeyCode::Up {
            self.selected.saturating_sub(1)
        } else {
            (self.selected + 1).min(self.count().saturating_sub(1))
        };
        self.connections_follow = true;
    }

    /// Flip the end-to-end requirement of the selected Eclipse endpoint.
    fn toggle_require(&mut self) -> Result<()> {
        let Some(row) = self.connections.get(self.selected) else {
            return Ok(());
        };
        let endpoint = row.endpoint.clone();
        let required = self.policy.toggle_endpoint_e2e(&endpoint)?;
        tracing::info!(
            %endpoint,
            required,
            "Operator changed the end-to-end encryption requirement of an Eclipse endpoint."
        );
        self.reload_e2e();
        self.status = if required {
            "End-to-end encryption is now required for this endpoint. Unencrypted sessions end at their next request."
        } else {
            "Unencrypted desktop sessions are allowed for this endpoint."
        }
        .into();
        Ok(())
    }

    /// The enrolled label for a certificate fingerprint, if it is still enrolled.
    fn label(&self, role: &str, fingerprint: &str) -> Option<&str> {
        self.clients
            .iter()
            .find(|client| client.role == role && client.fingerprint == fingerprint)
            .map(|client| client.label.as_str())
    }

    fn refresh_clients(&mut self) -> Result<()> {
        self.clients.clear();
        self.clients = self.pki.clients()?;
        self.clients
            .sort_by(|a, b| (&a.label, &a.fingerprint).cmp(&(&b.label, &b.fingerprint)));
        self.reload_e2e();
        Ok(())
    }

    fn desktops(&self) -> impl Iterator<Item = &EnrolledClient> {
        self.clients
            .iter()
            .filter(|client| client.role == "desktop")
    }

    fn count(&self) -> usize {
        match Tab::ALL[self.tab] {
            Tab::Enrollment => self.links.len(),
            Tab::Clients => self.clients.len(),
            Tab::Rules => 1 + self.desktops().count(),
            Tab::Connections => self.connections.len(),
            Tab::Logs => 0,
        }
    }

    fn switch(&mut self, backwards: bool) -> Result<()> {
        let count = Tab::ALL.len();
        self.tab = (self.tab + if backwards { count - 1 } else { 1 }) % count;
        self.selected = 0;
        self.status.clear();
        if matches!(
            Tab::ALL[self.tab],
            Tab::Clients | Tab::Rules | Tab::Connections
        ) {
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
            KeyCode::F(5) if matches!(tab, Tab::Clients | Tab::Rules | Tab::Connections) => {
                self.refresh_clients()?;
            }
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
            KeyCode::Up | KeyCode::Down if tab == Tab::Connections => {
                self.select_connection(key.code);
            }
            KeyCode::PageUp | KeyCode::PageDown | KeyCode::Home if tab == Tab::Connections => {
                self.scroll_connections(key.code);
            }
            KeyCode::Char('e') if tab == Tab::Connections => self.toggle_require()?,
            KeyCode::Up => self.selected = self.selected.saturating_sub(1),
            KeyCode::Down => {
                self.selected = (self.selected + 1).min(self.count().saturating_sub(1));
            }
            KeyCode::Char('n') if tab == Tab::Enrollment => {
                self.dialog = Some(Dialog::NewLink(LinkForm {
                    role: Role::Desktop,
                    label: String::new(),
                }));
                self.status.clear();
            }
            KeyCode::Char('x') if tab == Tab::Enrollment => {
                if let Some(row) = self.links.get(self.selected) {
                    self.status = if self.enrollment.cancel(row.number) {
                        "Link cancelled."
                    } else {
                        "The link was already used or expired."
                    }
                    .into();
                    self.refresh_pending();
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
                    Ok(Some(status)) => {
                        self.status = status.into();
                        self.reload_e2e();
                    }
                    other => {
                        self.dialog = Some(Dialog::Rules(editor));
                        let _ = other?;
                    }
                }
            }
            Dialog::NewLink(mut form) => match form.key(key) {
                FormAction::Cancel => self.status.clear(),
                FormAction::Pending => self.dialog = Some(Dialog::NewLink(form)),
                FormAction::Create => {
                    match self.enrollment.new_link(form.role, form.label.trim()) {
                        Ok(link) => self.dialog = Some(Dialog::Link(link)),
                        Err(error) => {
                            self.dialog = Some(Dialog::NewLink(form));
                            return Err(error.into());
                        }
                    }
                }
            },
            // Closing the dialog drops (and wipes) the link: it is not shown again.
            _ if key.code == KeyCode::Esc => self.status.clear(),
            Dialog::Link(link) if key.code == KeyCode::Char('c') => {
                // Clipboard writes are explicit. Keep this escape sequence out of all log writers.
                let encoded = Zeroizing::new(STANDARD.encode(link.as_bytes()));
                self.dialog = Some(Dialog::Link(link));
                let mut output = io::stdout().lock();
                write!(output, "\x1b]52;c;{}\x07", encoded.as_str())?;
                output.flush()?;
                self.status = "Clipboard copy requested. Terminal support is required.".into();
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
    ui.reload_e2e();
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
    registry: Registry,
    logs: Logs,
    service: impl Future<Output = Result<()>>,
) -> Result<()> {
    let stop = StopOnDrop(Arc::new(AtomicBool::new(false)));
    let signal = Arc::clone(&stop.0);
    let mut terminal = smol::unblock(move || {
        let mut ui = Ui {
            enrollment,
            pki,
            policy,
            logs,
            tab: 0,
            selected: 0,
            links: Vec::new(),
            enrolled: Vec::new(),
            clients: Vec::new(),
            registry,
            connections: Vec::new(),
            streams: Vec::new(),
            e2e: E2eSettings::default(),
            connections_scroll: 0,
            connections_follow: false,
            log_offset: 0,
            log_column: 0,
            dialog: None,
            status: String::new(),
        };
        interact(&mut ui, &signal)
    });
    // `true` marks that the service ended first.
    let (service_ended, result) =
        smol::future::or(async { (false, (&mut terminal).await) }, async {
            (true, service.await)
        })
        .await;
    if service_ended {
        drop(stop);
        terminal.await?;
    }
    result
}
