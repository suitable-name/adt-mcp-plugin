use std::collections::BTreeSet;

use anyhow::{Result, ensure};
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Style},
    widgets::{Block, List, ListState, Paragraph, Wrap},
};

use crate::{policy::PolicyStore, security::{EnrolledClient, Pki}};

pub(super) struct EndpointEditor {
    desktop: EnrolledClient,
    revision: String,
    endpoints: Vec<EnrolledClient>,
    granted: BTreeSet<String>,
    index: usize,
}

fn enrolled_endpoints(pki: &Pki, desktop: &str) -> Result<Vec<EnrolledClient>> {
    let mut clients = pki.clients()?;
    ensure!(clients.iter().any(|client| client.role == "desktop" && client.fingerprint == desktop),
        "This desktop is no longer enrolled. Refresh the client list.");
    clients.retain(|client| client.role == "eclipse");
    clients.sort_by(|a, b| (&a.label, &a.fingerprint).cmp(&(&b.label, &b.fingerprint)));
    Ok(clients)
}

impl EndpointEditor {
    pub(super) fn open(store: &PolicyStore, pki: &Pki, desktop: EnrolledClient) -> Result<Self> {
        let endpoints = enrolled_endpoints(pki, &desktop.fingerprint)?;
        let mut doc = store.snapshot()?;
        let granted = doc.endpoint_grants.remove(&desktop.fingerprint).unwrap_or_default()
            .into_iter().collect();
        Ok(Self { desktop, revision: doc.revision, endpoints, granted, index: 0 })
    }

    pub(super) fn key(&mut self, key: KeyEvent, store: &PolicyStore, pki: &Pki) -> Result<Option<&'static str>> {
        match key.code {
            KeyCode::Esc => return Ok(Some("Editor closed.")),
            KeyCode::Up => self.index = self.index.saturating_sub(1),
            KeyCode::Down => self.index = (self.index + 1).min(self.endpoints.len().saturating_sub(1)),
            KeyCode::Char(' ') => {
                if let Some(endpoint) = self.endpoints.get(self.index)
                    && !self.granted.remove(&endpoint.fingerprint) {
                    self.granted.insert(endpoint.fingerprint.clone());
                }
            }
            KeyCode::Char('l') => *self = Self::open(store, pki, self.desktop.clone())?,
            KeyCode::Char('s') => {
                let current: BTreeSet<_> = enrolled_endpoints(pki, &self.desktop.fingerprint)?
                    .into_iter().map(|client| client.fingerprint).collect();
                let selected: Vec<_> = self.endpoints.iter()
                    .filter(|client| self.granted.contains(&client.fingerprint))
                    .map(|client| client.fingerprint.clone()).collect();
                ensure!(selected.iter().all(|id| current.contains(id)), "An endpoint was revoked. Reload before saving.");
                store.set_endpoint_grants(&self.revision, &self.desktop.fingerprint, selected)?;
                tracing::info!(desktop = %self.desktop.fingerprint, "Operator saved endpoint assignments.");
                return Ok(Some("Endpoint assignments saved."));
            }
            _ => {}
        }
        Ok(None)
    }

    pub(super) fn draw(&self, frame: &mut Frame<'_>, area: Rect) {
        let block = Block::bordered().title(format!("Allowed Endpoints · {}", self.desktop.label));
        let inner = block.inner(area);
        frame.render_widget(block, area);
        // At the minimum terminal width, each full fingerprint needs two rows.
        let id_rows = if inner.width >= 64 { 2 } else { 3 };
        let [desktop, list, endpoint] = Layout::vertical([
            Constraint::Length(id_rows), Constraint::Min(1), Constraint::Length(id_rows),
        ]).areas(inner);
        let identity = |label, pin: &str| Paragraph::new(format!("{label}\n{pin}")).wrap(Wrap { trim: false });
        frame.render_widget(identity("Desktop ID", &self.desktop.fingerprint), desktop);
        if let Some(selected) = self.endpoints.get(self.index) {
            let rows = self.endpoints.iter().map(|client| {
                let mark = if self.granted.contains(&client.fingerprint) { 'x' } else { ' ' };
                format!("[{mark}] {}", client.label)
            }).collect::<Vec<_>>();
            let mut state = ListState::default().with_selected(Some(self.index));
            frame.render_stateful_widget(List::new(rows).highlight_symbol("› ")
                .highlight_style(Style::default().fg(Color::Cyan)), list, &mut state);
            frame.render_widget(identity("Selected Endpoint ID", &selected.fingerprint), endpoint);
        } else {
            frame.render_widget(Paragraph::new("Enroll an Eclipse workspace to assign an endpoint.")
                .wrap(Wrap { trim: true }), list);
        }
    }
}
