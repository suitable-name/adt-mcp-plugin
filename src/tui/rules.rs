use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Style},
    widgets::{Block, List, ListState, Paragraph, Wrap},
};

use crate::{
    policy::{PolicyStore, Rules, TOOLS},
    security::EnrolledClient,
};

enum Page {
    Summary,
    Actions {
        index: usize,
        selected: Option<Vec<String>>,
    },
    Packages(String),
    Remove,
}

pub(super) struct Editor {
    target: Option<EnrolledClient>,
    revision: String,
    rules: Rules,
    /// Global editor only: refuse unencrypted desktop sessions on every endpoint.
    require_e2e: bool,
    page: Page,
}

impl Editor {
    pub(super) fn open(policy: &PolicyStore, target: Option<EnrolledClient>) -> Result<Self> {
        let doc = policy.snapshot()?;
        let require_e2e = doc.require_e2e;
        let rules = match &target {
            Some(client) => doc
                .desktops
                .get(&client.fingerprint)
                .cloned()
                .unwrap_or_else(Rules::desktop_default),
            None => doc.global,
        };
        Ok(Self {
            target,
            revision: doc.revision,
            rules,
            require_e2e,
            page: Page::Summary,
        })
    }

    fn save(&self, store: &PolicyStore) -> Result<()> {
        if let Some(client) = &self.target {
            store.set_desktop(
                &self.revision,
                &client.fingerprint,
                Some(self.rules.clone()),
            )?;
        } else {
            store.set_global_with_e2e(&self.revision, self.rules.clone(), self.require_e2e)?;
            tracing::info!(
                require_e2e = self.require_e2e,
                "Operator saved the global end-to-end encryption requirement."
            );
        }
        tracing::info!("Operator saved access rules.");
        Ok(())
    }

    pub(super) fn key(
        &mut self,
        key: KeyEvent,
        store: &PolicyStore,
    ) -> Result<Option<&'static str>> {
        match &mut self.page {
            Page::Summary => match key.code {
                KeyCode::Esc => return Ok(Some("Editor closed.")),
                KeyCode::Char('r') => self.rules.read_only = !self.rules.read_only,
                KeyCode::Char('e') if self.target.is_none() => {
                    self.require_e2e = !self.require_e2e;
                }
                KeyCode::Char('a') => {
                    self.page = Page::Actions {
                        index: 0,
                        selected: self.rules.actions.clone(),
                    };
                }
                KeyCode::Char('p') => {
                    self.page = Page::Packages(
                        self.rules
                            .packages
                            .as_ref()
                            .map_or_else(|| "*".into(), |patterns| patterns.join(", ")),
                    );
                }
                KeyCode::Char('l') => *self = Self::open(store, self.target.clone())?,
                KeyCode::Char('x') if self.target.is_some() => self.page = Page::Remove,
                KeyCode::Char('s') => {
                    self.save(store)?;
                    return Ok(Some("Access rules saved."));
                }
                _ => {}
            },
            Page::Actions { index, selected } => match key.code {
                KeyCode::Up => *index = index.saturating_sub(1),
                KeyCode::Down => *index = (*index + 1).min(TOOLS.len().saturating_sub(1)),
                KeyCode::Char('*') => *selected = None,
                KeyCode::Char('0') => *selected = Some(Vec::new()),
                KeyCode::Char(' ') => {
                    if let Some(&tool) = TOOLS.get(*index) {
                        let values = selected.get_or_insert_with(|| {
                            TOOLS.iter().map(|&name| name.to_owned()).collect()
                        });
                        if let Some(pos) = values.iter().position(|name| name == tool) {
                            values.remove(pos);
                        } else {
                            values.push(tool.to_owned());
                        }
                    }
                }
                KeyCode::Enter => {
                    self.rules.actions = selected.take();
                    self.page = Page::Summary;
                }
                KeyCode::Esc => self.page = Page::Summary,
                _ => {}
            },
            Page::Packages(value) => match key.code {
                KeyCode::Backspace => {
                    value.pop();
                }
                KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    value.clear();
                }
                KeyCode::Char(c) if !c.is_control() && value.len() < 4096 => value.push(c),
                KeyCode::Enter => {
                    self.rules.packages = match value.trim() {
                        "*" => None,
                        "" => Some(Vec::new()),
                        list => Some(
                            list.split(',')
                                .map(|pattern| pattern.trim().to_owned())
                                .collect(),
                        ),
                    };
                    self.page = Page::Summary;
                }
                KeyCode::Esc => self.page = Page::Summary,
                _ => {}
            },
            Page::Remove => match key.code {
                KeyCode::Esc => self.page = Page::Summary,
                KeyCode::Enter => {
                    if let Some(client) = &self.target {
                        store.set_desktop(&self.revision, &client.fingerprint, None)?;
                        tracing::info!("Operator removed a desktop access override.");
                        return Ok(Some("Desktop override removed."));
                    }
                }
                _ => {}
            },
        }
        Ok(None)
    }

    pub(super) fn draw(&self, frame: &mut Frame<'_>, area: Rect) {
        let title = self.target.as_ref().map_or_else(
            || "Global Rules".to_owned(),
            |client| format!("Desktop Rules · {}", client.label),
        );
        let block = Block::bordered().title(title);
        match &self.page {
            Page::Summary => {
                let encryption = if self.target.is_some() {
                    String::new()
                } else {
                    format!(
                        "Require end-to-end encryption    {}\n\n",
                        if self.require_e2e { "On" } else { "Off" }
                    )
                };
                let contents = format!(
                    "Read-Only Mode    {}\n\n{encryption}Allowed Actions\n{}\n\nAllowed Packages\n{}\n\n{}",
                    if self.rules.read_only { "On" } else { "Off" },
                    describe(self.rules.actions.as_deref()),
                    describe(self.rules.packages.as_deref()),
                    self.target.as_ref().map_or_else(
                        || "Global restrictions apply to every desktop.".to_owned(),
                        |c| format!(
                            "Certificate fingerprint\n{}\n\nGlobal restrictions also apply.",
                            c.fingerprint
                        )
                    )
                );
                frame.render_widget(
                    Paragraph::new(contents)
                        .block(block)
                        .wrap(Wrap { trim: false }),
                    area,
                );
            }
            Page::Packages(value) => {
                frame.render_widget(Paragraph::new(format!(
                    "Allowed Packages\n\n{value}▏\n\nSeparate package patterns with commas. Use * for unrestricted access. An empty list allows no packages."
                )).wrap(Wrap { trim: false }).block(block), area);
            }
            Page::Actions { index, selected } => {
                let items = TOOLS
                    .iter()
                    .map(|&tool| {
                        let allowed = selected
                            .as_ref()
                            .is_none_or(|list| list.iter().any(|s| s == tool));
                        format!("[{}] {tool}", if allowed { 'x' } else { ' ' })
                    })
                    .collect::<Vec<_>>();
                let mut state = ListState::default().with_selected(Some(*index));
                frame.render_stateful_widget(
                    List::new(items)
                        .block(block)
                        .highlight_symbol("› ")
                        .highlight_style(Style::default().fg(Color::Cyan)),
                    area,
                    &mut state,
                );
            }
            Page::Remove => frame.render_widget(
                Paragraph::new(
                    "Remove the desktop override and restore the default desktop rules?",
                )
                .wrap(Wrap { trim: false })
                .block(block),
                area,
            ),
        }
    }

    pub(super) const fn help(&self) -> &'static str {
        match self.page {
            Page::Summary if self.target.is_some() => {
                "R Read-Only · A Actions · P Packages · S Save · L Reload · X Remove Override · Esc Cancel"
            }
            Page::Summary => {
                "R Read-Only · E Require Encryption · A Actions · P Packages · S Save · L Reload · Esc Cancel"
            }
            Page::Actions { .. } => {
                "↑/↓ Select · Space Toggle · * Allow All · 0 Clear · Enter Apply · Esc Cancel"
            }
            Page::Packages(_) => "Type Patterns · Ctrl+U Clear · Enter Apply · Esc Cancel",
            Page::Remove => "Enter Remove Override · Esc Cancel",
        }
    }
}

fn describe(values: Option<&[String]>) -> String {
    match values {
        None => "Unrestricted".into(),
        Some([]) => "None".into(),
        Some(values) => values.join(", "),
    }
}
