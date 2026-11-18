use ratatui::{
    Frame, layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style}, text::Line,
    widgets::{Block, List, ListState, Paragraph, Tabs, Wrap},
};

use super::{Dialog, MIN_COLUMNS, MIN_ROWS, Tab, Ui};

pub(super) fn draw(frame: &mut Frame<'_>, ui: &mut Ui) {
    let area = frame.area();
    if area.width < MIN_COLUMNS || area.height < MIN_ROWS {
        frame.render_widget(Paragraph::new(format!("Resize to at least {MIN_COLUMNS} columns and {MIN_ROWS} rows, or press Q to quit."))
            .wrap(Wrap { trim: true }), area);
        return;
    }
    let regions = Layout::default().direction(Direction::Vertical).constraints([
        Constraint::Length(3), Constraint::Min(4), Constraint::Length(2), Constraint::Length(2),
    ]).split(area);
    let titles = Tab::ALL.map(|tab| Line::from(tab.title()));
    let tabs = Tabs::new(titles).select(ui.tab)
        .highlight_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .block(Block::bordered().title("SAP ADT Relay"));
    frame.render_widget(tabs, regions[0]);
    let help = match &ui.dialog {
        Some(Dialog::Request { row, approve }) => {
            let action = if *approve { "Approve Enrollment" } else { "Deny Enrollment" };
            let details = format!("Request ID\n{}\n\n{} · {}\n{}\n\nCompare the full ID, role, and label with the requester before approval.",
                row.id, row.role, row.peer, row.label);
            panel(frame, regions[1], action, details);
            "Enter Confirm · Esc Cancel"
        }
        Some(Dialog::Token(token)) => {
            let block = Block::bordered().title("Enrollment Token");
            let inner = block.inner(regions[1]);
            frame.render_widget(block, regions[1]);
            // Borrow the secret directly. No token is sent through the logging layer.
            frame.render_widget(Paragraph::new(vec![
                Line::from(token.as_str()), Line::default(),
                Line::from("Give this token to the verified requester through a trusted channel. It expires in 180 seconds."),
            ]).wrap(Wrap { trim: false }), inner);
            "C Copy Token · Esc Dismiss"
        }
        Some(Dialog::Revoke(client)) => {
            panel(frame, regions[1], "Revoke Certificate", format!(
                "{}\n{}\n\nCertificate Fingerprint\n{}\n\nRevoking this certificate blocks further use of this enrollment.",
                client.label, client.role, client.fingerprint));
            "Enter Revoke · Esc Cancel"
        }
        Some(Dialog::Rules(editor)) => {
            editor.draw(frame, regions[1]);
            editor.help()
        }
        Some(Dialog::Endpoints(editor)) => {
            editor.draw(frame, regions[1]);
            "↑/↓ Select · Space Toggle · S Save · L Reload · Esc Cancel"
        }
        None => dashboard(frame, regions[1], ui),
    };
    frame.render_widget(Paragraph::new(ui.status.as_str()).wrap(Wrap { trim: true })
        .style(Style::default().fg(Color::Yellow)), regions[2]);
    frame.render_widget(Paragraph::new(help).wrap(Wrap { trim: true }), regions[3]);
}

fn dashboard(frame: &mut Frame<'_>, area: Rect, ui: &mut Ui) -> &'static str {
    match Tab::ALL[ui.tab] {
        Tab::Enrollment => {
            let title = if ui.open { "Enrollment · Open" } else { "Enrollment · Closed" };
            let rows = ui.pending.iter().map(|row| format!("{}  {}  {}  {}", row.id, row.role, row.label, row.peer)).collect();
            list(frame, area, title, rows, ui.selected, "No pending requests.");
            "O Open/Close · ↑/↓ Select · A Approve · D Deny · Tab Menu · Q Quit"
        }
        Tab::Clients => {
            let rows = ui.clients.iter().map(|client| format!("{}  {}  {}", client.role, client.label, client.fingerprint)).collect();
            list(frame, area, "Enrolled Clients", rows, ui.selected, "No enrolled clients.");
            "↑/↓ Select · R Revoke · F5 Refresh · Tab Menu · Q Quit"
        }
        Tab::Rules => {
            let rows = std::iter::once("Global Rules".to_owned()).chain(
                ui.desktops().map(|client| format!("{}  {}", client.label, client.fingerprint))).collect();
            list(frame, area, "Access Rules", rows, ui.selected, "");
            if ui.selected == 0 {
                "↑/↓ Select Desktop · Enter Edit Rules · F5 Refresh · Tab Menu · Q Quit"
            } else {
                "↑/↓ Select · E Endpoints · Enter Edit Rules · F5 Refresh · Tab Menu · Q Quit"
            }
        }
        Tab::Logs => {
            let block = Block::bordered().title("Logs");
            let inner = block.inner(area);
            frame.render_widget(block, area);
            let visible = ui.logs.visible(usize::from(inner.height), &mut ui.log_offset);
            if visible.is_empty() {
                frame.render_widget(Paragraph::new("No log entries."), inner);
            } else {
                let lines = visible.into_iter()
                    .map(|line| Line::from(line.chars().skip(ui.log_column).collect::<String>()))
                    .collect::<Vec<_>>();
                frame.render_widget(Paragraph::new(lines), inner);
            }
            "↑/↓ History · PgUp/PgDn Page · ←/→ Pan · End Latest · Tab Menu · Q Quit"
        }
    }
}

fn panel(frame: &mut Frame<'_>, area: Rect, title: &str, text: String) {
    frame.render_widget(Paragraph::new(text).block(Block::bordered().title(title)).wrap(Wrap { trim: false }), area);
}

fn list(frame: &mut Frame<'_>, area: Rect, title: &str, rows: Vec<String>, index: usize, empty: &str) {
    let block = Block::bordered().title(title);
    if rows.is_empty() {
        frame.render_widget(Paragraph::new(empty).block(block), area);
    } else {
        let mut state = ListState::default().with_selected(Some(index));
        frame.render_stateful_widget(List::new(rows).block(block).highlight_symbol("› ")
            .highlight_style(Style::default().fg(Color::Cyan)), area, &mut state);
    }
}
