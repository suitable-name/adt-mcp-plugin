use std::time::Instant;

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, List, ListState, Paragraph, Tabs, Wrap},
};

use super::{Dialog, MIN_COLUMNS, MIN_ROWS, Tab, Ui};
use crate::{bridge::BridgeRow, tunnel::StreamRow, tunnel_proto::Status};

pub(super) fn draw(frame: &mut Frame<'_>, ui: &mut Ui) {
    let area = frame.area();
    if area.width < MIN_COLUMNS || area.height < MIN_ROWS {
        frame.render_widget(
            Paragraph::new(format!(
                "Resize to at least {MIN_COLUMNS} columns and {MIN_ROWS} rows, or press Q to quit."
            ))
            .wrap(Wrap { trim: true }),
            area,
        );
        return;
    }
    let regions = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(4),
            Constraint::Length(2),
            Constraint::Length(2),
        ])
        .split(area);
    let titles = Tab::ALL.map(|tab| Line::from(tab.title()));
    let tabs = Tabs::new(titles)
        .select(ui.tab)
        .highlight_style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::bordered().title("SAP ADT Relay"));
    frame.render_widget(tabs, regions[0]);
    let help = match &ui.dialog {
        Some(Dialog::NewLink(form)) => {
            let details = format!(
                "Role    ◀ {} ▶   (←/→ change)\nLabel   {}▏\n\nA desktop link enrolls an MCP client; an Eclipse link enrolls an Eclipse workspace.\nThe label names the certificate in the Clients tab and in the logs.",
                form.role.as_str(),
                form.label
            );
            panel(frame, regions[1], "New Enrollment Link", details);
            "←/→ Role · Type Label · Enter Create Link · Esc Cancel"
        }
        Some(Dialog::Link(link)) => {
            let block = Block::bordered().title("Enrollment Link");
            let inner = block.inner(regions[1]);
            frame.render_widget(block, regions[1]);
            // Borrow the secret directly. No link is sent through the logging layer.
            frame.render_widget(Paragraph::new(vec![
                Line::from(link.as_str()), Line::default(),
                Line::from("Give this link to the person who enrolls the device. It works once, expires in 10 minutes and is shown only now. Treat it like a password."),
            ]).wrap(Wrap { trim: false }), inner);
            "C Copy Link · Esc Dismiss"
        }
        Some(Dialog::Revoke(client)) => {
            panel(
                frame,
                regions[1],
                "Revoke Certificate",
                format!(
                    "{}\n{}\n\nCertificate Fingerprint\n{}\n\nRevoking this certificate blocks further use of this enrollment.",
                    client.label, client.role, client.fingerprint
                ),
            );
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
    frame.render_widget(
        Paragraph::new(ui.status.as_str())
            .wrap(Wrap { trim: true })
            .style(Style::default().fg(Color::Yellow)),
        regions[2],
    );
    frame.render_widget(Paragraph::new(help).wrap(Wrap { trim: true }), regions[3]);
}

fn enrollment(frame: &mut Frame<'_>, area: Rect, ui: &Ui) -> &'static str {
    let halves = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);
    let links = ui
        .links
        .iter()
        .map(|row| {
            let seconds = row.expires_in.as_secs();
            format!(
                "{}  {}  expires in {}m {:02}s",
                row.label,
                row.role.as_str(),
                seconds / 60,
                seconds % 60
            )
        })
        .collect();
    list(
        frame,
        halves[0],
        "Outstanding Links",
        links,
        ui.selected,
        "No outstanding links. Press N to create one.",
    );
    let enrolled = ui
        .enrolled
        .iter()
        .map(|row| {
            format!(
                "{}  {}  {}  {} ago",
                row.label,
                row.role.as_str(),
                row.peer,
                age(row.at)
            )
        })
        .collect();
    list(
        frame,
        halves[1],
        "Recent Enrollments",
        enrolled,
        0,
        "Nothing enrolled since this relay started.",
    );
    "N New Link · X Cancel Link · ↑/↓ Select · Tab Menu · Q Quit"
}

fn dashboard(frame: &mut Frame<'_>, area: Rect, ui: &mut Ui) -> &'static str {
    match Tab::ALL[ui.tab] {
        Tab::Enrollment => enrollment(frame, area, ui),
        Tab::Clients => {
            let rows = ui
                .clients
                .iter()
                .map(|client| format!("{}  {}  {}", client.role, client.label, client.fingerprint))
                .collect();
            list(
                frame,
                area,
                "Enrolled Clients",
                rows,
                ui.selected,
                "No enrolled clients.",
            );
            "↑/↓ Select · R Revoke · F5 Refresh · Tab Menu · Q Quit"
        }
        Tab::Rules => {
            let rows = std::iter::once("Global Rules".to_owned())
                .chain(
                    ui.desktops()
                        .map(|client| format!("{}  {}", client.label, client.fingerprint)),
                )
                .collect();
            list(frame, area, "Access Rules", rows, ui.selected, "");
            if ui.selected == 0 {
                "↑/↓ Select Desktop · Enter Edit Rules · F5 Refresh · Tab Menu · Q Quit"
            } else {
                "↑/↓ Select · E Endpoints · Enter Edit Rules · F5 Refresh · Tab Menu · Q Quit"
            }
        }
        Tab::Connections => {
            connections(frame, area, ui);
            "↑/↓ Select Eclipse · E Require/Allow Encryption · PgUp/PgDn Scroll · Home Top · F5 Refresh · Tab Menu · Q Quit"
        }
        Tab::Logs => {
            let block = Block::bordered().title("Logs");
            let inner = block.inner(area);
            frame.render_widget(block, area);
            let visible = ui
                .logs
                .visible(usize::from(inner.height), &mut ui.log_offset);
            if visible.is_empty() {
                frame.render_widget(Paragraph::new("No log entries."), inner);
            } else {
                let lines = visible
                    .into_iter()
                    .map(|line| Line::from(line.chars().skip(ui.log_column).collect::<String>()))
                    .collect::<Vec<_>>();
                frame.render_widget(Paragraph::new(lines), inner);
            }
            "↑/↓ History · PgUp/PgDn Page · ←/→ Pan · End Latest · Tab Menu · Q Quit"
        }
    }
}

/// A short age such as `42s`, `7m` or `3h 05m`.
fn age(since: Instant) -> String {
    let seconds = since.elapsed().as_secs();
    match seconds {
        0..60 => format!("{seconds}s"),
        60..3600 => format!("{}m", seconds / 60),
        _ => format!("{}h {:02}m", seconds / 3600, seconds / 60 % 60),
    }
}

/// `1.5 KiB` style sizes, in integer arithmetic.
fn bytes(count: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * KIB;
    match count {
        0..KIB => format!("{count} B"),
        KIB..MIB => format!("{}.{} KiB", count / KIB, count % KIB * 10 / KIB),
        _ => format!("{}.{} MiB", count / MIB, count % MIB * 10 / MIB),
    }
}

/// The result of a stream's last response, as shown to the operator.
const fn status_text(status: Option<Status>) -> &'static str {
    match status {
        None => "no response yet",
        Some(Status::Ok) => "ok",
        Some(Status::Error) => "error",
        Some(Status::Denied) => "denied",
    }
}

/// One encrypted stream under its bridge. Only envelope metadata is known; the relay cannot
/// read what the stream carries.
fn stream_line(stream: &StreamRow, desktop: &str) -> String {
    let id = stream.id.simple().to_string();
    let last = match &stream.last_tool {
        Some(tool) => format!("{} {tool}", stream.last_method),
        None if stream.last_method.is_empty() => "nothing yet".to_owned(),
        None => stream.last_method.clone(),
    };
    let handshake = if stream.handshaken {
        ""
    } else {
        "  handshake pending"
    };
    let took = stream.last_response.map_or_else(String::new, |time| {
        format!("  took {} ms", time.as_millis())
    });
    format!(
        "    └ encrypted  {desktop}  {}  stream {}  opened {} ago  active {} ago  {} request(s), last {last}  {}  in {}  out {}{took}{handshake}",
        stream.peer,
        &id[..8],
        age(stream.since),
        age(stream.last_active),
        stream.requests,
        status_text(stream.last_status),
        bytes(stream.bytes_in),
        bytes(stream.bytes_out),
    )
}

/// The desktops that still hold unencrypted sessions, sorted and without repeats: they must pair
/// before the endpoint can require end-to-end encryption.
fn legacy_desktops<'a>(
    bridges: &[BridgeRow],
    label: impl Fn(&str) -> Option<&'a str>,
) -> Vec<String> {
    let mut names: Vec<String> = bridges
        .iter()
        .flat_map(|bridge| &bridge.sessions)
        .map(|session| {
            label(&session.desktop).map_or_else(|| session.desktop[..8].to_owned(), str::to_owned)
        })
        .collect();
    names.sort_unstable();
    names.dedup();
    names
}

/// The header line of one Eclipse bridge.
fn bridge_header(ui: &Ui, row: &BridgeRow, selected: bool) -> Line<'static> {
    let label = ui
        .label("eclipse", &row.endpoint)
        .unwrap_or("(not enrolled)");
    let state = match (row.ready, row.busy) {
        (false, _) => Span::styled("handshake", Style::default().fg(Color::Yellow)),
        (true, true) => Span::styled("busy", Style::default().fg(Color::Yellow)),
        (true, false) => Span::styled("ready", Style::default().fg(Color::Green)),
    };
    let capability = if row.e2e {
        Span::styled("e2e", Style::default().fg(Color::Green))
    } else {
        Span::styled("legacy only", Style::default().fg(Color::Yellow))
    };
    let requirement = if ui.e2e.required(&row.endpoint) {
        Span::styled("encryption required", Style::default().fg(Color::Cyan))
    } else {
        Span::styled("encryption optional", Style::default().fg(Color::DarkGray))
    };
    let last = row.last_call.as_ref().map_or_else(
        || "no calls yet".to_owned(),
        |(activity, at)| format!("last {activity} {} ago", age(*at)),
    );
    Line::from(vec![
        Span::raw(if selected { "› " } else { "  " }),
        Span::styled(
            format!("Eclipse  {label}"),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!("  {}  connected {}  ", row.peer, age(row.since))),
        state,
        Span::raw("  "),
        capability,
        Span::raw("  "),
        requirement,
        Span::raw(format!("  {} call(s), {last}", row.calls)),
    ])
}

/// The Connections lines, and the line where each bridge starts.
fn connection_lines(ui: &Ui) -> (Vec<Line<'static>>, Vec<usize>) {
    let dim = Style::default().fg(Color::DarkGray);
    let waiting = legacy_desktops(&ui.connections, |fingerprint| {
        ui.label("desktop", fingerprint)
    });
    let mut lines = vec![
        if waiting.is_empty() {
            Line::styled("No desktop uses unencrypted sessions.", dim)
        } else {
            Line::styled(
                format!(
                    "Still unencrypted: {}. These desktops must pair before encryption is required.",
                    waiting.join(", ")
                ),
                Style::default().fg(Color::Yellow),
            )
        },
        Line::raw(""),
    ];
    let mut starts = Vec::new();
    for (index, row) in ui.connections.iter().enumerate() {
        starts.push(lines.len());
        lines.push(bridge_header(ui, row, index == ui.selected));
        lines.push(Line::styled(format!("    endpoint {}", row.endpoint), dim));
        let streams = ui.streams.iter().filter(|s| s.endpoint == row.endpoint);
        let mut any = false;
        for stream in streams {
            any = true;
            let desktop = ui
                .label("desktop", &stream.desktop)
                .or(stream.label.as_deref())
                .unwrap_or("(not enrolled)");
            lines.push(Line::from(stream_line(stream, desktop)));
        }
        for session in &row.sessions {
            any = true;
            let desktop = ui
                .label("desktop", &session.desktop)
                .unwrap_or("(not enrolled)");
            let id = session.id.simple().to_string();
            lines.push(Line::styled(
                format!(
                    "    └ unencrypted  {desktop}  {}  session {}  started {} ago  active {} ago  {} request(s), last {}",
                    session.peer,
                    &id[..8],
                    age(session.since),
                    age(session.last_used),
                    session.requests,
                    session.activity,
                ),
                Style::default().fg(Color::Yellow),
            ));
        }
        if !any {
            lines.push(Line::styled("    no desktop connections", dim));
        }
        lines.push(Line::raw(""));
    }
    (lines, starts)
}

/// Live Eclipse bridges, each followed by the encrypted streams and unencrypted sessions
/// that use it.
fn connections(frame: &mut Frame<'_>, area: Rect, ui: &mut Ui) {
    let sessions: usize = ui.connections.iter().map(|row| row.sessions.len()).sum();
    let title = format!(
        "Connections · {} Eclipse · {} encrypted stream(s) · {sessions} unencrypted session(s)",
        ui.connections.len(),
        ui.streams.len()
    );
    let block = Block::bordered().title(title);
    if ui.connections.is_empty() {
        frame.render_widget(
            Paragraph::new(
                "No Eclipse bridge is connected.\n\nDesktop connections appear here under the Eclipse endpoint they use.",
            )
            .block(block)
            .wrap(Wrap { trim: false }),
            area,
        );
        return;
    }
    let (lines, starts) = connection_lines(ui);
    let height = usize::from(block.inner(area).height);
    if ui.connections_follow {
        ui.connections_follow = false;
        let start = starts.get(ui.selected).copied().unwrap_or(0);
        let end = starts
            .get(ui.selected + 1)
            .map_or(lines.len(), |next| *next);
        let top = usize::from(ui.connections_scroll);
        // Show as much of the selected bridge as fits, starting at its header.
        let wanted = if start < top {
            start
        } else if end > top + height {
            end.saturating_sub(height).min(start)
        } else {
            top
        };
        ui.connections_scroll = u16::try_from(wanted).unwrap_or(u16::MAX);
    }
    let max_scroll = u16::try_from(lines.len().saturating_sub(height)).unwrap_or(u16::MAX);
    ui.connections_scroll = ui.connections_scroll.min(max_scroll);
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .scroll((ui.connections_scroll, 0)),
        area,
    );
}

fn panel(frame: &mut Frame<'_>, area: Rect, title: &str, text: String) {
    frame.render_widget(
        Paragraph::new(text)
            .block(Block::bordered().title(title))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn list(
    frame: &mut Frame<'_>,
    area: Rect,
    title: &str,
    rows: Vec<String>,
    index: usize,
    empty: &str,
) {
    let block = Block::bordered().title(title);
    if rows.is_empty() {
        frame.render_widget(
            Paragraph::new(empty)
                .block(block)
                .wrap(Wrap { trim: false }),
            area,
        );
    } else {
        let mut state = ListState::default().with_selected(Some(index));
        frame.render_stateful_widget(
            List::new(rows)
                .block(block)
                .highlight_symbol("› ")
                .highlight_style(Style::default().fg(Color::Cyan)),
            area,
            &mut state,
        );
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, SocketAddr},
        time::Duration,
    };

    use uuid::Uuid;

    use super::*;

    fn stream() -> StreamRow {
        let now = Instant::now();
        StreamRow {
            id: Uuid::from_u128(0xabcd_ef01_2345_6789_0000_0000_0000_0001),
            endpoint: "e".repeat(64),
            desktop: "d".repeat(64),
            label: Some("Anna Laptop".into()),
            peer: SocketAddr::from((Ipv4Addr::LOCALHOST, 4242)),
            since: now,
            last_active: now,
            handshaken: true,
            requests: 3,
            last_method: "tools/call".into(),
            last_tool: Some("sap_set_source".into()),
            last_status: Some(Status::Denied),
            bytes_in: 1536,
            bytes_out: 3 * 1024 * 1024 / 2,
            last_response: Some(Duration::from_millis(42)),
        }
    }

    #[test]
    fn stream_rows_show_envelope_metadata_only() {
        let line = stream_line(&stream(), "Anna Laptop");
        for expected in [
            "encrypted",
            "Anna Laptop",
            "127.0.0.1:4242",
            "stream abcdef01",
            "3 request(s)",
            "last tools/call sap_set_source",
            "denied",
            "in 1.5 KiB",
            "out 1.5 MiB",
            "took 42 ms",
        ] {
            assert!(line.contains(expected), "{expected} missing in {line}");
        }
        assert!(!line.contains("handshake pending"));
        let mut fresh = stream();
        fresh.handshaken = false;
        fresh.last_tool = None;
        fresh.last_method.clear();
        fresh.last_status = None;
        fresh.last_response = None;
        let line = stream_line(&fresh, "?");
        assert!(line.contains("nothing yet") && line.contains("no response yet"));
        assert!(line.contains("handshake pending") && !line.contains("took"));
    }

    #[test]
    fn sizes_use_binary_units() {
        assert_eq!(bytes(0), "0 B");
        assert_eq!(bytes(1023), "1023 B");
        assert_eq!(bytes(1024), "1.0 KiB");
        assert_eq!(bytes(5 * 1024 * 1024 + 512 * 1024), "5.5 MiB");
    }
}
