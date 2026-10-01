use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::Duration;

use anyhow::Context;

const POLL: Duration = Duration::from_millis(250);

pub async fn run(path: &Path, last: usize, follow: bool) -> anyhow::Result<()> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("could not open audit log {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut recent = VecDeque::with_capacity(last);
    let mut line = String::new();
    while reader.read_line(&mut line)? > 0 {
        if line.ends_with('\n') {
            if recent.len() == last {
                recent.pop_front();
            }
            if last > 0 {
                recent.push_back(std::mem::take(&mut line));
            }
            line.clear();
        }
    }
    let mut stdout = std::io::stdout();
    for entry in recent {
        writeln!(stdout, "{}", render(&entry))?;
    }
    stdout.flush()?;
    if !follow {
        return Ok(());
    }
    loop {
        let position = reader.stream_position()? - line.len() as u64;
        if std::fs::metadata(path)?.len() < position {
            reader.seek(SeekFrom::Start(0))?;
            line.clear();
        }
        if reader.read_line(&mut line)? == 0 || !line.ends_with('\n') {
            tokio::time::sleep(POLL).await;
            continue;
        }
        writeln!(stdout, "{}", render(&line))?;
        stdout.flush()?;
        line.clear();
    }
}

fn render(line: &str) -> String {
    let Ok(entry) = serde_json::from_str::<serde_json::Value>(line) else {
        return line.trim_end().to_string();
    };
    let fields = &entry["fields"];
    let text = |name: &str| match &fields[name] {
        serde_json::Value::String(value) => printable(value),
        serde_json::Value::Null => String::new(),
        other => printable(&other.to_string()),
    };
    let time = entry["timestamp"].as_str().unwrap_or("-");
    if text("ingress") == "ssh_agent" {
        let reason = text("reason");
        let reason = if reason.is_empty() {
            String::new()
        } else {
            format!(" ({reason})")
        };
        return format!(
            "{time} {decision:<11} ssh {user}@{host_key} [{rules}]{reason} via ssh_agent",
            decision = text("decision"),
            user = text("user"),
            host_key = text("host_key"),
            rules = text("rules"),
        );
    }
    let rules = text("rules");
    let rules = if rules.is_empty() {
        String::new()
    } else {
        format!(" [{rules}]")
    };
    let service = text("service");
    let operation = text("operation");
    let aws = match (service.is_empty(), operation.is_empty()) {
        (true, true) => String::new(),
        _ => format!(
            " aws:{service}/{region}:{operation}",
            region = text("region")
        ),
    };
    let reason = text("reason");
    let reason = if reason.is_empty() {
        String::new()
    } else {
        format!(" ({reason})")
    };
    format!(
        "{time} {decision:<11} {status} {method} {scheme}://{host}:{port}{path}{rules}{aws}{reason} via {ingress}",
        decision = text("decision"),
        status = text("status"),
        method = text("method"),
        scheme = text("scheme"),
        host = text("host"),
        port = text("port"),
        path = text("path"),
        ingress = text("ingress"),
    )
}

fn printable(value: &str) -> String {
    value
        .chars()
        .flat_map(|c| {
            if c.is_control() {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_characters_in_fields_cannot_forge_lines_or_drive_the_terminal() {
        let line = serde_json::json!({
            "timestamp": "t",
            "fields": {
                "ingress": "ssh_agent",
                "decision": "deny",
                "user": "x\n2026 sign ssh git@SHA256:x [github] via ssh_agent\u{1b}[2K",
                "host_key": "SHA256:y",
                "rules": "github",
                "reason": "user_not_allowed",
            }
        })
        .to_string();
        let rendered = render(&line);
        assert!(
            !rendered.contains('\n') && !rendered.contains('\u{1b}'),
            "{rendered}"
        );
        assert!(rendered.contains(r"x\n2026"), "{rendered}");
    }

    #[test]
    fn aws_requests_show_service_region_operation_and_reason() {
        let line = serde_json::json!({
            "timestamp": "t",
            "fields": {
                "ingress": "connect",
                "decision": "deny",
                "status": 403,
                "method": "POST",
                "scheme": "https",
                "host": "sts.ap-northeast-1.amazonaws.com",
                "port": 443,
                "path": "/",
                "rules": "aws-dev",
                "service": "sts",
                "region": "ap-northeast-1",
                "operation": "AssumeRole",
                "reason": "credential_operation",
            }
        })
        .to_string();
        assert_eq!(
            render(&line),
            "t deny        403 POST https://sts.ap-northeast-1.amazonaws.com:443/ [aws-dev] aws:sts/ap-northeast-1:AssumeRole (credential_operation) via connect"
        );
    }
}
