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
        serde_json::Value::String(value) => value.clone(),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    };
    let rules = text("rules");
    let rules = if rules.is_empty() {
        String::new()
    } else {
        format!(" [{rules}]")
    };
    format!(
        "{time} {decision:<11} {status} {method} {scheme}://{host}:{port}{path}{rules} via {ingress}",
        time = entry["timestamp"].as_str().unwrap_or("-"),
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
