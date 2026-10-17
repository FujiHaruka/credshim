use std::fmt::Write as _;

use anyhow::bail;

pub const SITE: &str = "https://fujiharuka.github.io/credshim";

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Lang {
    En,
    Ja,
}

impl Lang {
    pub fn from_env() -> Self {
        let locale = ["LC_ALL", "LC_MESSAGES", "LANG"]
            .iter()
            .filter_map(|name| std::env::var(name).ok())
            .find(|value| !value.is_empty())
            .unwrap_or_default();
        if locale.starts_with("ja") {
            Lang::Ja
        } else {
            Lang::En
        }
    }

    fn dir(self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::Ja => "ja",
        }
    }
}

pub struct Page {
    pub name: &'static str,
    pub en: &'static str,
    pub ja: &'static str,
}

impl Page {
    fn text(&self, lang: Lang) -> &'static str {
        match lang {
            Lang::En => self.en,
            Lang::Ja => self.ja,
        }
    }

    fn source(&self) -> &'static str {
        match self.name {
            "overview" => "index",
            name => name,
        }
    }
}

macro_rules! page {
    ($name:literal, $en:literal, $ja:literal) => {
        Page {
            name: $name,
            en: include_str!(concat!("../../../", $en)),
            ja: include_str!(concat!("../../../", $ja)),
        }
    };
}

pub const PAGES: &[Page] = &[
    page!("overview", "README.md", "docs/ja/README.md"),
    page!("install", "docs/install.md", "docs/ja/install.md"),
    page!(
        "configuration",
        "docs/configuration.md",
        "docs/ja/configuration.md"
    ),
    page!("aws", "docs/aws.md", "docs/ja/aws.md"),
    page!("ssh", "docs/ssh.md", "docs/ja/ssh.md"),
    page!("container", "docs/container.md", "docs/ja/container.md"),
    page!(
        "troubleshooting",
        "docs/troubleshooting.md",
        "docs/ja/troubleshooting.md"
    ),
    page!(
        "threat-model",
        "docs/threat-model.md",
        "docs/ja/threat-model.md"
    ),
    page!(
        "development",
        "docs/development.md",
        "docs/ja/development.md"
    ),
];

#[derive(Debug, PartialEq, Eq)]
pub struct Heading {
    pub level: usize,
    pub anchor: String,
    pub title: String,
    line: usize,
}

pub fn headings(text: &str) -> Vec<Heading> {
    let mut found = Vec::new();
    let mut fenced = false;
    let mut seen = std::collections::HashMap::<String, usize>::new();
    for (line_no, line) in text.lines().enumerate() {
        if line.starts_with("```") {
            fenced = !fenced;
            continue;
        }
        if fenced {
            continue;
        }
        let level = line.chars().take_while(|c| *c == '#').count();
        let Some(title) = line[level..].strip_prefix(' ') else {
            continue;
        };
        if level == 0 || level > 6 {
            continue;
        }
        let title = plain(title.trim());
        let base = slug(&title);
        let count = seen.entry(base.clone()).or_default();
        let anchor = if *count == 0 {
            base
        } else {
            format!("{base}-{count}")
        };
        *count += 1;
        found.push(Heading {
            level,
            anchor,
            title,
            line: line_no,
        });
    }
    found
}

fn plain(markdown: &str) -> String {
    let mut text = String::new();
    let mut rest = markdown;
    while let Some(c) = rest.chars().next() {
        if c == '['
            && let Some((label, after)) = rest[1..].split_once("](")
            && let Some((_, tail)) = after.split_once(')')
        {
            text.push_str(label);
            rest = tail;
            continue;
        }
        if c != '`' && c != '*' {
            text.push(c);
        }
        rest = &rest[c.len_utf8()..];
    }
    text
}

pub fn slug(title: &str) -> String {
    title
        .chars()
        .filter_map(|c| {
            if c.is_alphanumeric() || c == '_' || c == '-' {
                Some(c.to_ascii_lowercase())
            } else if c.is_whitespace() {
                Some('-')
            } else {
                None
            }
        })
        .collect()
}

pub fn find(name: &str) -> anyhow::Result<&'static Page> {
    match PAGES.iter().find(|page| page.name == name) {
        Some(page) => Ok(page),
        None => bail!(
            "there is no page {name:?}; list the pages with `credshim docs` (pages: {})",
            PAGES
                .iter()
                .map(|page| page.name)
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

pub fn section(page: &Page, anchor: &str, lang: Lang) -> Option<String> {
    let text = page.text(lang);
    let own = headings(text);
    let index = own
        .iter()
        .position(|heading| heading.anchor == anchor)
        .or_else(|| {
            headings(page.en)
                .iter()
                .position(|heading| heading.anchor == anchor)
                .filter(|_| headings(page.en).len() == own.len())
        })?;
    let start = &own[index];
    let end = own[index + 1..]
        .iter()
        .find(|heading| heading.level <= start.level)
        .map_or(usize::MAX, |heading| heading.line);
    let lines: Vec<&str> = text
        .lines()
        .skip(start.line)
        .take(end.saturating_sub(start.line))
        .collect();
    Some(lines.join("\n").trim_end().to_string() + "\n")
}

#[cfg(test)]
pub fn resolves(topic: &str, lang: Lang) -> bool {
    let (name, anchor) = split(topic);
    PAGES
        .iter()
        .find(|page| page.name == name)
        .is_some_and(|page| anchor.is_none_or(|anchor| section(page, anchor, lang).is_some()))
}

fn split(topic: &str) -> (&str, Option<&str>) {
    match topic.split_once('#') {
        Some((name, anchor)) => (name, Some(anchor)),
        None => (topic, None),
    }
}

pub fn render(topic: Option<&str>, toc: bool, lang: Lang) -> anyhow::Result<String> {
    let Some(topic) = topic else {
        return Ok(index(lang));
    };
    let (name, anchor) = split(topic);
    let page = find(name)?;
    if toc {
        return Ok(contents(page, lang));
    }
    let text = match anchor {
        None => page.text(lang).to_string(),
        Some(anchor) => match section(page, anchor, lang) {
            Some(text) => text,
            None => bail!(
                "page {name} has no section #{anchor}; list its sections with `credshim docs {name} --toc`"
            ),
        },
    };
    let mut out = navigable(&text, page);
    let _ = write!(
        out,
        "\n---\nweb: {SITE}/{}/{}.html{}\n",
        lang.dir(),
        page.source(),
        anchor
            .map(|anchor| format!("#{anchor}"))
            .unwrap_or_default()
    );
    Ok(out)
}

fn index(lang: Lang) -> String {
    let mut out =
        String::from("CredShim documentation (this version's, built into the binary)\n\n");
    for page in PAGES {
        let title = headings(page.text(lang))
            .into_iter()
            .next()
            .map(|heading| heading.title)
            .unwrap_or_default();
        let _ = writeln!(out, "  {:<16} {title}", page.name);
    }
    out.push_str(
        "\nRead a page:       credshim docs <page>\n\
         List its sections: credshim docs <page> --toc\n\
         Read one section:  credshim docs <page>#<section>\n\
         Language:          --lang en|ja (default: from LANG)\n",
    );
    out
}

fn contents(page: &Page, lang: Lang) -> String {
    let mut out = String::new();
    for heading in headings(page.text(lang)) {
        let indent = "  ".repeat(heading.level - 1);
        let _ = writeln!(
            out,
            "{indent}{}  (credshim docs {}#{})",
            heading.title, page.name, heading.anchor
        );
    }
    out
}

fn navigable(text: &str, page: &Page) -> String {
    let mut out = String::with_capacity(text.len());
    let mut fenced = false;
    for line in text.lines() {
        if line.starts_with("```") {
            fenced = !fenced;
        }
        if fenced {
            out.push_str(line);
        } else {
            out.push_str(&relink(line, page));
        }
        out.push('\n');
    }
    out
}

fn relink(line: &str, page: &Page) -> String {
    let mut out = String::new();
    let mut rest = line;
    while let Some(at) = rest.find("](") {
        out.push_str(&rest[..at + 2]);
        let after = &rest[at + 2..];
        let Some(end) = after.find(')') else {
            rest = after;
            break;
        };
        let target = &after[..end];
        match docs_topic(target, page) {
            Some(topic) => {
                out.push_str("credshim docs ");
                out.push_str(&topic);
            }
            None => out.push_str(target),
        }
        out.push(')');
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    out
}

fn docs_topic(target: &str, page: &Page) -> Option<String> {
    if target.contains("://") {
        return None;
    }
    let (path, anchor) = split(target);
    let name = if path.is_empty() {
        page.name
    } else {
        let file = path.rsplit('/').next()?;
        let stem = file.strip_suffix(".md")?;
        if stem == "README" {
            "overview"
        } else {
            PAGES.iter().find(|page| page.name == stem)?.name
        }
    };
    Some(match anchor {
        Some(anchor) => format!("{name}#{anchor}"),
        None => name.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs_follow_mdbook() {
        assert_eq!(
            slug("6. Replace existing credentials"),
            "6-replace-existing-credentials"
        );
        assert_eq!(slug(&plain("`not_allowed`")), "not_allowed");
        assert_eq!(slug("macOS の Go 製ツール"), "macos-の-go-製ツール");
        assert_eq!(slug(&plain("[Base URL](x.md) mode")), "base-url-mode");
    }

    #[test]
    fn every_page_has_the_same_heading_levels_in_both_languages() {
        for page in PAGES {
            let levels = |text| headings(text).iter().map(|h| h.level).collect::<Vec<_>>();
            assert_eq!(levels(page.en), levels(page.ja), "{}", page.name);
        }
    }

    #[test]
    fn every_link_between_pages_resolves_in_its_own_language() {
        const MARK: &str = "](credshim docs ";
        for lang in [Lang::En, Lang::Ja] {
            for page in PAGES {
                let text = navigable(page.text(lang), page);
                let mut rest = text.as_str();
                while let Some(at) = rest.find(MARK) {
                    rest = &rest[at + MARK.len()..];
                    let topic = &rest[..rest.find(')').unwrap()];
                    assert!(resolves(topic, lang), "{lang:?} {}: {topic}", page.name);
                }
            }
        }
    }

    #[test]
    fn an_english_anchor_finds_the_same_section_in_japanese() {
        let page = find("configuration").unwrap();
        let section = section(page, "audit-log-and-status", Lang::Ja).unwrap();
        assert!(section.starts_with("## 監査ログと状態\n"), "{section}");
    }

    #[test]
    fn a_section_ends_at_the_next_heading_of_its_level() {
        let page = find("troubleshooting").unwrap();
        let section = section(page, "not_allowed", Lang::En).unwrap();
        assert!(section.starts_with("### `not_allowed`\n"), "{section}");
        assert!(!section.contains("### `limited`"), "{section}");
    }
}
