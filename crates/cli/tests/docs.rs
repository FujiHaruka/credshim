mod common;

use common::output;

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[tokio::test]
async fn docs_lists_pages_and_says_how_to_go_deeper_without_any_config() {
    let home = tempfile::tempdir().unwrap();

    let listed = output(home.path(), &["docs", "--lang", "en"]).await;

    assert!(listed.status.success(), "{}", stderr(&listed));
    let text = stdout(&listed);
    assert!(text.contains("  troubleshooting  Troubleshooting\n"), "{text}");
    assert!(text.contains("credshim docs <page>#<section>"), "{text}");
}

#[tokio::test]
async fn docs_prints_one_section_with_links_turned_into_docs_commands() {
    let home = tempfile::tempdir().unwrap();

    let section = output(
        home.path(),
        &["docs", "troubleshooting#files", "--lang", "en"],
    )
    .await;

    assert!(section.status.success(), "{}", stderr(&section));
    let text = stdout(&section);
    assert!(text.starts_with("### `files`\n"), "{text}");
    assert!(
        text.contains("](credshim docs install#6-replace-existing-credentials)"),
        "{text}"
    );
    assert!(!text.contains("### `proxy`"), "{text}");
    assert!(
        text.ends_with(
            "web: https://fujiharuka.github.io/credshim/en/troubleshooting.html#files\n"
        ),
        "{text}"
    );
}

#[tokio::test]
async fn an_english_anchor_prints_the_japanese_section() {
    let home = tempfile::tempdir().unwrap();

    let section = output(
        home.path(),
        &["docs", "configuration#audit-log-and-status", "--lang", "ja"],
    )
    .await;

    assert!(section.status.success(), "{}", stderr(&section));
    assert!(stdout(&section).starts_with("## 監査ログと状態\n"));
}

#[tokio::test]
async fn a_missing_section_says_how_to_list_the_sections() {
    let home = tempfile::tempdir().unwrap();

    let missing = output(home.path(), &["docs", "install#nope"]).await;

    assert!(!missing.status.success());
    assert!(
        stderr(&missing).contains("list its sections with `credshim docs install --toc`"),
        "{}",
        stderr(&missing)
    );
}

#[tokio::test]
async fn every_error_ends_with_the_docs_for_its_command() {
    let home = tempfile::tempdir().unwrap();
    let config = home.path().join("missing.toml");

    let failed = output(
        home.path(),
        &["tail", "--config", config.to_str().unwrap(), "--no-follow"],
    )
    .await;

    assert!(!failed.status.success());
    assert!(
        stderr(&failed).ends_with("\ndocs: credshim docs configuration#audit-log-and-status\n"),
        "{}",
        stderr(&failed)
    );
}

#[tokio::test]
async fn help_ends_with_the_docs_for_the_command() {
    let home = tempfile::tempdir().unwrap();

    let help = output(home.path(), &["doctor", "--help"]).await;

    assert!(
        stdout(&help).ends_with("Docs: credshim docs troubleshooting#credshim-doctor\n"),
        "{}",
        stdout(&help)
    );
}
