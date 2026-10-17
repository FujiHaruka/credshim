mod common;

use std::os::unix::fs::PermissionsExt;

use common::output;

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn write_draft(home: &std::path::Path, contents: &str) -> String {
    let path = home.join("draft.toml");
    std::fs::write(&path, contents).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o664)).unwrap();
    path.display().to_string()
}

#[tokio::test]
async fn a_draft_is_checked_without_the_secret_store_and_says_how_to_apply_it() {
    let home = tempfile::tempdir().unwrap();
    let preset = output(home.path(), &["preset", "openai"]).await;
    let draft = write_draft(
        home.path(),
        &format!(
            "{}\n[[rule]]\nname = \"echo\"\nhost = \"echo.example.com\"\nport = 8443\npath_prefix = \"/v1\"\nsecret = \"echo\"\ndummy = \"sk-credshim-echo-0123456789abcdefghij\"\ninject = {{ header = \"authorization\" }}\nlimits = {{ per_minute = 5 }}\n\n[[ssh_key]]\nname = \"github\"\nsecret = \"ssh-github\"\nusers = [\"git\"]\nhost_keys = [\"SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU\"]\n",
            text(&preset.stdout)
        ),
    );

    let checked = output(home.path(), &["config", "check", &draft]).await;

    assert!(checked.status.success(), "{}", text(&checked.stderr));
    let stdout = text(&checked.stdout);
    assert!(
        stdout.starts_with(&format!("{draft} is a valid config.\n")),
        "{stdout}"
    );
    assert!(
        stdout.contains(
            "  rule \"openai\": secret openai -> https://api.openai.com:443  (openai preset host)\n"
        ),
        "{stdout}"
    );
    assert!(
        stdout.contains("  rule \"echo\": secret echo -> https://echo.example.com:8443/v1  !! host not from a preset: confirm with the service\n      methods: all; paths: all; limits: per_minute 5\n"),
        "{stdout}"
    );
    assert!(stdout.contains("(github-ssh preset host keys)"), "{stdout}");
    assert!(stdout.contains(" secret set openai\n"), "{stdout}");
    assert!(stdout.contains(" ssh keygen ssh-github "), "{stdout}");
    assert!(
        stdout.contains("These sections apply only after a restart"),
        "{stdout}"
    );
    assert_eq!(
        std::fs::read_dir(home.path()).unwrap().count(),
        1,
        "only the draft exists"
    );
}

#[tokio::test]
async fn every_problem_in_a_draft_is_listed_with_its_docs() {
    let home = tempfile::tempdir().unwrap();
    let draft = write_draft(
        home.path(),
        "[[rule]]\nname = \"a\"\nhost = \"api.example.com\"\nsecret = \"a\"\ndummy = \"short\"\ninject = { header = \"authorization\" }\nenv = \"lower\"\n\n[ssh]\nclient_uids = []\n",
    );

    let checked = output(home.path(), &["config", "check", &draft]).await;

    assert!(!checked.status.success());
    let stderr = text(&checked.stderr);
    assert!(
        stderr.starts_with(&format!(
            "Error: {draft} has 3 problems\n  1. rule \"a\": env"
        )),
        "{stderr}"
    );
    assert!(
        stderr.contains("\n     docs: credshim docs ssh#configuration\n"),
        "{stderr}"
    );
    assert!(
        stderr.ends_with("\ndocs: credshim docs configuration#checking-a-draft\n"),
        "{stderr}"
    );
}

#[tokio::test]
async fn a_config_error_points_to_the_section_it_is_in() {
    let home = tempfile::tempdir().unwrap();
    let draft = write_draft(home.path(), "[secrets]\nbackend = \"file\"\n");

    let checked = output(home.path(), &["config", "check", &draft]).await;

    let stderr = text(&checked.stderr);
    assert!(stderr.contains("unknown variant `file`"), "{stderr}");
    assert!(
        stderr.ends_with("\ndocs: credshim docs configuration#secret-stores\n"),
        "{stderr}"
    );
}

#[tokio::test]
async fn the_github_preset_sits_beside_github_ssh_and_lets_gh_change_pull_requests() {
    let home = tempfile::tempdir().unwrap();
    let api = output(home.path(), &["preset", "github"]).await;
    let ssh = output(home.path(), &["preset", "github-ssh"]).await;
    let draft = write_draft(
        home.path(),
        &format!("{}\n{}", text(&api.stdout), text(&ssh.stdout)),
    );

    let checked = output(home.path(), &["config", "check", &draft]).await;

    assert!(checked.status.success(), "{}", text(&checked.stderr));
    let stdout = text(&checked.stdout);
    assert!(
        stdout.contains(
            "  rule \"github\": secret github -> https://api.github.com:443  (github preset host)\n      methods: GET, POST, PATCH, PUT, DELETE; paths: /graphql, /repos,"
        ),
        "{stdout}"
    );
    assert!(stdout.contains("(github-ssh preset host keys)"), "{stdout}");
    assert!(text(&api.stdout).contains("env = \"GH_TOKEN\""));
}

#[tokio::test]
async fn every_host_an_oauth_provider_sends_its_secrets_to_is_listed_and_marked() {
    let home = tempfile::tempdir().unwrap();
    let draft = write_draft(
        home.path(),
        "[[oauth]]\nname = \"example\"\ntoken_endpoint = \"https://oauth.example.com/token\"\nrevoke_endpoint = \"https://revoke.example.net:8443/revoke\"\nclient_secret = { secret = \"example-client\", dummy = \"credshim-example-client-0123456789abcdef\" }\nresource_hosts = [\"api.example.com\", \"api.github.com\"]\n",
    );

    let checked = output(home.path(), &["config", "check", &draft]).await;

    assert!(checked.status.success(), "{}", text(&checked.stderr));
    let stdout = text(&checked.stdout);
    let not_preset = "  !! host not from a preset: confirm with the service\n";
    for line in [
        format!(
            "  oauth \"example\": client secret and refresh tokens -> https://oauth.example.com/token{not_preset}"
        ),
        format!(
            "      revoke: client secret, access and refresh tokens -> https://revoke.example.net:8443/revoke{not_preset}"
        ),
        format!("      access tokens -> https://api.example.com:443{not_preset}"),
        "      access tokens -> https://api.github.com:443  (github preset host)\n".to_string(),
    ] {
        assert!(stdout.contains(&line), "{line}\n{stdout}");
    }
}

#[tokio::test]
async fn an_aws_key_that_reaches_api_gateway_is_marked() {
    let home = tempfile::tempdir().unwrap();
    let draft = write_draft(
        home.path(),
        "[[aws_key]]\nname = \"gateway\"\ndummy_access_key_id = \"CREDSHIMAWS0123456789ABCDEF\"\naccess_key_id = \"aws-access-key-id\"\nsecret_access_key = \"aws-secret-access-key\"\nservices = [\"s3\", \"execute-api\"]\n\n[[aws_key]]\nname = \"storage\"\ndummy_access_key_id = \"CREDSHIMAWS9876543210ZYXWVU\"\naccess_key_id = \"aws-access-key-id\"\nsecret_access_key = \"aws-secret-access-key\"\nservices = [\"s3\"]\n",
    );

    let checked = output(home.path(), &["config", "check", &draft]).await;

    assert!(checked.status.success(), "{}", text(&checked.stderr));
    let stdout = text(&checked.stdout);
    assert!(
        stdout.contains("  aws_key \"gateway\": secrets aws-access-key-id and aws-secret-access-key -> AWS endpoints, including execute-api in any AWS account  !! whoever runs such an endpoint gets the request: confirm the rule needs it\n"),
        "{stdout}"
    );
    assert!(
        stdout.contains("  aws_key \"storage\": secrets aws-access-key-id and aws-secret-access-key -> AWS endpoints only\n"),
        "{stdout}"
    );
}

#[tokio::test]
async fn control_characters_in_a_draft_cannot_redraw_the_destinations() {
    let home = tempfile::tempdir().unwrap();
    let draft = write_draft(
        home.path(),
        "[[rule]]\nname = \"openai-v2\"\nhost = \"attacker.example\"\nsecret = \"openai\"\ndummy = \"sk-credshim-openai-0123456789abcdefghij\"\ninject = { header = \"authorization\" }\nallow_paths = [\"/\", \"/\\u001b[1A\\r\\u001b[2K  rule\"]\n",
    );

    let checked = output(home.path(), &["config", "check", &draft]).await;

    assert!(!checked.status.success());
    let stderr = text(&checked.stderr);
    assert!(stderr.contains("allow_paths entry"), "{stderr}");
    assert!(!stderr.contains('\u{1b}'), "{stderr:?}");
    assert!(!stderr.contains('\r'), "{stderr:?}");
}

#[tokio::test]
async fn a_preset_prints_only_the_rule_on_stdout_and_the_next_steps_on_stderr() {
    let home = tempfile::tempdir().unwrap();

    let preset = output(home.path(), &["preset", "aws"]).await;

    assert!(preset.status.success());
    let stdout = text(&preset.stdout);
    assert!(stdout.starts_with("[[aws_key]]\n"), "{stdout}");
    assert!(!stdout.contains("credshim:"), "{stdout}");
    let stderr = text(&preset.stderr);
    assert!(
        stderr.starts_with("credshim: next steps for this aws preset:\n  1. Add it to the config"),
        "{stderr}"
    );
    assert!(
        stderr.contains(" secret set aws-access-key-id\n"),
        "{stderr}"
    );
    assert!(
        stderr.contains(" secret set aws-secret-access-key\n"),
        "{stderr}"
    );
}

#[tokio::test]
async fn secret_set_without_a_terminal_names_the_command_for_the_person() {
    let home = tempfile::tempdir().unwrap();
    let config = common::write_config(home.path(), "");

    let output = output(
        home.path(),
        &["secret", "set", "openai", "--config", &config],
    )
    .await;

    assert!(!output.status.success());
    let stderr = text(&output.stderr);
    assert!(
        stderr.contains(&format!(
            "ask the person to run: {} secret set openai --config {config}\n",
            std::fs::canonicalize(env!("CARGO_BIN_EXE_credshim"))
                .unwrap()
                .display()
        )),
        "{stderr}"
    );
    assert!(!home.path().join("secrets.age").exists());
}
