mod common;

use std::path::PathBuf;
use std::sync::Arc;

use common::UserKey;
use credshim_ssh::ssh_key::PublicKey;
use credshim_ssh::{Agent, SigningKey, SshKeySpec, SshRule};
use credshim_testkit::capture_logs;
use credshim_testkit::sshd::{HOST_KEY_TYPES, SshOutput, TestSshd, keygen, login_user};
use secrecy::ExposeSecret;

struct World {
    sshd: TestSshd,
    key: UserKey,
    _agent: tokio::task::JoinHandle<()>,
}

impl World {
    async fn start(name: &str, host_keys: &[&str], users: Option<&[&str]>) -> Self {
        capture_logs();
        let key = UserKey::generate();
        let public = PublicKey::new(key.public(), "credshim");
        let sshd = TestSshd::start(&format!("{}\n", public.to_openssh().unwrap())).await;
        let rule = SshRule::from_spec(SshKeySpec {
            name: name.to_string(),
            secret: format!("ssh-{name}"),
            host_keys: host_keys
                .iter()
                .map(|kind| sshd.host_key_fingerprint(kind))
                .collect(),
            users: users.map_or_else(
                || vec![login_user()],
                |users| users.iter().map(|u| u.to_string()).collect(),
            ),
            limits: Default::default(),
        })
        .unwrap();
        let signer = SigningKey::from_secret(&key.secret).unwrap();
        let agent = Arc::new(Agent::new(vec![(rule, signer)]))
            .bind(&sshd.dir().join("agent.sock"))
            .unwrap();
        Self {
            sshd,
            key,
            _agent: agent,
        }
    }

    fn socket(&self) -> PathBuf {
        self.sshd.dir().join("agent.sock")
    }

    async fn ssh(&self, host_key_algorithm: &str, extra: &[&str], remote: &str) -> SshOutput {
        self.sshd
            .ssh(&self.socket(), host_key_algorithm, extra, remote)
            .await
    }

    fn audit_lines(&self, rule: &str) -> Vec<String> {
        let rules = format!("rules=\"{rule}\"");
        capture_logs()
            .contents()
            .lines()
            .filter(|line| line.contains(credshim_core::AUDIT_TARGET) && line.contains(&rules))
            .map(str::to_string)
            .collect()
    }

    fn assert_key_never_logged(&self) {
        let pem = self.key.secret.expose_secret().to_string();
        let body: Vec<&str> = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        assert!(!body.is_empty());
        capture_logs().assert_absent(&body);
    }
}

#[tokio::test]
async fn openssh_authenticates_through_the_agent_for_every_host_key_type() {
    let world = World::start("every-type", &["ed25519", "ecdsa", "rsa"], None).await;
    for (kind, algorithm) in HOST_KEY_TYPES {
        let out = world.ssh(algorithm, &[], "echo authenticated").await;
        assert!(
            out.success && out.text.contains("authenticated"),
            "{kind}: {}\n{}",
            out.text,
            world.sshd.log()
        );
    }
    let signed = world
        .audit_lines("every-type")
        .into_iter()
        .filter(|line| line.contains(r#"decision="sign""#))
        .count();
    assert_eq!(signed, 3);
    world.assert_key_never_logged();
}

#[tokio::test]
async fn servers_whose_host_key_is_not_bound_get_no_signature_and_the_refusal_is_audited() {
    let world = World::start("only-ed25519", &["ed25519"], None).await;
    let out = world.ssh("ecdsa-sha2-nistp256", &[], "true").await;
    assert!(!out.success, "{}", out.text);
    assert!(out.text.contains("Permission denied"), "{}", out.text);
    let ecdsa = world.sshd.host_key_fingerprint("ecdsa");
    let lines = world.audit_lines("only-ed25519");
    assert!(
        lines
            .iter()
            .any(|line| line.contains(&format!("host_key=\"{ecdsa}\""))
                && line.contains(r#"decision="deny""#)
                && line.contains(r#"reason="host_key_not_bound""#)),
        "{lines:#?}"
    );
    assert!(!lines.iter().any(|line| line.contains(r#"decision="sign""#)));
    world.assert_key_never_logged();
}

#[tokio::test]
async fn users_outside_the_allow_list_are_refused() {
    let world = World::start("git-only", &["ed25519"], Some(&["git"])).await;
    let out = world.ssh("ssh-ed25519", &[], "true").await;
    assert!(!out.success, "{}", out.text);
    let lines = world.audit_lines("git-only");
    assert!(
        lines
            .iter()
            .any(|line| line.contains(&format!("user=\"{}\"", login_user()))
                && line.contains(r#"reason="user_not_allowed""#)),
        "{lines:#?}"
    );
}

#[tokio::test]
async fn requests_through_a_forwarded_agent_are_refused() {
    let world = World::start("forwarded", &["ed25519"], None).await;
    let inner = format!(
        "ssh {} -o HostKeyAlgorithms=ssh-ed25519 -p {} {}@127.0.0.1 echo inner-ok",
        world.sshd.client_options().join(" "),
        world.sshd.port(),
        login_user()
    );
    let out = world.ssh("ssh-ed25519", &["-A"], &inner).await;
    assert!(!out.success, "{}", out.text);
    assert!(!out.text.contains("inner-ok"), "{}", out.text);
    assert!(
        out.text.contains("Permission denied"),
        "{}\n{}",
        out.text,
        world.sshd.log()
    );
    let lines = world.audit_lines("forwarded");
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.contains(r#"decision="sign""#))
            .count(),
        1,
        "only the outer login is signed: {lines:#?}"
    );
    assert!(
        lines
            .iter()
            .any(|line| line.contains(r#"reason="forwarded""#)),
        "{lines:#?}"
    );
}

#[tokio::test]
async fn ssh_keygen_signatures_are_refused() {
    let world = World::start("sshsig", &["ed25519"], None).await;
    let dir = world.sshd.dir();
    let public = dir.join("user.pub");
    let key = PublicKey::new(world.key.public(), "credshim");
    std::fs::write(&public, key.to_openssh().unwrap()).unwrap();
    let message = dir.join("message");
    std::fs::write(&message, "commit").unwrap();
    let out = world
        .sshd
        .command("ssh-keygen", &world.socket())
        .args(["-Y", "sign", "-n", "git", "-f"])
        .arg(&public)
        .arg(&message)
        .output()
        .await
        .unwrap();
    assert!(!out.status.success());
    assert!(!dir.join("message.sig").exists());
    let lines = world.audit_lines("sshsig");
    assert!(
        lines
            .iter()
            .any(|line| line.contains(r#"reason="no_session_bind""#)),
        "{lines:#?}"
    );
}

#[tokio::test]
async fn ssh_add_cannot_change_the_agent() {
    let world = World::start("readonly", &["ed25519"], None).await;
    let extra = world.sshd.dir().join("extra");
    keygen(&extra, "ed25519");
    for args in [vec!["-D".to_string()], vec![extra.display().to_string()]] {
        let out = world
            .sshd
            .command("ssh-add", &world.socket())
            .args(&args)
            .output()
            .await
            .unwrap();
        assert!(!out.status.success(), "ssh-add {args:?} succeeded");
    }
    let out = world
        .sshd
        .command("ssh-add", &world.socket())
        .arg("-L")
        .output()
        .await
        .unwrap();
    assert!(out.status.success());
    let listed = String::from_utf8(out.stdout).unwrap();
    assert_eq!(listed.lines().count(), 1, "{listed}");
    assert!(listed.contains("credshim:readonly"), "{listed}");
}
