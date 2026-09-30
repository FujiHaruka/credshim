use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use credshim_secrets::{
    AgeFileStore, BackendConfig, CommandStore, Keychain, KeychainStore, SecretStore, StoreError,
};
use credshim_testkit::fake_secret;
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn value(store: &dyn SecretStore, name: &str) -> Option<String> {
    store
        .get(name)
        .unwrap()
        .map(|secret| secret.expose_secret().to_string())
}

fn assert_round_trip(store: &dyn SecretStore) {
    let before = SystemTime::now() - Duration::from_secs(1);
    let openai = fake_secret("openai");
    let anthropic = fake_secret("anthropic");

    assert_eq!(value(store, "openai"), None);
    store
        .set("openai", SecretString::from(openai.as_str()))
        .unwrap();
    store
        .set("anthropic", SecretString::from("old value"))
        .unwrap();
    store
        .set("anthropic", SecretString::from(anthropic.as_str()))
        .unwrap();

    assert_eq!(value(store, "openai").as_deref(), Some(openai.as_str()));
    assert_eq!(
        value(store, "anthropic").as_deref(),
        Some(anthropic.as_str())
    );
    let listed = store.list().unwrap();
    let names: Vec<&str> = listed.iter().map(|info| info.name.as_str()).collect();
    assert_eq!(names, ["anthropic", "openai"]);
    assert!(listed.iter().all(|info| info.updated_at >= before));
    let rendered = format!("{listed:?}");
    assert!(!rendered.contains(&openai) && !rendered.contains(&anthropic));
}

fn assert_remove(store: &dyn SecretStore) {
    store.set("kept", SecretString::from("kept")).unwrap();
    store.set("gone", SecretString::from("gone")).unwrap();

    assert!(store.remove("gone").unwrap());
    assert!(!store.remove("gone").unwrap());
    assert_eq!(value(store, "gone"), None);
    assert_eq!(value(store, "kept").as_deref(), Some("kept"));
    let names: Vec<String> = store
        .list()
        .unwrap()
        .into_iter()
        .map(|info| info.name)
        .collect();
    assert_eq!(names, ["kept"]);
    assert!(matches!(
        store.remove("a/b"),
        Err(StoreError::InvalidName(_))
    ));
}

fn assert_rejects_bad_names(store: &dyn SecretStore) {
    for name in ["", "a/b", "../x", "with space"] {
        assert!(
            matches!(
                store.set(name, SecretString::from("x")),
                Err(StoreError::InvalidName(_))
            ),
            "{name:?}"
        );
        assert!(matches!(store.get(name), Err(StoreError::InvalidName(_))));
    }
}

#[test]
fn age_file_round_trips_and_keeps_files_private() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state").join("secrets.age");
    let store = AgeFileStore::new(path.clone(), None);

    assert_round_trip(&store);

    let identity = dir.path().join("state").join("secrets.key");
    assert_eq!(store.identity_path(), identity);
    assert_eq!(mode(&path), 0o600);
    assert_eq!(mode(&identity), 0o600);
    assert_eq!(mode(&dir.path().join("state")), 0o700);
}

#[test]
fn age_file_is_encrypted_at_rest() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secrets.age");
    let secret = fake_secret("at-rest");
    let store = AgeFileStore::new(path.clone(), None);
    store
        .set("openai", SecretString::from(secret.as_str()))
        .unwrap();

    let raw = std::fs::read(&path).unwrap();
    assert!(raw.starts_with(b"age-encryption.org/v1"));
    assert!(!String::from_utf8_lossy(&raw).contains(&secret));

    let reopened = AgeFileStore::new(path, None);
    assert_eq!(value(&reopened, "openai"), Some(secret));
}

#[test]
fn age_file_uses_an_explicit_identity_path() {
    let dir = tempfile::tempdir().unwrap();
    let identity = dir.path().join("keys").join("id.txt");
    let store = AgeFileStore::new(dir.path().join("s.age"), Some(identity.clone()));

    store.set("a", SecretString::from("v")).unwrap();

    assert!(identity.exists());
    assert!(!dir.path().join("s.key").exists());
}

#[test]
fn age_file_without_its_identity_is_an_error_not_a_fresh_store() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secrets.age");
    let store = AgeFileStore::new(path.clone(), None);
    store.set("a", SecretString::from("v")).unwrap();
    std::fs::remove_file(dir.path().join("secrets.key")).unwrap();

    assert!(matches!(store.get("a"), Err(StoreError::Io { .. })));
    assert!(matches!(
        store.set("b", SecretString::from("v")),
        Err(StoreError::Corrupt { .. })
    ));
}

#[test]
fn age_file_with_the_wrong_identity_is_corrupt() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secrets.age");
    AgeFileStore::new(path.clone(), None)
        .set("a", SecretString::from("v"))
        .unwrap();
    let other = dir.path().join("other.key");
    AgeFileStore::new(dir.path().join("other.age"), Some(other.clone()))
        .set("b", SecretString::from("v"))
        .unwrap();

    let store = AgeFileStore::new(path, Some(other));
    assert!(matches!(store.get("a"), Err(StoreError::Corrupt { .. })));
}

#[test]
fn age_file_removes_one_secret_and_keeps_the_rest() {
    let dir = tempfile::tempdir().unwrap();
    assert_remove(&AgeFileStore::new(dir.path().join("s.age"), None));
}

#[test]
fn age_file_writers_in_parallel_do_not_lose_each_others_secrets() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("s.age");
    AgeFileStore::new(path.clone(), None)
        .set("seed", SecretString::from("seed"))
        .unwrap();
    let writers: Vec<_> = (0..8)
        .map(|i| {
            let path = path.clone();
            std::thread::spawn(move || {
                let store = AgeFileStore::new(path, None);
                for round in 0..4 {
                    store
                        .set(&format!("w{i}-{round}"), SecretString::from("v"))
                        .unwrap();
                }
            })
        })
        .collect();
    for writer in writers {
        writer.join().unwrap();
    }

    let store = AgeFileStore::new(path, None);
    assert_eq!(store.list().unwrap().len(), 1 + 8 * 4);
}

#[test]
fn age_file_rejects_bad_names() {
    let dir = tempfile::tempdir().unwrap();
    assert_rejects_bad_names(&AgeFileStore::new(dir.path().join("s.age"), None));
}

#[derive(Default)]
struct FakeKeychain(Mutex<HashMap<String, String>>);

impl Keychain for &FakeKeychain {
    fn get(&self, account: &str) -> Result<Option<Zeroizing<String>>, StoreError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .get(account)
            .cloned()
            .map(Zeroizing::new))
    }

    fn set(&self, account: &str, value: &str) -> Result<(), StoreError> {
        self.0
            .lock()
            .unwrap()
            .insert(account.to_string(), value.to_string());
        Ok(())
    }

    fn delete(&self, account: &str) -> Result<bool, StoreError> {
        Ok(self.0.lock().unwrap().remove(account).is_some())
    }
}

#[test]
fn keychain_store_removes_the_entry_and_its_index_row() {
    let keychain = FakeKeychain::default();
    assert_remove(&KeychainStore::new(&keychain));

    let accounts = keychain.0.lock().unwrap();
    assert!(!accounts.contains_key("secret:gone"));
    assert!(!accounts["index"].contains("gone"));
}

#[test]
fn keychain_store_round_trips_through_namespaced_accounts() {
    let keychain = FakeKeychain::default();
    let store = KeychainStore::new(&keychain);

    assert_round_trip(&store);
    assert_rejects_bad_names(&store);

    let accounts = keychain.0.lock().unwrap();
    let mut names: Vec<&str> = accounts.keys().map(String::as_str).collect();
    names.sort();
    assert_eq!(names, ["index", "secret:anthropic", "secret:openai"]);
    assert!(!accounts["index"].contains("FAKE-SECRET"));
}

fn script(dir: &Path, body: &str) -> String {
    let path = dir.join("fetch.sh");
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    path.to_string_lossy().into_owned()
}

fn command_store(dir: &Path, body: &str, timeout: Duration) -> CommandStore {
    CommandStore::new(
        vec![script(dir, body), "op://dev/{name}/credential".into()],
        timeout,
    )
    .unwrap()
}

#[test]
fn command_store_substitutes_the_name_and_trims_one_newline() {
    let dir = tempfile::tempdir().unwrap();
    let store = command_store(
        dir.path(),
        r#"printf 'value-for:%s\n' "$1""#,
        Duration::from_secs(10),
    );

    assert_eq!(
        value(&store, "openai").as_deref(),
        Some("value-for:op://dev/openai/credential")
    );
}

#[test]
fn command_store_reports_failures_without_output() {
    let dir = tempfile::tempdir().unwrap();
    let secret = fake_secret("command");
    let failing = command_store(
        dir.path(),
        &format!("echo {secret}; exit 3"),
        Duration::from_secs(10),
    );

    let err = failing.get("openai").unwrap_err();
    assert!(matches!(err, StoreError::Command { .. }));
    assert!(!err.to_string().contains(&secret), "{err}");

    let empty = command_store(dir.path(), "true", Duration::from_secs(10));
    assert_eq!(value(&empty, "openai"), None);
}

#[test]
fn command_store_times_out() {
    let dir = tempfile::tempdir().unwrap();
    let slow = command_store(dir.path(), "sleep 10", Duration::from_millis(200));

    let started = std::time::Instant::now();
    let err = slow.get("openai").unwrap_err();

    assert!(err.to_string().contains("timed out"), "{err}");
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn command_store_is_read_only() {
    let dir = tempfile::tempdir().unwrap();
    let store = command_store(dir.path(), "true", Duration::from_secs(10));

    assert!(matches!(
        store.set("a", SecretString::from("v")),
        Err(StoreError::ReadOnly(_))
    ));
    assert!(matches!(store.remove("a"), Err(StoreError::ReadOnly(_))));
    assert!(matches!(store.list(), Err(StoreError::ListUnsupported(_))));
    assert!(CommandStore::new(vec![], Duration::from_secs(1)).is_err());
}

#[test]
fn backend_config_parses_each_backend_and_rejects_unknown_fields() {
    let parse = |text: &str| toml::from_str::<BackendConfig>(text);

    assert_eq!(
        parse(r#"backend = "keychain""#).unwrap(),
        BackendConfig::Keychain { service: None }
    );
    assert_eq!(
        parse("backend = \"age-file\"\npath = \"/tmp/s.age\"").unwrap(),
        BackendConfig::AgeFile {
            path: "/tmp/s.age".into(),
            identity: None
        }
    );
    assert_eq!(
        parse("backend = \"command\"\ncommand = [\"op\", \"read\"]\ntimeout_secs = 5").unwrap(),
        BackendConfig::Command {
            command: vec!["op".into(), "read".into()],
            timeout_secs: Some(5)
        }
    );
    assert!(parse("backend = \"age-file\"\npath = \"x\"\nextra = 1").is_err());
    assert!(parse(r#"backend = "vault""#).is_err());
}

#[test]
fn backend_config_opens_an_age_file_store() {
    let dir = tempfile::tempdir().unwrap();
    let config = BackendConfig::AgeFile {
        path: dir.path().join("s.age"),
        identity: None,
    };
    let store = config.open().unwrap();

    store.set("x", SecretString::from("v")).unwrap();
    assert_eq!(value(store.as_ref(), "x").as_deref(), Some("v"));
}

#[test]
fn command_store_times_out_when_a_background_process_holds_stdout() {
    let dir = tempfile::tempdir().unwrap();
    let store = command_store(
        dir.path(),
        "sleep 10 &\necho value",
        Duration::from_millis(500),
    );

    let started = std::time::Instant::now();
    let err = store.get("openai").unwrap_err();

    assert!(err.to_string().contains("timed out"), "{err}");
    assert!(started.elapsed() < Duration::from_secs(5));
}
