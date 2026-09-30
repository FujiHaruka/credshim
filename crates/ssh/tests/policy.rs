mod common;

use common::{Auth, HostKey, UserKey, agent_key, encode, rule, session_id, sign_request};
use credshim_ssh::{BindRefusal, Connection, Refusal, SshKeySpec, SshRule, SshRuleError};

struct Case {
    host: HostKey,
    user: UserKey,
    keys: Vec<credshim_ssh::AgentKey>,
    session_id: Vec<u8>,
}

impl Case {
    fn new() -> Self {
        let host = HostKey::generate();
        let user = UserKey::generate();
        let keys = vec![agent_key(
            rule("github", &[host.fingerprint()], &["git"]),
            &user,
        )];
        Self {
            host,
            user,
            keys,
            session_id: session_id(32),
        }
    }

    fn bound(&self) -> Connection {
        let mut connection = Connection::default();
        connection
            .bind(&self.host.bind(&self.session_id, false))
            .unwrap();
        connection
    }

    fn hostbound(&self) -> Auth<'_> {
        Auth::hostbound(&self.session_id, "git", &self.user, &self.host)
    }

    fn decide(&self, connection: &Connection, data: Vec<u8>) -> credshim_ssh::Decision {
        connection.decide(&self.keys, &sign_request(&self.user, data))
    }

    fn refusal(&self, connection: &Connection, data: Vec<u8>) -> Option<Refusal> {
        self.decide(connection, data).refusal
    }
}

#[test]
fn hostbound_and_plain_publickey_requests_to_a_bound_host_are_approved() {
    for len in [32, 64] {
        let mut case = Case::new();
        case.session_id = session_id(len);
        let connection = case.bound();
        let decision = case.decide(&connection, case.hostbound().to_bytes());
        assert_eq!(decision.approved(), Some(0), "session id of {len} bytes");
        assert_eq!(decision.user.as_deref(), Some("git"));
        assert_eq!(
            decision.host_key.unwrap().to_string(),
            case.host.fingerprint()
        );
        let plain = Auth::plain(&case.session_id, "git", &case.user).to_bytes();
        assert_eq!(case.decide(&connection, plain).approved(), Some(0));
    }
}

#[test]
fn requests_without_a_session_bind_are_refused() {
    let case = Case::new();
    let data = case.hostbound().to_bytes();
    assert_eq!(
        case.refusal(&Connection::default(), data),
        Some(Refusal::NoSessionBind)
    );
}

#[test]
fn a_bind_that_fails_verification_poisons_the_connection() {
    let case = Case::new();
    let mut connection = Connection::default();
    let mut forged = case.host.bind(&case.session_id, false);
    forged.session_id[0] ^= 1;
    assert_eq!(connection.bind(&forged), Err(BindRefusal::BadSignature));
    assert_eq!(
        connection.bind(&case.host.bind(&case.session_id, false)),
        Err(BindRefusal::Poisoned)
    );
    let data = case.hostbound().to_bytes();
    assert_eq!(case.refusal(&connection, data), Some(Refusal::BindFailed));

    let mut connection = Connection::default();
    let long = session_id(129);
    assert_eq!(
        connection.bind(&case.host.bind(&long, false)),
        Err(BindRefusal::BadSignature)
    );
}

#[test]
fn forwarded_connections_are_refused_even_after_a_later_authentication_bind() {
    let case = Case::new();
    let mut connection = Connection::default();
    let outer = session_id(32);
    assert_eq!(
        connection.bind(&case.host.bind(&outer, true)),
        Err(BindRefusal::Forwarded)
    );
    assert_eq!(
        connection.bind(&case.host.bind(&case.session_id, false)),
        Err(BindRefusal::Forwarded)
    );
    let data = case.hostbound().to_bytes();
    assert_eq!(case.refusal(&connection, data), Some(Refusal::Forwarded));
}

#[test]
fn a_second_bind_on_an_authentication_connection_poisons_it() {
    let case = Case::new();
    let mut connection = case.bound();
    let other = session_id(32);
    assert_eq!(
        connection.bind(&case.host.bind(&other, false)),
        Err(BindRefusal::AlreadyBound)
    );
    let data = Auth::hostbound(&other, "git", &case.user, &case.host).to_bytes();
    assert_eq!(case.refusal(&connection, data), Some(Refusal::BindFailed));
}

#[test]
fn host_keys_outside_the_binding_are_refused_and_reported() {
    let case = Case::new();
    let stranger = HostKey::generate();
    let mut connection = Connection::default();
    connection
        .bind(&stranger.bind(&case.session_id, false))
        .unwrap();
    let data = Auth::hostbound(&case.session_id, "git", &case.user, &stranger).to_bytes();
    let decision = case.decide(&connection, data);
    assert_eq!(decision.refusal, Some(Refusal::HostKeyNotBound));
    assert_eq!(
        decision.host_key.unwrap().to_string(),
        stranger.fingerprint()
    );
}

#[test]
fn a_hostbound_host_key_that_differs_from_the_bind_is_refused() {
    let case = Case::new();
    let connection = case.bound();
    let mut auth = case.hostbound();
    auth.host_key_blob = Some(encode(&HostKey::generate().public()));
    assert_eq!(
        case.refusal(&connection, auth.to_bytes()),
        Some(Refusal::HostKeyMismatch)
    );
}

#[test]
fn users_outside_the_allow_list_are_refused() {
    let case = Case::new();
    let connection = case.bound();
    let data = Auth::hostbound(&case.session_id, "root", &case.user, &case.host).to_bytes();
    let decision = case.decide(&connection, data);
    assert_eq!(decision.refusal, Some(Refusal::UserNotAllowed));
    assert_eq!(decision.user.as_deref(), Some("root"));
}

#[test]
fn a_session_id_other_than_the_bound_one_is_refused() {
    let case = Case::new();
    let connection = case.bound();
    let other = session_id(32);
    let data = Auth::hostbound(&other, "git", &case.user, &case.host).to_bytes();
    assert_eq!(
        case.refusal(&connection, data),
        Some(Refusal::SessionMismatch)
    );
}

#[test]
fn data_that_is_not_exactly_a_user_authentication_request_is_refused() {
    let case = Case::new();
    let connection = case.bound();
    let mut sshsig = b"SSHSIG".to_vec();
    sshsig.extend(encode(&"git"));
    let mut trailing = case.hostbound().to_bytes();
    trailing.push(0);
    let mut truncated = case.hostbound().to_bytes();
    truncated.pop();
    let mut wrong_service = case.hostbound();
    wrong_service.service = "ssh-userauth";
    let mut wrong_method = case.hostbound();
    wrong_method.method = "hostbased";
    let mut no_host_key = case.hostbound();
    no_host_key.host_key_blob = None;
    let mut empty_user = case.hostbound();
    empty_user.user = "";
    for (name, data) in [
        ("SSHSIG", sshsig),
        ("arbitrary bytes", b"sign me".to_vec()),
        ("empty", Vec::new()),
        ("trailing byte", trailing),
        ("truncated", truncated),
        ("service", wrong_service.to_bytes()),
        ("method", wrong_method.to_bytes()),
        ("hostbound without host key", no_host_key.to_bytes()),
        ("empty user", empty_user.to_bytes()),
    ] {
        assert_eq!(
            case.refusal(&connection, data),
            Some(Refusal::NotUserAuth),
            "{name}"
        );
    }
}

#[test]
fn a_request_naming_another_key_or_algorithm_is_refused() {
    let case = Case::new();
    let connection = case.bound();
    let mut other_key = case.hostbound();
    other_key.key_blob = UserKey::generate().blob();
    let mut other_algorithm = case.hostbound();
    other_algorithm.algorithm = "rsa-sha2-512";
    for data in [other_key.to_bytes(), other_algorithm.to_bytes()] {
        assert_eq!(case.refusal(&connection, data), Some(Refusal::KeyMismatch));
    }
}

#[test]
fn unknown_keys_and_signature_flags_are_refused() {
    let case = Case::new();
    let connection = case.bound();
    let stranger = UserKey::generate();
    let data = case.hostbound().to_bytes();
    let decision = connection.decide(&case.keys, &sign_request(&stranger, data.clone()));
    assert_eq!(decision.refusal, Some(Refusal::UnknownKey));
    assert_eq!(decision.key, None);
    let mut flagged = sign_request(&case.user, data);
    flagged.flags = 4;
    assert_eq!(
        connection.decide(&case.keys, &flagged).refusal,
        Some(Refusal::UnsupportedFlags)
    );
}

#[test]
fn ssh_key_rules_are_validated() {
    let spec = |host_keys: &[&str], users: &[&str]| SshKeySpec {
        name: "github".into(),
        secret: "ssh-github".into(),
        host_keys: host_keys.iter().map(|s| s.to_string()).collect(),
        users: users.iter().map(|s| s.to_string()).collect(),
    };
    let github = "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU";
    assert!(SshRule::from_spec(spec(&[github], &["git"])).is_ok());
    assert!(matches!(
        SshRule::from_spec(spec(&[], &["git"])),
        Err(SshRuleError::NoHostKeys(_))
    ));
    assert!(matches!(
        SshRule::from_spec(spec(&[github], &[])),
        Err(SshRuleError::NoUsers(_))
    ));
    for bad in [
        "MD5:16:27:ac:a5:76:28:2d:36:63:1b:56:4d:eb:df:a6:48",
        "github.com",
        "SHA256:",
    ] {
        assert!(
            matches!(
                SshRule::from_spec(spec(&[github, bad], &["git"])),
                Err(SshRuleError::InvalidHostKey { value, .. }) if value == bad
            ),
            "{bad}"
        );
    }
    assert!(matches!(
        SshRule::from_spec(spec(&[github], &["git\nroot"])),
        Err(SshRuleError::InvalidUser { .. })
    ));
    let twice = [spec(&[github], &["git"]), spec(&[github], &["git"])];
    assert!(matches!(
        SshRule::from_specs(&twice),
        Err(SshRuleError::DuplicateName(_))
    ));
    let mut other = spec(&[github], &["git"]);
    other.name = "gitlab".into();
    assert!(matches!(
        SshRule::from_specs(&[spec(&[github], &["git"]), other]),
        Err(SshRuleError::SharedSecret { .. })
    ));
}
