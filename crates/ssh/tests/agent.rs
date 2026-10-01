mod common;

use std::sync::Arc;

use common::{Auth, Client, HostKey, UserKey, encode, rule, session_id, sign_request};
use credshim_ssh::ssh_agent_lib::proto::{
    AddIdentity, Extension, PrivateCredential, Request, Response,
};
use credshim_ssh::{Agent, MAX_MESSAGE_LEN, SigningKey};
use signature::Verifier;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Setup {
    dir: TempDir,
    host: HostKey,
    user: UserKey,
    _agent: tokio::task::JoinHandle<()>,
}

impl Setup {
    fn new() -> Self {
        let dir = tempfile::Builder::new().prefix("cs").tempdir().unwrap();
        let host = HostKey::generate();
        let user = UserKey::generate();
        let signer = SigningKey::from_secret(&user.secret).unwrap();
        let agent = Arc::new(Agent::new(vec![(
            rule("agent", &[host.fingerprint()], &["git"]),
            signer,
        )]))
        .bind(&dir.path().join("agent.sock"))
        .unwrap();
        Self {
            dir,
            host,
            user,
            _agent: agent,
        }
    }

    async fn client(&self) -> Client {
        Client::connect(&self.dir.path().join("agent.sock")).await
    }
}

#[tokio::test]
async fn a_bound_connection_gets_a_signature_that_verifies_with_the_listed_key() {
    let setup = Setup::new();
    let mut client = setup.client().await;
    let Response::IdentitiesAnswer(identities) = client.send(Request::RequestIdentities).await
    else {
        panic!("expected identities");
    };
    assert_eq!(identities.len(), 1);
    assert_eq!(identities[0].comment, "credshim:agent");
    let id = session_id(64);
    assert_eq!(
        client.bind(setup.host.bind(&id, false)).await,
        Response::Success
    );
    let data = Auth::hostbound(&id, "git", &setup.user, &setup.host).to_bytes();
    let Response::SignResponse(signature) = client
        .send(Request::SignRequest(sign_request(
            &setup.user,
            data.clone(),
        )))
        .await
    else {
        panic!("expected a signature");
    };
    setup.user.public().verify(&data, &signature).unwrap();
}

#[tokio::test]
async fn hostbound_requests_naming_another_host_key_get_no_signature() {
    let setup = Setup::new();
    let mut client = setup.client().await;
    let id = session_id(32);
    client.bind(setup.host.bind(&id, false)).await;
    let mut auth = Auth::hostbound(&id, "git", &setup.user, &setup.host);
    auth.host_key_blob = Some(encode(&HostKey::generate().public()));
    let response = client
        .send(Request::SignRequest(sign_request(
            &setup.user,
            auth.to_bytes(),
        )))
        .await;
    assert_eq!(response, Response::Failure);
}

#[tokio::test]
async fn binds_that_fail_verification_are_refused_on_the_wire() {
    let setup = Setup::new();
    let mut client = setup.client().await;
    let id = session_id(32);
    let mut forged = setup.host.bind(&id, false);
    forged.session_id[0] ^= 1;
    assert_eq!(client.bind(forged).await, Response::Failure);
    assert_eq!(
        client.bind(setup.host.bind(&id, false)).await,
        Response::Failure
    );
    let data = Auth::hostbound(&id, "git", &setup.user, &setup.host).to_bytes();
    let response = client
        .send(Request::SignRequest(sign_request(&setup.user, data)))
        .await;
    assert_eq!(response, Response::Failure);
}

#[tokio::test]
async fn an_undecodable_bind_poisons_the_connection() {
    let setup = Setup::new();
    let mut client = setup.client().await;
    let id = session_id(32);
    let valid = Extension::new_message(setup.host.bind(&id, true)).unwrap();
    let mut truncated = encode(&Request::Extension(valid));
    truncated.truncate(truncated.len() - 8);
    assert_eq!(client.raw(&truncated).await, Some(Response::Failure));
    assert_eq!(
        client.bind(setup.host.bind(&id, false)).await,
        Response::Failure
    );
    let data = Auth::hostbound(&id, "git", &setup.user, &setup.host).to_bytes();
    let response = client
        .send(Request::SignRequest(sign_request(&setup.user, data)))
        .await;
    assert_eq!(response, Response::Failure);
}

#[tokio::test]
async fn write_requests_fail_and_leave_the_keys_unchanged() {
    let setup = Setup::new();
    let mut client = setup.client().await;
    let (secret, _) = SigningKey::generate("extra").unwrap();
    let extra = credshim_ssh::ssh_key::PrivateKey::from_openssh(
        secrecy::ExposeSecret::expose_secret(&secret),
    )
    .unwrap();
    let add = Request::AddIdentity(AddIdentity {
        credential: PrivateCredential::Key {
            privkey: extra.key_data().clone(),
            comment: "extra".into(),
        },
    });
    for request in [
        add,
        Request::RemoveAllIdentities,
        Request::Lock("pw".into()),
        Request::Unlock("pw".into()),
        Request::Extension(Extension {
            name: "query".into(),
            details: Vec::new().into(),
        }),
    ] {
        assert_eq!(client.send(request).await, Response::Failure);
    }
    let Response::IdentitiesAnswer(identities) = client.send(Request::RequestIdentities).await
    else {
        panic!("expected identities");
    };
    assert_eq!(identities.len(), 1);
}

#[tokio::test]
async fn undecodable_messages_fail_without_closing_the_connection() {
    let setup = Setup::new();
    let mut client = setup.client().await;
    for body in [vec![200u8], vec![13u8, 0, 0], vec![27u8, 0, 0, 0, 99]] {
        assert_eq!(client.raw(&body).await, Some(Response::Failure));
    }
    assert!(matches!(
        client.send(Request::RequestIdentities).await,
        Response::IdentitiesAnswer(_)
    ));
}

#[tokio::test]
async fn oversized_frames_close_the_connection_without_buffering() {
    let setup = Setup::new();
    let mut client = setup.client().await;
    let stream = client.stream();
    stream.write_u32(MAX_MESSAGE_LEN as u32 + 1).await.unwrap();
    let mut rest = Vec::new();
    let read = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_to_end(&mut rest),
    )
    .await
    .expect("the agent closes the connection");
    assert_eq!(read.unwrap(), 0);
}

#[test]
fn debug_output_never_contains_secret_values() {
    let user = UserKey::generate();
    let host = HostKey::generate();
    let signer = SigningKey::from_secret(&user.secret).unwrap();
    let agent = Agent::new(vec![(
        rule("debug", &[host.fingerprint()], &["git"]),
        SigningKey::from_secret(&user.secret).unwrap(),
    )]);
    let rendered = format!("{signer:?} {agent:?} {:?}", user.secret);
    for line in secrecy::ExposeSecret::expose_secret(&user.secret)
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .skip(1)
    {
        assert!(!rendered.contains(line), "{rendered}");
    }
}

#[tokio::test]
async fn connections_beyond_the_cap_are_closed_and_slots_are_reused() {
    let setup = Setup::new();
    let mut held = Vec::new();
    for _ in 0..credshim_ssh::MAX_CONNECTIONS {
        let mut client = setup.client().await;
        assert!(matches!(
            client.send(Request::RequestIdentities).await,
            Response::IdentitiesAnswer(_)
        ));
        held.push(client);
    }
    let mut refused = setup.client().await;
    assert_eq!(
        refused.raw(&encode(&Request::RequestIdentities)).await,
        None
    );
    held.pop();
    let mut reply = None;
    for _ in 0..50 {
        let mut client = setup.client().await;
        reply = client.raw(&encode(&Request::RequestIdentities)).await;
        if reply.is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(matches!(reply, Some(Response::IdentitiesAnswer(_))));
}

fn limited_setup(limits: credshim_core::Limits) -> Setup {
    let dir = tempfile::Builder::new().prefix("cs").tempdir().unwrap();
    let host = HostKey::generate();
    let user = UserKey::generate();
    let signer = SigningKey::from_secret(&user.secret).unwrap();
    let rule = credshim_ssh::SshRule::from_spec(credshim_ssh::SshKeySpec {
        name: "agent".into(),
        secret: "ssh-agent".into(),
        host_keys: vec![host.fingerprint()],
        users: vec!["git".into()],
        limits,
    })
    .unwrap();
    let agent = Arc::new(Agent::new(vec![(rule, signer)]))
        .bind(&dir.path().join("agent.sock"))
        .unwrap();
    Setup {
        dir,
        host,
        user,
        _agent: agent,
    }
}

async fn sign_once(setup: &Setup) -> Response {
    let mut client = setup.client().await;
    let id = session_id(32);
    assert_eq!(
        client.bind(setup.host.bind(&id, false)).await,
        Response::Success
    );
    let data = Auth::hostbound(&id, "git", &setup.user, &setup.host).to_bytes();
    client
        .send(Request::SignRequest(sign_request(&setup.user, data)))
        .await
}

#[tokio::test]
async fn signatures_beyond_a_rule_limit_are_refused_and_audited() {
    let logs = credshim_testkit::capture_logs();
    let setup = limited_setup(credshim_core::Limits {
        per_minute: Some(2),
        ..Default::default()
    });
    for _ in 0..2 {
        assert!(matches!(sign_once(&setup).await, Response::SignResponse(_)));
    }
    assert_eq!(sign_once(&setup).await, Response::Failure);
    let contents = logs.contents();
    assert!(
        contents.contains("decision=\"deny\" reason=\"limited\""),
        "{contents}"
    );
}

#[test]
fn concurrent_and_zero_limits_are_rejected_for_ssh_keys() {
    let spec = |limits| credshim_ssh::SshKeySpec {
        name: "agent".into(),
        secret: "ssh-agent".into(),
        host_keys: vec!["SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU".into()],
        users: vec!["git".into()],
        limits,
    };
    assert!(matches!(
        credshim_ssh::SshRule::from_spec(spec(credshim_core::Limits {
            concurrent: Some(1),
            ..Default::default()
        })),
        Err(credshim_ssh::SshRuleError::ConcurrentLimit(_))
    ));
    assert!(matches!(
        credshim_ssh::SshRule::from_spec(spec(credshim_core::Limits {
            per_day: Some(0),
            ..Default::default()
        })),
        Err(credshim_ssh::SshRuleError::ZeroLimit(_))
    ));
}

#[tokio::test]
async fn connections_from_uids_outside_the_client_list_are_closed() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::Builder::new().prefix("cs").tempdir().unwrap();
    let user = UserKey::generate();
    let own = rustix::process::geteuid().as_raw();
    let path = dir.path().join("agent.sock");
    let _agent = Arc::new(
        Agent::new(vec![(
            rule("agent", &[HostKey::generate().fingerprint()], &["git"]),
            SigningKey::from_secret(&user.secret).unwrap(),
        )])
        .with_clients(vec![own.wrapping_add(1)]),
    )
    .bind(&path)
    .unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o666
    );
    let mut client = Client::connect(&path).await;
    assert_eq!(client.raw(&encode(&Request::RequestIdentities)).await, None);
}
