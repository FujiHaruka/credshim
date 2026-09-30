use ssh_agent_lib::proto::extension::SessionBind;
use ssh_agent_lib::proto::{PublicCredential, SignRequest};
use ssh_agent_lib::ssh_encoding::{Decode, Encode};
use ssh_key::public::KeyData;
use ssh_key::{Fingerprint, HashAlg};

use crate::rule::{SshRule, is_plain_name};

pub const MAX_SESSION_ID_LEN: usize = 128;
pub const UNPRINTABLE_USER: &str = "<invalid>";
const SSH_MSG_USERAUTH_REQUEST: u8 = 50;
const SERVICE: &str = "ssh-connection";
const PUBLICKEY: &str = "publickey";
const PUBLICKEY_HOSTBOUND: &str = "publickey-hostbound-v00@openssh.com";

#[derive(Debug, Default)]
pub struct Connection {
    state: State,
}

#[derive(Debug, Default)]
enum State {
    #[default]
    Unbound,
    Bound {
        host_key: KeyData,
        session_id: Vec<u8>,
    },
    Forwarded,
    Poisoned,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BindRefusal {
    #[error("the host signature over the session ID does not verify")]
    BadSignature,
    #[error("the connection is forwarded")]
    Forwarded,
    #[error("the connection is already bound")]
    AlreadyBound,
    #[error("an earlier bind on this connection failed")]
    Poisoned,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    UnknownKey,
    NoSessionBind,
    BindFailed,
    Forwarded,
    HostKeyNotBound,
    NotUserAuth,
    SessionMismatch,
    UserNotAllowed,
    HostKeyMismatch,
    KeyMismatch,
    UnsupportedFlags,
}

impl Refusal {
    pub fn as_str(self) -> &'static str {
        match self {
            Refusal::UnknownKey => "unknown_key",
            Refusal::NoSessionBind => "no_session_bind",
            Refusal::BindFailed => "bind_failed",
            Refusal::Forwarded => "forwarded",
            Refusal::HostKeyNotBound => "host_key_not_bound",
            Refusal::NotUserAuth => "not_user_auth",
            Refusal::SessionMismatch => "session_mismatch",
            Refusal::UserNotAllowed => "user_not_allowed",
            Refusal::HostKeyMismatch => "hostbound_key_mismatch",
            Refusal::KeyMismatch => "key_mismatch",
            Refusal::UnsupportedFlags => "unsupported_flags",
        }
    }
}

#[derive(Clone, Debug)]
pub struct AgentKey {
    pub rule: SshRule,
    pub public: KeyData,
}

#[derive(Debug)]
pub struct Decision {
    pub key: Option<usize>,
    pub host_key: Option<Fingerprint>,
    pub user: Option<String>,
    pub refusal: Option<Refusal>,
}

impl Decision {
    pub fn approved(&self) -> Option<usize> {
        self.key.filter(|_| self.refusal.is_none())
    }
}

impl Connection {
    pub fn bind(&mut self, bind: &SessionBind) -> Result<(), BindRefusal> {
        let (next, result) = match std::mem::take(&mut self.state) {
            State::Unbound => {
                if bind.session_id.len() > MAX_SESSION_ID_LEN || bind.verify_signature().is_err() {
                    (State::Poisoned, Err(BindRefusal::BadSignature))
                } else if bind.is_forwarding {
                    (State::Forwarded, Err(BindRefusal::Forwarded))
                } else {
                    (
                        State::Bound {
                            host_key: bind.host_key.clone(),
                            session_id: bind.session_id.clone(),
                        },
                        Ok(()),
                    )
                }
            }
            State::Bound { .. } => (State::Poisoned, Err(BindRefusal::AlreadyBound)),
            State::Forwarded => (State::Forwarded, Err(BindRefusal::Forwarded)),
            State::Poisoned => (State::Poisoned, Err(BindRefusal::Poisoned)),
        };
        self.state = next;
        result
    }

    pub fn decide(&self, keys: &[AgentKey], request: &SignRequest) -> Decision {
        let key = match &request.credential {
            PublicCredential::Key(key) => keys.iter().position(|k| &k.public == key),
            PublicCredential::Cert(_) => None,
        };
        let mut decision = Decision {
            key,
            host_key: None,
            user: None,
            refusal: None,
        };
        let refuse = |mut decision: Decision, refusal| {
            decision.refusal = Some(refusal);
            decision
        };
        let Some(index) = key else {
            return refuse(decision, Refusal::UnknownKey);
        };
        let agent_key = &keys[index];
        let (host_key, session_id) = match &self.state {
            State::Unbound => return refuse(decision, Refusal::NoSessionBind),
            State::Poisoned => return refuse(decision, Refusal::BindFailed),
            State::Forwarded => return refuse(decision, Refusal::Forwarded),
            State::Bound {
                host_key,
                session_id,
            } => (host_key, session_id),
        };
        let fingerprint = host_key.fingerprint(HashAlg::Sha256);
        decision.host_key = Some(fingerprint);
        if !agent_key.rule.binds_host_key(&fingerprint) {
            return refuse(decision, Refusal::HostKeyNotBound);
        }
        let Some(auth) = UserAuth::parse(&request.data) else {
            return refuse(decision, Refusal::NotUserAuth);
        };
        decision.user = Some(if is_plain_name(&auth.user) {
            auth.user.clone()
        } else {
            UNPRINTABLE_USER.to_string()
        });
        if &auth.session_id != session_id {
            return refuse(decision, Refusal::SessionMismatch);
        }
        if !agent_key.rule.allows_user(&auth.user) {
            return refuse(decision, Refusal::UserNotAllowed);
        }
        if auth.algorithm != agent_key.public.algorithm().as_str()
            || Some(auth.key_blob) != encoded(&agent_key.public)
        {
            return refuse(decision, Refusal::KeyMismatch);
        }
        if let Some(blob) = auth.host_key_blob
            && Some(blob) != encoded(host_key)
        {
            return refuse(decision, Refusal::HostKeyMismatch);
        }
        if request.flags != 0 {
            return refuse(decision, Refusal::UnsupportedFlags);
        }
        decision
    }
}

struct UserAuth {
    session_id: Vec<u8>,
    user: String,
    algorithm: String,
    key_blob: Vec<u8>,
    host_key_blob: Option<Vec<u8>>,
}

impl UserAuth {
    fn parse(mut data: &[u8]) -> Option<Self> {
        let reader = &mut data;
        let session_id = Vec::<u8>::decode(reader).ok()?;
        if u8::decode(reader).ok()? != SSH_MSG_USERAUTH_REQUEST {
            return None;
        }
        let user = String::decode(reader).ok()?;
        if String::decode(reader).ok()? != SERVICE {
            return None;
        }
        let method = String::decode(reader).ok()?;
        if u8::decode(reader).ok()? != 1 {
            return None;
        }
        let algorithm = String::decode(reader).ok()?;
        let key_blob = Vec::<u8>::decode(reader).ok()?;
        let host_key_blob = match method.as_str() {
            PUBLICKEY => None,
            PUBLICKEY_HOSTBOUND => Some(Vec::<u8>::decode(reader).ok()?),
            _ => return None,
        };
        if !reader.is_empty() || user.is_empty() {
            return None;
        }
        Some(Self {
            session_id,
            user,
            algorithm,
            key_blob,
            host_key_blob,
        })
    }
}

fn encoded(key: &KeyData) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    key.encode(&mut out).ok()?;
    Some(out)
}
