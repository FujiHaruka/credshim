#![allow(dead_code)]

use credshim_ssh::ssh_agent_lib::proto::extension::SessionBind;
use credshim_ssh::ssh_agent_lib::proto::{
    Extension, PublicCredential, Request, Response, SignRequest,
};
use credshim_ssh::ssh_agent_lib::ssh_encoding::{Decode, Encode};
use credshim_ssh::ssh_key::private::{Ed25519Keypair, KeypairData};
use credshim_ssh::ssh_key::public::KeyData;
use credshim_ssh::ssh_key::{HashAlg, PrivateKey};
use credshim_ssh::{AgentKey, SigningKey, SshKeySpec, SshRule};
use secrecy::SecretString;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

pub struct HostKey(PrivateKey);

impl HostKey {
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        Self(
            PrivateKey::new(
                KeypairData::Ed25519(Ed25519Keypair::from_seed(&seed)),
                "host",
            )
            .unwrap(),
        )
    }

    pub fn public(&self) -> KeyData {
        self.0.public_key().key_data().clone()
    }

    pub fn fingerprint(&self) -> String {
        self.0.fingerprint(HashAlg::Sha256).to_string()
    }

    pub fn bind(&self, session_id: &[u8], is_forwarding: bool) -> SessionBind {
        use signature::Signer;
        SessionBind {
            host_key: self.public(),
            session_id: session_id.to_vec(),
            signature: self.0.try_sign(session_id).unwrap(),
            is_forwarding,
        }
    }
}

pub struct UserKey {
    pub secret: SecretString,
    pub signer: SigningKey,
}

impl UserKey {
    pub fn generate() -> Self {
        let (secret, _) = SigningKey::generate("user").unwrap();
        let signer = SigningKey::from_secret(&secret).unwrap();
        Self { secret, signer }
    }

    pub fn public(&self) -> KeyData {
        self.signer.public().clone()
    }

    pub fn blob(&self) -> Vec<u8> {
        encode(&self.public())
    }
}

pub fn rule(name: &str, host_keys: &[String], users: &[&str]) -> SshRule {
    SshRule::from_spec(SshKeySpec {
        name: name.to_string(),
        secret: format!("ssh-{name}"),
        host_keys: host_keys.to_vec(),
        users: users.iter().map(|user| user.to_string()).collect(),
    })
    .unwrap()
}

pub fn agent_key(rule: SshRule, user: &UserKey) -> AgentKey {
    AgentKey {
        rule,
        public: user.public(),
    }
}

pub fn encode(value: &impl Encode) -> Vec<u8> {
    let mut out = Vec::new();
    value.encode(&mut out).unwrap();
    out
}

pub struct Auth<'a> {
    pub session_id: &'a [u8],
    pub user: &'a str,
    pub service: &'a str,
    pub method: &'a str,
    pub algorithm: &'a str,
    pub key_blob: Vec<u8>,
    pub host_key_blob: Option<Vec<u8>>,
}

impl<'a> Auth<'a> {
    pub fn hostbound(session_id: &'a [u8], user: &'a str, key: &UserKey, host: &HostKey) -> Self {
        Self {
            session_id,
            user,
            service: "ssh-connection",
            method: "publickey-hostbound-v00@openssh.com",
            algorithm: "ssh-ed25519",
            key_blob: key.blob(),
            host_key_blob: Some(encode(&host.public())),
        }
    }

    pub fn plain(session_id: &'a [u8], user: &'a str, key: &UserKey) -> Self {
        Self {
            method: "publickey",
            host_key_blob: None,
            ..Self::hostbound(session_id, user, key, &HostKey::generate())
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.session_id.encode(&mut out).unwrap();
        50u8.encode(&mut out).unwrap();
        self.user.encode(&mut out).unwrap();
        self.service.encode(&mut out).unwrap();
        self.method.encode(&mut out).unwrap();
        1u8.encode(&mut out).unwrap();
        self.algorithm.encode(&mut out).unwrap();
        self.key_blob.encode(&mut out).unwrap();
        if let Some(blob) = &self.host_key_blob {
            blob.encode(&mut out).unwrap();
        }
        out
    }
}

pub fn sign_request(key: &UserKey, data: Vec<u8>) -> SignRequest {
    SignRequest {
        credential: PublicCredential::Key(key.public()),
        data,
        flags: 0,
    }
}

pub fn session_id(len: usize) -> Vec<u8> {
    let mut id = vec![0u8; len];
    getrandom::fill(&mut id).unwrap();
    id
}

pub struct Client(UnixStream);

impl Client {
    pub async fn connect(path: &std::path::Path) -> Self {
        Self(UnixStream::connect(path).await.unwrap())
    }

    pub async fn raw(&mut self, body: &[u8]) -> Option<Response> {
        self.0.write_u32(body.len() as u32).await.ok()?;
        self.0.write_all(body).await.ok()?;
        let len = self.0.read_u32().await.ok()?;
        let mut reply = vec![0; len as usize];
        self.0.read_exact(&mut reply).await.ok()?;
        Some(Response::decode(&mut &reply[..]).unwrap())
    }

    pub async fn send(&mut self, request: Request) -> Response {
        self.raw(&encode(&request)).await.expect("agent reply")
    }

    pub async fn bind(&mut self, bind: SessionBind) -> Response {
        self.send(Request::Extension(Extension::new_message(bind).unwrap()))
            .await
    }

    pub fn stream(&mut self) -> &mut UnixStream {
        &mut self.0
    }
}
