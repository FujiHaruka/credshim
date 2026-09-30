use std::io;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use credshim_core::AUDIT_TARGET;
use ssh_agent_lib::proto::extension::SessionBind;
use ssh_agent_lib::proto::{Identity, PublicCredential, Request, Response, SignRequest};
use ssh_agent_lib::ssh_encoding::{Decode, Encode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

use crate::key::SigningKey;
use crate::policy::{AgentKey, Connection, Decision};
use crate::rule::SshRule;

pub const MAX_MESSAGE_LEN: usize = 256 * 1024;
pub const MAX_CONNECTIONS: usize = 64;
pub const FRAME_TIMEOUT: Duration = Duration::from_secs(10);
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(100);

#[derive(Debug)]
pub struct Agent {
    keys: Vec<AgentKey>,
    signers: Vec<SigningKey>,
}

impl Agent {
    pub fn new(entries: Vec<(SshRule, SigningKey)>) -> Self {
        let (keys, signers) = entries
            .into_iter()
            .map(|(rule, signer)| {
                let public = signer.public().clone();
                (AgentKey { rule, public }, signer)
            })
            .unzip();
        Self { keys, signers }
    }

    pub fn bind(self: Arc<Self>, path: &Path) -> io::Result<JoinHandle<()>> {
        remove_stale_socket(path)?;
        let listener = UnixListener::bind(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        tracing::info!(socket = %path.display(), keys = self.keys.len(), "ssh agent listening");
        Ok(tokio::spawn(self.serve(listener)))
    }

    pub async fn serve(self: Arc<Self>, listener: UnixListener) {
        let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                tokio::time::sleep(ACCEPT_RETRY_DELAY).await;
                continue;
            };
            let Ok(slot) = slots.clone().try_acquire_owned() else {
                tracing::warn!("ssh agent connection refused: {MAX_CONNECTIONS} already open");
                continue;
            };
            let agent = self.clone();
            tokio::spawn(async move {
                agent.handle(stream).await;
                drop(slot);
            });
        }
    }

    async fn handle(self: Arc<Self>, mut stream: UnixStream) {
        let mut connection = Connection::default();
        loop {
            let Ok(len) = stream.read_u32().await else {
                return;
            };
            let len = len as usize;
            if len == 0 || len > MAX_MESSAGE_LEN {
                return;
            }
            let mut body = Vec::new();
            let read = tokio::time::timeout(
                FRAME_TIMEOUT,
                (&mut stream).take(len as u64).read_to_end(&mut body),
            )
            .await;
            if !matches!(read, Ok(Ok(n)) if n == len) {
                return;
            }
            let response = self.respond(&mut connection, &body);
            let Some(frame) = frame(&response) else {
                return;
            };
            if stream.write_all(&frame).await.is_err() {
                return;
            }
        }
    }

    fn respond(&self, connection: &mut Connection, body: &[u8]) -> Response {
        let Ok(request) = Request::decode(&mut &body[..]) else {
            return Response::Failure;
        };
        match request {
            Request::RequestIdentities => Response::IdentitiesAnswer(self.identities()),
            Request::SignRequest(request) => self.sign(connection, &request),
            Request::Extension(extension) => match extension.parse_message::<SessionBind>() {
                Ok(Some(bind)) => match connection.bind(&bind) {
                    Ok(()) => Response::Success,
                    Err(refusal) => {
                        tracing::info!(%refusal, "refused an ssh session bind");
                        Response::Failure
                    }
                },
                _ => Response::Failure,
            },
            _ => Response::Failure,
        }
    }

    fn identities(&self) -> Vec<Identity> {
        self.keys
            .iter()
            .map(|key| Identity {
                credential: PublicCredential::Key(key.public.clone()),
                comment: format!("credshim:{}", key.rule.name()),
            })
            .collect()
    }

    fn sign(&self, connection: &Connection, request: &SignRequest) -> Response {
        let decision = connection.decide(&self.keys, request);
        let (response, outcome) = match decision.approved() {
            Some(index) => match self.signers[index].sign(&request.data) {
                Ok(signature) => (Response::SignResponse(signature), "sign"),
                Err(_) => (Response::Failure, "error"),
            },
            None => (Response::Failure, "deny"),
        };
        self.audit(&decision, outcome);
        response
    }

    fn audit(&self, decision: &Decision, outcome: &'static str) {
        let rule = decision
            .key
            .map_or("", |index| self.keys[index].rule.name());
        let host_key = decision
            .host_key
            .map(|fingerprint| fingerprint.to_string())
            .unwrap_or_default();
        tracing::info!(
            target: AUDIT_TARGET,
            ingress = "ssh_agent",
            rules = rule,
            host_key = host_key.as_str(),
            user = decision.user.as_deref().unwrap_or(""),
            decision = outcome,
            reason = decision.refusal.map_or("", |refusal| refusal.as_str()),
            "ssh sign"
        );
    }
}

fn frame(response: &Response) -> Option<Vec<u8>> {
    let len = u32::try_from(response.encoded_len().ok()?).ok()?;
    let mut out = Vec::with_capacity(4 + len as usize);
    len.encode(&mut out).ok()?;
    response.encode(&mut out).ok()?;
    Some(out)
}

fn remove_stale_socket(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(existing) if existing.file_type().is_socket() => std::fs::remove_file(path),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("{} exists and is not a socket", path.display()),
        )),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}
