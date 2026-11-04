use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use secrecy::SecretString;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use zeroize::{Zeroize, Zeroizing};

const CALLBACK_PATH: &str = "/oauth/callback";
const HEAD_LIMIT: usize = 8 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CONNECTIONS: usize = 16;
const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);

const DONE_PAGE: &str = "<!doctype html><title>credshim</title><p>credshim: the AWS SSO login is complete. You can close this tab and return to the terminal.</p>";
const DENIED_PAGE: &str = "<!doctype html><title>credshim</title><p>credshim: the AWS SSO login was not allowed. Return to the terminal.</p>";
const OTHER_PAGE: &str = "<!doctype html><title>credshim</title><p>credshim: this is not the login credshim is waiting for, so it was ignored.</p>";
const NOT_FOUND_PAGE: &str = "<!doctype html><title>credshim</title><p>Not found.</p>";

pub(crate) enum Outcome {
    Code(SecretString),
    Denied(String),
}

enum Parsed {
    NotCallback,
    OtherLogin,
    Code(SecretString),
    Denied(String),
}

pub(crate) struct Callback {
    listener: TcpListener,
    port: u16,
}

impl Callback {
    pub async fn bind() -> std::io::Result<Self> {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
        let port = listener.local_addr()?.port();
        Ok(Self { listener, port })
    }

    pub fn redirect_uri(&self) -> String {
        format!("http://127.0.0.1:{}{CALLBACK_PATH}", self.port)
    }

    pub async fn wait(self, state: &str) -> Outcome {
        let state: Arc<str> = Arc::from(state);
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                Some(joined) = tasks.join_next(), if !tasks.is_empty() => {
                    if let Ok(Some(outcome)) = joined {
                        return outcome;
                    }
                }
                accepted = self.listener.accept() => match accepted {
                    Ok((stream, _)) if tasks.len() < MAX_CONNECTIONS => {
                        let state = state.clone();
                        tasks.spawn(async move {
                            tokio::time::timeout(REQUEST_TIMEOUT, serve(stream, &state))
                                .await
                                .ok()
                                .flatten()
                        });
                    }
                    Ok(_) => {}
                    Err(_) => tokio::time::sleep(ACCEPT_BACKOFF).await,
                },
            }
        }
    }
}

async fn serve(mut stream: TcpStream, state: &str) -> Option<Outcome> {
    let head = read_head(&mut stream).await?;
    let (status, page, outcome) = match parse(&head, state) {
        Parsed::NotCallback => ("404 Not Found", NOT_FOUND_PAGE, None),
        Parsed::OtherLogin => ("400 Bad Request", OTHER_PAGE, None),
        Parsed::Code(code) => ("200 OK", DONE_PAGE, Some(Outcome::Code(code))),
        Parsed::Denied(reason) => ("200 OK", DENIED_PAGE, Some(Outcome::Denied(reason))),
    };
    drop(head);
    let response = format!(
        "HTTP/1.1 {status}\r\ncontent-type: text/html; charset=utf-8\r\ncontent-length: {}\r\ncache-control: no-store\r\nreferrer-policy: no-referrer\r\nconnection: close\r\n\r\n{page}",
        page.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
    outcome
}

async fn read_head(stream: &mut TcpStream) -> Option<Zeroizing<Vec<u8>>> {
    let mut head = Zeroizing::new(Vec::with_capacity(HEAD_LIMIT));
    loop {
        if head.windows(4).any(|window| window == b"\r\n\r\n") {
            return Some(head);
        }
        if head.len() >= HEAD_LIMIT {
            return None;
        }
        let mut limited = (&mut *stream).take((HEAD_LIMIT - head.len()) as u64);
        if limited.read_buf(&mut *head).await.ok()? == 0 {
            return None;
        }
    }
}

fn parse(head: &[u8], state: &str) -> Parsed {
    let Some(line) = head.split(|byte| *byte == b'\r').next() else {
        return Parsed::NotCallback;
    };
    let Ok(line) = std::str::from_utf8(line) else {
        return Parsed::NotCallback;
    };
    let mut parts = line.split(' ');
    let (Some("GET"), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Parsed::NotCallback;
    };
    if !version.starts_with("HTTP/1.") {
        return Parsed::NotCallback;
    }
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    if path != CALLBACK_PATH {
        return Parsed::NotCallback;
    }
    let mut seen_state = None;
    let mut code = None;
    let mut error = None;
    for (key, value) in form_urlencoded::parse(query.as_bytes()) {
        let fresh = match key.as_ref() {
            "state" => seen_state.replace(value.into_owned()).is_none(),
            "error" => error.replace(value.into_owned()).is_none(),
            "code" => {
                let mut value = value.into_owned();
                let fresh = code.replace(SecretString::from(value.as_str())).is_none();
                value.zeroize();
                fresh
            }
            _ => true,
        };
        if !fresh {
            return Parsed::OtherLogin;
        }
    }
    if seen_state.as_deref() != Some(state) {
        return Parsed::OtherLogin;
    }
    match (code, error) {
        (Some(code), None) => Parsed::Code(code),
        (None, Some(error)) => Parsed::Denied(error_code(&error)),
        _ => Parsed::OtherLogin,
    }
}

fn error_code(error: &str) -> String {
    if !error.is_empty()
        && error.len() <= 64
        && error
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
    {
        error.to_string()
    } else {
        "unknown".to_string()
    }
}
