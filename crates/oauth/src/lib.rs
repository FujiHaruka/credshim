mod provider;
mod token_exchange;
mod vault;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use credshim_core::{Rule, TokenResolver};
use http::request::Parts;

pub use provider::{ClientAuth, ClientSecretSpec, IdToken, Provider, ProviderError, ProviderSpec};
pub use token_exchange::{EndpointKind, Exchange, ExchangeError};
pub use vault::{EXPIRY_GRACE, Issued, TokenKind, Vault, VaultError};

use provider::RequestPath;
use token_exchange::Gate;

pub const DEFAULT_MAX_BODY: usize = 64 * 1024;
pub const DEFAULT_REPLAY_WINDOW: Duration = Duration::from_secs(30);

pub struct OAuth {
    providers: Vec<Provider>,
    vault: Vault,
    max_body: usize,
    replay_window: Duration,
    gates: Mutex<HashMap<(String, String), Gate>>,
}

impl std::fmt::Debug for OAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuth")
            .field("providers", &self.providers)
            .field("vault", &self.vault)
            .field("max_body", &self.max_body)
            .finish_non_exhaustive()
    }
}

impl OAuth {
    pub fn new(providers: Vec<Provider>, vault: Vault) -> Result<Self, ProviderError> {
        provider::check_unique(&providers)?;
        Ok(Self {
            providers,
            vault,
            max_body: DEFAULT_MAX_BODY,
            replay_window: DEFAULT_REPLAY_WINDOW,
            gates: Mutex::default(),
        })
    }

    pub fn with_max_body(mut self, max_body: usize) -> Self {
        self.max_body = max_body;
        self
    }

    pub fn with_replay_window(mut self, window: Duration) -> Self {
        self.replay_window = window;
        self
    }

    pub fn vault(&self) -> &Vault {
        &self.vault
    }

    pub fn client_secret_rules(&self) -> Result<Vec<Rule>, ProviderError> {
        self.providers
            .iter()
            .filter_map(|provider| provider.client_secret_rule().transpose())
            .collect()
    }

    pub fn hosts(&self) -> impl Iterator<Item = &str> {
        self.providers.iter().flat_map(Provider::hosts)
    }

    pub fn exchange(&self, host: &str, port: u16, parts: &Parts) -> Option<Exchange<'_>> {
        let path = RequestPath::new(parts.uri.path());
        let mut raw = None;
        let mut normalized = None;
        for provider in &self.providers {
            for (kind, endpoint) in provider.endpoint_kinds() {
                let matched = endpoint.covers(host, port, &path);
                if matched.raw && raw.is_none() {
                    raw = Some((provider, kind));
                }
                if matched.normalized && normalized.is_none() {
                    normalized = Some((provider, kind));
                }
            }
        }
        let (provider, kind) = raw.or(normalized)?;
        let disguised = match (raw, normalized) {
            (Some((a, x)), Some((b, y))) => !std::ptr::eq(a, b) || x != y,
            _ => true,
        };
        Some(Exchange::new(self, provider, kind, parts, disguised))
    }

    pub fn purge(&self, now: SystemTime) -> usize {
        self.lock_gates().retain(|_, gate| {
            Arc::strong_count(gate) > 1
                || gate.try_lock().map_or(true, |replay| {
                    replay
                        .as_ref()
                        .is_some_and(|r| r.is_fresh(self.replay_window))
                })
        });
        self.vault.purge_expired(now)
    }

    fn gate(&self, provider: &str, dummy: &str, create: bool) -> Option<Gate> {
        let key = (provider.to_string(), dummy.to_string());
        let mut gates = self.lock_gates();
        match gates.get(&key) {
            Some(gate) => Some(gate.clone()),
            None if create => Some(gates.entry(key).or_default().clone()),
            None => None,
        }
    }

    fn lock_gates(&self) -> std::sync::MutexGuard<'_, HashMap<(String, String), Gate>> {
        self.gates
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl TokenResolver for OAuth {
    fn resolve(&self, dummy: &str) -> Option<Rule> {
        let issued = self.vault.get(dummy)?;
        let provider = self
            .providers
            .iter()
            .find(|provider| provider.name() == issued.provider)?;
        let (suffix, bindings) = match issued.kind {
            TokenKind::Access => ("access", &provider.access_bindings),
            TokenKind::Refresh => ("refresh", &provider.refresh_bindings),
        };
        Some(Rule::issued(
            format!("oauth.{}.{suffix}", provider.name()),
            dummy.to_string(),
            issued.real,
            bindings.clone(),
        ))
    }

    fn generation(&self) -> u64 {
        self.vault.generation()
    }

    fn issued(&self) -> Vec<(String, secrecy::SecretString)> {
        self.vault.issued()
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use bytes::Bytes;
    use http::{Request, Response};
    use http_body_util::Full;
    use secrecy::SecretString;

    use super::*;

    fn oauth() -> OAuth {
        let spec = ProviderSpec {
            name: "a".to_string(),
            token_endpoint: "https://a.example.test/token".to_string(),
            revoke_endpoint: None,
            client_id: None,
            client_secret: None,
            client_auth: ClientAuth::default(),
            resource_hosts: Vec::new(),
            id_token: IdToken::default(),
        };
        OAuth::new(vec![Provider::new(spec, None).unwrap()], Vault::in_memory()).unwrap()
    }

    async fn refresh(oauth: &OAuth, refresh_token: &str) -> Result<(), ExchangeError> {
        let (parts, ()) = Request::post("/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(())
            .unwrap()
            .into_parts();
        let body = format!("grant_type=refresh_token&refresh_token={refresh_token}");
        oauth
            .exchange("a.example.test", 443, &parts)
            .unwrap()
            .run(parts, Full::new(Bytes::from(body)), |_| async {
                Ok::<_, Infallible>(
                    Response::builder()
                        .header("content-type", "application/json")
                        .body(Full::new(Bytes::from_static(
                            b"{\"access_token\":\"real\"}",
                        )))
                        .unwrap(),
                )
            })
            .await
            .map(drop)
    }

    #[tokio::test]
    async fn only_issued_refresh_dummies_take_a_replay_gate() {
        let oauth = oauth();
        let access =
            oauth
                .vault
                .issue("a", TokenKind::Access, &SecretString::from("real-at"), None);
        let foreign =
            oauth
                .vault
                .issue("b", TokenKind::Refresh, &SecretString::from("real-b"), None);
        for junk in ["junk-1", "junk-2", &access, &foreign] {
            let _ = refresh(&oauth, junk).await;
        }
        assert!(oauth.lock_gates().is_empty());

        let issued = oauth.vault.issue(
            "a",
            TokenKind::Refresh,
            &SecretString::from("real-rt"),
            None,
        );
        refresh(&oauth, &issued).await.unwrap();
        assert_eq!(oauth.lock_gates().len(), 1);
    }
}
