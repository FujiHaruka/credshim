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

use token_exchange::Gate;

pub const DEFAULT_MAX_BODY: usize = 64 * 1024;
pub const DEFAULT_REPLAY_WINDOW: Duration = Duration::from_secs(30);

pub struct OAuth {
    providers: Vec<Provider>,
    vault: Vault,
    max_body: usize,
    replay_window: Duration,
    gates: Mutex<HashMap<String, Gate>>,
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
        let path = parts.uri.path();
        self.providers.iter().find_map(|provider| {
            let kind = if provider.token.is(host, port, path) {
                EndpointKind::Token
            } else if provider
                .revoke
                .as_ref()
                .is_some_and(|revoke| revoke.is(host, port, path))
            {
                EndpointKind::Revoke
            } else {
                return None;
            };
            Some(Exchange::new(self, provider, kind, parts))
        })
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

    fn gate(&self, dummy: &str) -> Gate {
        self.lock_gates()
            .entry(dummy.to_string())
            .or_default()
            .clone()
    }

    fn lock_gates(&self) -> std::sync::MutexGuard<'_, HashMap<String, Gate>> {
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
}
