use crate::rule::{DEFAULT_PORT, RuleSpec, is_clean_path_prefix, is_unreserved, path_is_under};

#[derive(Clone, Debug, PartialEq, Eq)]
struct Route {
    rule: String,
    prefix: String,
    host: String,
    port: u16,
}

#[derive(Clone, Debug, Default)]
pub struct BaseUrls {
    routes: Vec<Route>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Resolved<'m, 'p> {
    pub rule: &'m str,
    pub host: &'m str,
    pub port: u16,
    pub path: &'p str,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BaseUrlError {
    #[error(
        "rule {rule:?}: base_url_prefix {prefix:?} must start with '/', name at least one segment, use only A-Z, a-z, 0-9, '-', '.', '_', '~' and '/', and contain no dot segments"
    )]
    InvalidPrefix { rule: String, prefix: String },
    #[error("rules {0:?} and {1:?} have base_url_prefix values where one contains the other")]
    Overlapping(String, String),
}

impl BaseUrls {
    pub fn from_specs<'s>(
        specs: impl IntoIterator<Item = &'s RuleSpec>,
    ) -> Result<Self, BaseUrlError> {
        let mut routes: Vec<Route> = Vec::new();
        for spec in specs {
            let Some(prefix) = &spec.base_url_prefix else {
                continue;
            };
            let trimmed = prefix.trim_end_matches('/');
            if trimmed.is_empty()
                || !is_clean_path_prefix(trimmed)
                || !trimmed.bytes().all(|b| b == b'/' || is_unreserved(b))
            {
                return Err(BaseUrlError::InvalidPrefix {
                    rule: spec.name.clone(),
                    prefix: prefix.clone(),
                });
            }
            if let Some(other) = routes.iter().find(|route| {
                path_is_under(trimmed, &route.prefix) || path_is_under(&route.prefix, trimmed)
            }) {
                return Err(BaseUrlError::Overlapping(
                    other.rule.clone(),
                    spec.name.clone(),
                ));
            }
            routes.push(Route {
                rule: spec.name.clone(),
                prefix: trimmed.to_string(),
                host: spec.host.to_ascii_lowercase(),
                port: spec.port.unwrap_or(DEFAULT_PORT),
            });
        }
        Ok(Self { routes })
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    pub fn prefix_for(&self, rule: &str) -> Option<&str> {
        self.routes
            .iter()
            .find(|route| route.rule == rule)
            .map(|route| route.prefix.as_str())
    }

    pub fn resolve<'m, 'p>(&'m self, path: &'p str) -> Option<Resolved<'m, 'p>> {
        let route = self
            .routes
            .iter()
            .find(|route| path_is_under(path, &route.prefix))?;
        let rest = &path[route.prefix.len()..];
        Some(Resolved {
            rule: &route.rule,
            host: &route.host,
            port: route.port,
            path: if rest.is_empty() { "/" } else { rest },
        })
    }
}
