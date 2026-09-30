use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use http::Method;
use serde::Deserialize;

use crate::rule;

const MINUTE: Duration = Duration::from_secs(60);
const DAY_SECS: u64 = 24 * 60 * 60;

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub per_minute: Option<u32>,
    pub per_day: Option<u32>,
    pub concurrent: Option<u32>,
}

impl Limits {
    fn is_unlimited(&self) -> bool {
        self.per_minute.is_none() && self.per_day.is_none() && self.concurrent.is_none()
    }
}

#[derive(Clone, Debug, Default)]
pub struct Policy {
    methods: Option<Vec<Method>>,
    paths: Option<Vec<String>>,
    limits: Limits,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("allow_methods must list at least one method")]
    NoMethods,
    #[error("allow_methods entry {0:?} is not an HTTP method")]
    InvalidMethod(String),
    #[error("allow_paths must list at least one path")]
    NoPaths,
    #[error(
        "allow_paths entry {0:?} must start with '/' and contain no dot segments, '%', '?', '#' or '\\'"
    )]
    InvalidPath(String),
    #[error("limits must be positive")]
    ZeroLimit,
}

impl Policy {
    pub fn new(
        methods: Option<Vec<String>>,
        paths: Option<Vec<String>>,
        limits: Limits,
    ) -> Result<Self, PolicyError> {
        let methods = methods
            .map(|methods| {
                if methods.is_empty() {
                    return Err(PolicyError::NoMethods);
                }
                methods
                    .into_iter()
                    .map(|method| {
                        let upper = method.to_ascii_uppercase();
                        Method::from_bytes(upper.as_bytes())
                            .map_err(|_| PolicyError::InvalidMethod(method))
                    })
                    .collect()
            })
            .transpose()?;
        if let Some(paths) = &paths {
            if paths.is_empty() {
                return Err(PolicyError::NoPaths);
            }
            if let Some(bad) = paths.iter().find(|path| !rule::is_clean_path_prefix(path)) {
                return Err(PolicyError::InvalidPath(bad.clone()));
            }
        }
        if [limits.per_minute, limits.per_day, limits.concurrent].contains(&Some(0)) {
            return Err(PolicyError::ZeroLimit);
        }
        Ok(Self {
            methods,
            paths,
            limits,
        })
    }

    pub fn allows(&self, method: &Method, path: &str) -> bool {
        let method_ok = self
            .methods
            .as_ref()
            .is_none_or(|methods| methods.contains(method));
        let path_ok = self
            .paths
            .as_ref()
            .is_none_or(|paths| paths.iter().any(|prefix| rule::path_is_under(path, prefix)));
        method_ok && path_ok
    }

    pub fn limits(&self) -> Limits {
        self.limits
    }
}

#[derive(Debug, Default)]
struct Window {
    recent: VecDeque<Instant>,
    day: u64,
    today: u32,
    active: Arc<AtomicU32>,
}

#[derive(Debug, Default)]
pub struct Limiter {
    windows: Mutex<HashMap<String, Window>>,
}

#[derive(Debug, Default)]
pub struct Permit {
    held: Vec<Arc<AtomicU32>>,
}

impl Drop for Permit {
    fn drop(&mut self) {
        for active in &self.held {
            active.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

impl Limiter {
    pub fn admit<'a>(
        &self,
        rules: impl IntoIterator<Item = (&'a str, Limits)>,
        now: Instant,
        wall: SystemTime,
    ) -> Result<Permit, String> {
        let rules: Vec<(&str, Limits)> = rules
            .into_iter()
            .filter(|(_, limits)| !limits.is_unlimited())
            .collect();
        let day = wall
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs() / DAY_SECS);
        let mut windows = self
            .windows
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for (name, limits) in &rules {
            let window = windows.entry((*name).to_string()).or_default();
            while window
                .recent
                .front()
                .is_some_and(|at| now.saturating_duration_since(*at) >= MINUTE)
            {
                window.recent.pop_front();
            }
            if window.day != day {
                window.day = day;
                window.today = 0;
            }
            let over = limits
                .per_minute
                .is_some_and(|max| window.recent.len() >= max as usize)
                || limits.per_day.is_some_and(|max| window.today >= max)
                || limits
                    .concurrent
                    .is_some_and(|max| window.active.load(Ordering::Acquire) >= max);
            if over {
                return Err((*name).to_string());
            }
        }
        let mut permit = Permit::default();
        for (name, limits) in &rules {
            let window = windows.get_mut(*name).expect("checked above");
            if limits.per_minute.is_some() {
                window.recent.push_back(now);
            }
            window.today = window.today.saturating_add(1);
            window.active.fetch_add(1, Ordering::AcqRel);
            permit.held.push(window.active.clone());
        }
        Ok(permit)
    }
}
