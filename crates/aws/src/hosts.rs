pub const AWS_DOMAIN: &str = "amazonaws.com";

const AWS_DOMAINS: [&str; 4] = [
    "amazonaws.com",
    "amazonaws.com.cn",
    "api.aws",
    "api.amazonwebservices.com.cn",
];
const SSO_OIDC_LABELS: [&str; 2] = ["oidc", "oidc-fips"];
const SSO_PORTAL_PREFIXES: [&str; 2] = ["portal.sso.", "portal.sso-fips."];
const SIGNIN_DOMAINS: [&str; 3] = ["signin.aws.amazon.com", "signin.aws", "signin.amazonaws.cn"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockedHost {
    SsoOidc,
    SsoPortal,
    Signin,
}

impl BlockedHost {
    pub fn name(self) -> &'static str {
        match self {
            BlockedHost::SsoOidc => "sso_oidc",
            BlockedHost::SsoPortal => "sso_portal",
            BlockedHost::Signin => "signin",
        }
    }
}

pub fn is_aws_host(host: &str) -> bool {
    is_under(&host.to_ascii_lowercase(), AWS_DOMAIN)
}

pub fn blocked(host: &str) -> Option<BlockedHost> {
    let host = host.to_ascii_lowercase();
    if SIGNIN_DOMAINS
        .iter()
        .any(|domain| is_or_under(&host, domain))
    {
        return Some(BlockedHost::Signin);
    }
    if !AWS_DOMAINS.iter().any(|domain| is_under(&host, domain)) {
        return None;
    }
    let first = host.split('.').next().unwrap_or_default();
    if SSO_OIDC_LABELS.contains(&first) {
        return Some(BlockedHost::SsoOidc);
    }
    if SSO_PORTAL_PREFIXES
        .iter()
        .any(|prefix| host.starts_with(prefix))
    {
        return Some(BlockedHost::SsoPortal);
    }
    None
}

pub(crate) fn has_prefix(host: &str, prefix: &str) -> bool {
    let host = host.to_ascii_lowercase();
    host.starts_with(&format!("{prefix}.")) || host.contains(&format!(".{prefix}."))
}

fn is_under(host: &str, domain: &str) -> bool {
    host.strip_suffix(domain)
        .is_some_and(|rest| rest.len() > 1 && rest.ends_with('.'))
}

fn is_or_under(host: &str, domain: &str) -> bool {
    host == domain || is_under(host, domain)
}
