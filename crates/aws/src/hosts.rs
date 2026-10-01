use crate::service_endpoints::SERVICE_ENDPOINTS;

pub const AWS_DOMAIN: &str = "amazonaws.com";
pub const CUSTOMER_HOSTED_SERVICES: [&str; 1] = ["execute-api"];

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
    [prefix.to_string(), format!("{prefix}-fips")]
        .iter()
        .any(|prefix| {
            host.starts_with(&format!("{prefix}.")) || host.contains(&format!(".{prefix}."))
        })
}

pub fn is_endpoint_of(host: &str, service: &str, region: &str) -> bool {
    let host = host.to_ascii_lowercase();
    let Some(rest) = host.strip_suffix(&format!(".{AWS_DOMAIN}")) else {
        return false;
    };
    let labels: Vec<&str> = rest.split('.').collect();
    let s3_legacy = service == "s3"
        && labels
            .last()
            .is_some_and(|last| *last == format!("s3-{region}") || *last == "s3-external-1");
    s3_legacy
        || endpoint_prefixes(service).any(|prefix| {
            let wanted: Vec<&str> = prefix.split('.').collect();
            (0..labels.len()).any(|start| {
                let Some(found) = labels.get(start..start + wanted.len()) else {
                    return false;
                };
                let named = found
                    .iter()
                    .zip(&wanted)
                    .enumerate()
                    .all(|(i, (got, want))| {
                        got == want || (i + 1 == wanted.len() && *got == format!("{want}-fips"))
                    });
                let tail = &labels[start + wanted.len()..];
                named && (tail.is_empty() || tail == [region])
            })
        })
}

fn endpoint_prefixes(service: &str) -> impl Iterator<Item = &'static str> {
    let extra: &[&str] = if service == "s3" {
        &["s3", "s3-accesspoint"]
    } else {
        &[]
    };
    SERVICE_ENDPOINTS
        .iter()
        .filter(move |(signing_name, _)| *signing_name == service)
        .map(|(_, prefix)| *prefix)
        .chain(extra.iter().copied())
}

fn is_under(host: &str, domain: &str) -> bool {
    host.strip_suffix(domain)
        .is_some_and(|rest| rest.len() > 1 && rest.ends_with('.'))
}

fn is_or_under(host: &str, domain: &str) -> bool {
    host == domain || is_under(host, domain)
}
