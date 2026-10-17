use std::fmt;

use bytes::Bytes;
use http::header::{self, HeaderName, HeaderValue};
use http::{Response, StatusCode};

use credshim_aws::refusal::Format;

use crate::proxy::{ProxyBody, full};

pub const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("credshim-request-id");
pub const ERROR_HEADER: HeaderName = HeaderName::from_static("credshim-error");
pub const TROUBLESHOOTING: &str = "troubleshooting";
pub const AUDIT_LOG_TOPIC: &str = "configuration#audit-log-and-status";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Topic {
    Deny,
    NotAllowed,
    Limited,
    Misdirected,
    Error,
    Upstream,
    Rejected,
}

impl Topic {
    pub const ALL: [Topic; 7] = [
        Topic::Deny,
        Topic::NotAllowed,
        Topic::Limited,
        Topic::Misdirected,
        Topic::Error,
        Topic::Upstream,
        Topic::Rejected,
    ];

    pub fn anchor(self) -> &'static str {
        match self {
            Topic::Deny => "deny",
            Topic::NotAllowed => "not_allowed",
            Topic::Limited => "limited",
            Topic::Misdirected => "misdirected",
            Topic::Error => "error",
            Topic::Upstream => "upstream",
            Topic::Rejected => "rejected",
        }
    }

    pub fn docs_command(self) -> String {
        format!("credshim docs {TROUBLESHOOTING}#{}", self.anchor())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RequestId(String);

impl RequestId {
    pub(crate) fn new() -> Self {
        let mut raw = [0u8; 6];
        getrandom::fill(&mut raw).expect("the OS random number generator is unavailable");
        Self(raw.iter().map(|byte| format!("{byte:02x}")).collect())
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Details {
    #[default]
    NoAuditLog,
    Command(String),
}

#[derive(Clone, Debug, Default)]
pub struct Guide {
    details: Details,
}

impl Guide {
    pub fn new(details: Details) -> Self {
        Self { details }
    }

    pub(crate) fn finish(
        &self,
        id: Option<&RequestId>,
        mut response: Response<ProxyBody>,
    ) -> Response<ProxyBody> {
        if let Some(value) = id.and_then(|id| HeaderValue::from_str(id.as_str()).ok()) {
            response.headers_mut().insert(REQUEST_ID_HEADER, value);
        }
        let Some(refusal) = response.extensions_mut().remove::<Refusal>() else {
            return response;
        };
        let (mut parts, _) = response.into_parts();
        let details = self.details_line(id);
        let docs = refusal.topic.docs_command();
        let body = match refusal.aws {
            Some(aws) => {
                let message = format!(
                    "credshim: {} (details: {details}; docs: {docs})",
                    refusal.why
                );
                let (rendered, body) = aws
                    .format
                    .render(parts.status, aws.code, &message)
                    .into_parts();
                parts.headers.extend(rendered.headers);
                body
            }
            None => {
                parts.headers.insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("text/plain; charset=utf-8"),
                );
                Bytes::from(format!(
                    "credshim: {}\ndetails: {details}\ndocs: {docs}\n",
                    refusal.why
                ))
            }
        };
        parts.headers.insert(
            ERROR_HEADER,
            HeaderValue::from_static(refusal.topic.anchor()),
        );
        Response::from_parts(parts, full(body))
    }

    fn details_line(&self, id: Option<&RequestId>) -> String {
        match (&self.details, id) {
            (Details::Command(command), Some(id)) => format!("{command} {id}"),
            (Details::Command(_), None) => {
                "this request is not in the audit log; the proxy's own log has the reason".into()
            }
            (Details::NoAuditLog, _) => format!(
                "no audit log is configured, so only the proxy's own log has the reason (credshim docs {AUDIT_LOG_TOPIC})"
            ),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Refusal {
    topic: Topic,
    why: String,
    aws: Option<AwsRefusal>,
}

impl Refusal {
    pub(crate) fn why(&self) -> &str {
        &self.why
    }
}

#[derive(Clone, Copy, Debug)]
struct AwsRefusal {
    format: Format,
    code: &'static str,
}

pub(crate) fn refuse(
    status: StatusCode,
    topic: Topic,
    why: impl Into<String>,
) -> Response<ProxyBody> {
    refusal(
        status,
        Refusal {
            topic,
            why: why.into(),
            aws: None,
        },
    )
}

pub(crate) fn refuse_aws(
    status: StatusCode,
    topic: Topic,
    why: impl Into<String>,
    format: Format,
    code: &'static str,
) -> Response<ProxyBody> {
    refusal(
        status,
        Refusal {
            topic,
            why: why.into(),
            aws: Some(AwsRefusal { format, code }),
        },
    )
}

fn refusal(status: StatusCode, refusal: Refusal) -> Response<ProxyBody> {
    let mut response = Response::new(full(Bytes::new()));
    *response.status_mut() = status;
    response.extensions_mut().insert(refusal);
    response
}

pub(crate) fn error_chain(err: &(dyn std::error::Error + 'static)) -> String {
    let mut text = err.to_string();
    for source in std::iter::successors(err.source(), |err| err.source()) {
        let source = source.to_string();
        if !text.contains(&source) {
            text.push_str(": ");
            text.push_str(&source);
        }
    }
    text
}
