use bytes::Bytes;
use http::request::Parts;
use http::{HeaderValue, Response, StatusCode, header};

use crate::policy::S3;

const EC2: &str = "ec2";

pub fn error_response(
    parts: &Parts,
    service: Option<&str>,
    status: StatusCode,
    code: &str,
    message: &str,
) -> Response<Bytes> {
    let (content_type, body) = match service {
        Some(S3) => (
            "application/xml",
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>{code}</Code><Message>{}</Message></Error>",
                xml_escape(message)
            ),
        ),
        Some(EC2) => (
            "text/xml",
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Response><Errors><Error><Code>{code}</Code><Message>{}</Message></Error></Errors><RequestID>credshim</RequestID></Response>",
                xml_escape(message)
            ),
        ),
        _ if speaks_json(parts) => (
            "application/json",
            serde_json::json!({ "__type": code, "message": message }).to_string(),
        ),
        _ => (
            "text/xml",
            format!(
                "<ErrorResponse><Error><Type>Sender</Type><Code>{code}</Code><Message>{}</Message></Error><RequestId>credshim</RequestId></ErrorResponse>",
                xml_escape(message)
            ),
        ),
    };
    let mut response = Response::new(Bytes::from(body));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    if let Ok(code) = HeaderValue::from_str(code) {
        headers.insert("x-amzn-errortype", code);
    }
    response
}

fn speaks_json(parts: &Parts) -> bool {
    parts.headers.contains_key("x-amz-target")
        || parts
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.contains("json"))
}

fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
