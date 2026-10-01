use std::time::Duration;

use bytes::Bytes;
use credshim_aws::sso::{BoxFuture, Transport, TransportError};
use http::{Request, Response};
use http_body_util::{BodyExt, Full, Limited};
use hyper_util::rt::TokioIo;

use crate::upstream::{ALPN_HTTP1, Upstream};

const TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

pub struct UpstreamTransport {
    upstream: Upstream,
}

impl UpstreamTransport {
    pub fn new(upstream: Upstream) -> Self {
        Self { upstream }
    }

    async fn exchange(&self, request: Request<Bytes>) -> Result<Response<Bytes>, TransportError> {
        let failed = |err: &dyn std::fmt::Display| TransportError(err.to_string());
        let host = request
            .uri()
            .host()
            .ok_or_else(|| TransportError("the request has no host".into()))?
            .to_string();
        let port = request.uri().port_u16().unwrap_or(443);
        let tls = self
            .upstream
            .connect_tls(&host, port, &[ALPN_HTTP1])
            .await
            .map_err(|err| failed(&err))?;
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .map_err(|err| failed(&err))?;
        tokio::spawn(connection);
        let (mut parts, body) = request.into_parts();
        parts.uri = parts
            .uri
            .path_and_query()
            .map_or("/", |path| path.as_str())
            .parse()
            .map_err(|err| failed(&err))?;
        let response = sender
            .send_request(Request::from_parts(parts, Full::new(body)))
            .await
            .map_err(|err| failed(&err))?;
        let (parts, body) = response.into_parts();
        let body = Limited::new(body, MAX_RESPONSE_BYTES)
            .collect()
            .await
            .map_err(|err| failed(&err))?
            .to_bytes();
        Ok(Response::from_parts(parts, body))
    }
}

impl Transport for UpstreamTransport {
    fn send(
        &self,
        request: Request<Bytes>,
    ) -> BoxFuture<'_, Result<Response<Bytes>, TransportError>> {
        Box::pin(async move {
            tokio::time::timeout(TIMEOUT, self.exchange(request))
                .await
                .map_err(|_| TransportError("timed out talking to IAM Identity Center".into()))?
        })
    }
}
