use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use bytes::Bytes;
use credshim_core::{ScrubStream, Scrubber};
use http::header::{self, HeaderMap};
use http::{Method, StatusCode};
use http_body::{Body, Frame};

pub(crate) struct ScrubBody<B> {
    inner: B,
    stream: ScrubStream,
    stashed_trailers: Option<HeaderMap>,
    done: bool,
    host: String,
}

impl<B> ScrubBody<B> {
    pub(crate) fn new(inner: B, scrubber: &Arc<Scrubber>, host: String) -> Self {
        Self {
            inner,
            stream: scrubber.stream(),
            stashed_trailers: None,
            done: false,
            host,
        }
    }

    fn scrubber(&self) -> &Scrubber {
        self.stream.scrubber()
    }

    fn finish(&mut self) -> Bytes {
        self.done = true;
        let tail = self.stream.finish();
        if self.stream.replaced() > 0 {
            tracing::warn!(
                host = %self.host,
                occurrences = self.stream.replaced(),
                "scrubbed secret values from a response body"
            );
        }
        tail
    }
}

impl<B> Body for ScrubBody<B>
where
    B: Body<Data = Bytes> + Unpin,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        loop {
            if let Some(trailers) = this.stashed_trailers.take() {
                return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
            }
            if this.done {
                return Poll::Ready(None);
            }
            let frame = match ready!(Pin::new(&mut this.inner).poll_frame(cx)) {
                Some(Ok(frame)) => frame,
                Some(Err(err)) => {
                    this.done = true;
                    return Poll::Ready(Some(Err(err)));
                }
                None => {
                    let tail = this.finish();
                    if tail.is_empty() {
                        return Poll::Ready(None);
                    }
                    return Poll::Ready(Some(Ok(Frame::data(tail))));
                }
            };
            let frame = match frame.into_data() {
                Ok(data) => {
                    let clean = this.stream.push(data);
                    if clean.is_empty() {
                        continue;
                    }
                    return Poll::Ready(Some(Ok(Frame::data(clean))));
                }
                Err(frame) => frame,
            };
            let Ok(mut trailers) = frame.into_trailers() else {
                continue;
            };
            if this.scrubber().scrub_headers(&mut trailers) > 0 {
                tracing::warn!(host = %this.host, "scrubbed secret values from response trailers");
            }
            let tail = this.finish();
            if tail.is_empty() {
                return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
            }
            this.stashed_trailers = Some(trailers);
            return Poll::Ready(Some(Ok(Frame::data(tail))));
        }
    }

    fn is_end_stream(&self) -> bool {
        self.done && self.stashed_trailers.is_none()
    }
}

pub(crate) fn is_encoded(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::CONTENT_ENCODING)
        .iter()
        .flat_map(|value| value.to_str().unwrap_or("?").split(','))
        .map(str::trim)
        .any(|coding| !coding.is_empty() && !coding.eq_ignore_ascii_case("identity"))
}

pub(crate) fn may_have_body(method: &Method, status: StatusCode) -> bool {
    method != Method::HEAD
        && !status.is_informational()
        && status != StatusCode::NO_CONTENT
        && status != StatusCode::NOT_MODIFIED
}
