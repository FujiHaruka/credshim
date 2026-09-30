use std::fmt;
use std::sync::Arc;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use base64::Engine;
use base64::engine::GeneralPurpose;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use bytes::Bytes;
use http::{HeaderMap, HeaderValue};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_encode};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

pub const MIN_SCRUB_LEN: usize = 8;

const QUERY_VALUE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

#[derive(Default)]
pub struct Scrubber {
    automaton: Option<AhoCorasick>,
    patterns: Vec<Zeroizing<Vec<u8>>>,
    replacements: Vec<Bytes>,
}

impl fmt::Debug for Scrubber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Scrubber")
            .field("patterns", &self.patterns.len())
            .finish()
    }
}

impl Scrubber {
    pub fn new<'a>(pairs: impl IntoIterator<Item = (&'a SecretString, &'a str)>) -> Self {
        let mut patterns: Vec<Zeroizing<Vec<u8>>> = Vec::new();
        let mut replacements = Vec::new();
        for (secret, dummy) in pairs {
            let bytes = secret.expose_secret().as_bytes();
            if bytes.len() < MIN_SCRUB_LEN {
                continue;
            }
            for (pattern, replacement) in encodings(bytes, dummy.as_bytes()) {
                if pattern.len() < MIN_SCRUB_LEN
                    || patterns
                        .iter()
                        .any(|seen| seen.as_slice() == pattern.as_slice())
                {
                    continue;
                }
                patterns.push(pattern);
                replacements.push(replacement);
            }
        }
        let automaton = (!patterns.is_empty()).then(|| {
            AhoCorasickBuilder::new()
                .match_kind(MatchKind::LeftmostLongest)
                .build(patterns.iter().map(|pattern| pattern.as_slice()))
                .expect("scrub patterns are bounded in number and length")
        });
        Self {
            automaton,
            patterns,
            replacements,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    pub fn scrub(&self, haystack: &[u8]) -> Option<Vec<u8>> {
        let automaton = self.automaton.as_ref()?;
        let mut matches = automaton.find_iter(haystack).peekable();
        matches.peek()?;
        let mut out = Vec::with_capacity(haystack.len());
        let mut at = 0;
        for found in matches {
            out.extend_from_slice(&haystack[at..found.start()]);
            out.extend_from_slice(&self.replacements[found.pattern().as_usize()]);
            at = found.end();
        }
        out.extend_from_slice(&haystack[at..]);
        Some(out)
    }

    pub fn scrub_headers(&self, headers: &mut HeaderMap) -> usize {
        let mut replaced = 0;
        for value in headers.values_mut() {
            if let Some(clean) = self
                .scrub(value.as_bytes())
                .and_then(|clean| HeaderValue::from_bytes(&clean).ok())
            {
                *value = clean;
                replaced += 1;
            }
        }
        replaced
    }

    pub fn stream(self: &Arc<Self>) -> ScrubStream {
        ScrubStream {
            scrubber: self.clone(),
            pending: Zeroizing::new(Vec::new()),
            replaced: 0,
        }
    }

    fn held_tail(&self, bytes: &[u8]) -> usize {
        self.patterns
            .iter()
            .map(|pattern| {
                let longest = bytes.len().min(pattern.len() - 1);
                (1..=longest)
                    .rev()
                    .find(|&len| bytes[bytes.len() - len..] == pattern[..len])
                    .unwrap_or(0)
            })
            .max()
            .unwrap_or(0)
    }
}

fn encodings(secret: &[u8], dummy: &[u8]) -> Vec<(Zeroizing<Vec<u8>>, Bytes)> {
    let mut out = vec![(
        Zeroizing::new(secret.to_vec()),
        Bytes::copy_from_slice(dummy),
    )];
    let upper = Zeroizing::new(percent_encode(secret, QUERY_VALUE).to_string());
    let lower = Zeroizing::new(lowercase_escapes(&upper));
    for encoded in [&upper, &lower] {
        out.push((
            Zeroizing::new(encoded.as_bytes().to_vec()),
            Bytes::copy_from_slice(dummy),
        ));
    }
    for engine in [&STANDARD_NO_PAD, &URL_SAFE_NO_PAD] {
        for offset in 0..3 {
            out.push((
                base64_at(engine, secret, offset),
                Bytes::from(base64_at(engine, dummy, offset).to_vec()),
            ));
        }
    }
    out
}

fn lowercase_escapes(encoded: &str) -> String {
    let mut out = String::with_capacity(encoded.len());
    let mut escape = 0;
    for c in encoded.chars() {
        if c == '%' {
            escape = 2;
            out.push(c);
        } else if escape > 0 {
            escape -= 1;
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

fn base64_at(engine: &GeneralPurpose, bytes: &[u8], offset: usize) -> Zeroizing<Vec<u8>> {
    let mut shifted = Zeroizing::new(vec![0u8; offset]);
    shifted.extend_from_slice(bytes);
    let encoded = Zeroizing::new(engine.encode(&*shifted).into_bytes());
    let skip = (offset * 8).div_ceil(6);
    let bits = shifted.len() * 8;
    let keep = bits / 6;
    Zeroizing::new(encoded[skip.min(keep)..keep].to_vec())
}

pub struct ScrubStream {
    scrubber: Arc<Scrubber>,
    pending: Zeroizing<Vec<u8>>,
    replaced: usize,
}

impl fmt::Debug for ScrubStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScrubStream")
            .field("held", &self.pending.len())
            .field("replaced", &self.replaced)
            .finish()
    }
}

impl ScrubStream {
    pub fn push(&mut self, chunk: Bytes) -> Bytes {
        let Some(automaton) = self.scrubber.automaton.as_ref() else {
            return chunk;
        };
        if self.pending.is_empty() && automaton.find(chunk.as_ref()).is_none() {
            let held = self.scrubber.held_tail(&chunk);
            self.pending.extend_from_slice(&chunk[chunk.len() - held..]);
            return chunk.slice(..chunk.len() - held);
        }
        let mut buffer = Zeroizing::new(std::mem::take(&mut *self.pending));
        buffer.extend_from_slice(&chunk);
        let hold_from = buffer.len() - self.scrubber.held_tail(&buffer);
        let mut out = Vec::with_capacity(buffer.len());
        let mut at = 0;
        for found in automaton
            .find_iter(buffer.as_slice())
            .take_while(|found| found.start() < hold_from)
        {
            out.extend_from_slice(&buffer[at..found.start()]);
            out.extend_from_slice(&self.scrubber.replacements[found.pattern().as_usize()]);
            at = found.end();
            self.replaced += 1;
        }
        let rest = &buffer[at..];
        let held = self.scrubber.held_tail(rest);
        out.extend_from_slice(&rest[..rest.len() - held]);
        self.pending.extend_from_slice(&rest[rest.len() - held..]);
        Bytes::from(out)
    }

    pub fn finish(&mut self) -> Bytes {
        let pending = Zeroizing::new(std::mem::take(&mut *self.pending));
        match self.scrubber.scrub(&pending) {
            Some(clean) => {
                self.replaced += 1;
                Bytes::from(clean)
            }
            None => Bytes::copy_from_slice(&pending),
        }
    }

    pub fn replaced(&self) -> usize {
        self.replaced
    }

    pub fn scrubber(&self) -> &Scrubber {
        &self.scrubber
    }
}
