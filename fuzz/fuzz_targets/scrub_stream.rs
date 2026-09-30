#![no_main]

use std::sync::{Arc, LazyLock};

use bytes::Bytes;
use credshim_core::Scrubber;
use libfuzzer_sys::fuzz_target;
use secrecy::SecretString;

const PATTERNS: [(&str, &str); 3] = [
    ("sk-real-abcabc-123", "DUMMY-ONE"),
    ("abcabc-123-longer-token", "DUMMY-TWO"),
    ("aaaaaaaaaa", "DUMMY-THREE"),
];

static SCRUBBER: LazyLock<Arc<Scrubber>> = LazyLock::new(|| {
    let secrets: Vec<(SecretString, &str)> = PATTERNS
        .iter()
        .map(|(secret, dummy)| (SecretString::from(*secret), *dummy))
        .collect();
    Arc::new(Scrubber::new(
        secrets.iter().map(|(secret, dummy)| (secret, *dummy)),
    ))
});

fuzz_target!(|data: &[u8]| {
    let Some((&split_seed, input)) = data.split_first() else {
        return;
    };
    let whole = SCRUBBER.scrub(input).unwrap_or_else(|| input.to_vec());
    let mut stream = SCRUBBER.stream();
    let mut streamed = Vec::new();
    let mut rest = input;
    let mut seed = split_seed as usize;
    while !rest.is_empty() {
        let size = (seed % 40 + 1).min(rest.len());
        seed = seed.wrapping_mul(31).wrapping_add(7);
        streamed.extend_from_slice(&stream.push(Bytes::copy_from_slice(&rest[..size])));
        rest = &rest[size..];
    }
    streamed.extend_from_slice(&stream.finish());
    assert_eq!(streamed, whole, "chunking changed the scrubbed output");
    for (secret, _) in PATTERNS {
        let survived = streamed
            .windows(secret.len())
            .any(|w| w == secret.as_bytes());
        assert!(!survived, "a secret survived scrubbing");
    }
});
