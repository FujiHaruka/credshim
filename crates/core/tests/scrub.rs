use std::sync::Arc;

use bytes::Bytes;
use credshim_core::Scrubber;
use credshim_core::scrub::MIN_SCRUB_LEN;
use http::{HeaderMap, HeaderValue};
use secrecy::SecretString;

fn scrubber(pairs: &[(&str, &str)]) -> Arc<Scrubber> {
    let secrets: Vec<(SecretString, &str)> = pairs
        .iter()
        .map(|(secret, dummy)| (SecretString::from(*secret), *dummy))
        .collect();
    Arc::new(Scrubber::new(
        secrets.iter().map(|(secret, dummy)| (secret, *dummy)),
    ))
}

fn stream_in_chunks(scrubber: &Arc<Scrubber>, input: &[u8], size: usize) -> Vec<u8> {
    let mut stream = scrubber.stream();
    let mut out = Vec::new();
    for chunk in input.chunks(size) {
        out.extend_from_slice(&stream.push(Bytes::copy_from_slice(chunk)));
    }
    out.extend_from_slice(&stream.finish());
    out
}

#[test]
fn every_chunking_yields_the_same_scrubbed_output() {
    let s = scrubber(&[
        ("sk-real-secret-1234", "DUMMY-A"),
        ("tok-real-9876543", "DUMMY-B"),
    ]);
    let input = b"a sk-real-secret-1234 b tok-real-9876543sk-real-secret-1234 sk-real-secre end";
    let whole = s.scrub(input).unwrap();
    assert_eq!(
        whole,
        b"a DUMMY-A b DUMMY-BDUMMY-A sk-real-secre end".to_vec()
    );
    for size in 1..=input.len() {
        assert_eq!(
            stream_in_chunks(&s, input, size),
            whole,
            "chunk size {size}"
        );
    }
}

#[test]
fn only_a_possible_prefix_is_held_back() {
    let s = scrubber(&[("sk-real-secret-1234", "DUMMY")]);
    let mut stream = s.stream();

    assert_eq!(
        stream.push(Bytes::from_static(b"data: hello\n\n")),
        "data: hello\n\n"
    );
    assert_eq!(stream.push(Bytes::from_static(b"tail sk-re")), "tail ");
    assert_eq!(
        stream.push(Bytes::from_static(b"al-secret-1234!")),
        "DUMMY!"
    );
    assert_eq!(stream.push(Bytes::from_static(b"sk-rea")), "");
    assert_eq!(stream.push(Bytes::from_static(b"d")), "sk-read");
    assert_eq!(stream.finish(), "");
    assert_eq!(stream.replaced(), 1);
}

#[test]
fn unfinished_prefix_is_released_at_the_end() {
    let s = scrubber(&[("sk-real-secret-1234", "DUMMY")]);
    let mut stream = s.stream();

    assert_eq!(stream.push(Bytes::from_static(b"end sk-real")), "end ");
    assert_eq!(stream.finish(), "sk-real");
}

#[test]
fn longest_secret_wins_when_one_contains_another() {
    let s = scrubber(&[
        ("real-token-abc", "SHORT"),
        ("real-token-abc-extended", "LONG"),
    ]);

    assert_eq!(
        s.scrub(b"x real-token-abc-extended y").unwrap(),
        b"x LONG y"
    );
    assert_eq!(s.scrub(b"x real-token-abc y").unwrap(), b"x SHORT y");
    for size in 1..=8 {
        assert_eq!(
            stream_in_chunks(&s, b"x real-token-abc-extended y", size),
            b"x LONG y"
        );
        assert_eq!(stream_in_chunks(&s, b"x real-token-abc", size), b"x SHORT");
    }
}

#[test]
fn short_secrets_are_not_scrubbed_to_avoid_mangling_bodies() {
    let short = "a".repeat(MIN_SCRUB_LEN - 1);
    let s = scrubber(&[(&short, "DUMMY")]);

    assert!(s.is_empty());
    assert_eq!(s.scrub(short.as_bytes()), None);
}

#[test]
fn header_values_are_scrubbed() {
    let s = scrubber(&[("sk-real-secret-1234", "DUMMY")]);
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-echo",
        HeaderValue::from_static("Bearer sk-real-secret-1234"),
    );
    headers.insert("x-other", HeaderValue::from_static("fine"));

    assert_eq!(s.scrub_headers(&mut headers), 1);
    assert_eq!(headers["x-echo"], "Bearer DUMMY");
    assert!(headers["x-echo"].is_sensitive());
    assert_eq!(headers["x-other"], "fine");
    assert!(!headers["x-other"].is_sensitive());
}

#[test]
fn header_whose_scrubbed_value_is_not_a_valid_header_is_removed() {
    let s = scrubber(&[("sk-real-secret-1234", "BAD\nDUMMY")]);
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-echo",
        HeaderValue::from_static("Bearer sk-real-secret-1234"),
    );
    headers.insert("x-other", HeaderValue::from_static("fine"));

    assert_eq!(s.scrub_headers(&mut headers), 1);
    assert!(!headers.contains_key("x-echo"));
    assert_eq!(headers["x-other"], "fine");
}

#[test]
fn debug_output_never_contains_secret_values() {
    let s = scrubber(&[("sk-real-secret-1234", "DUMMY")]);
    let mut stream = s.stream();
    stream.push(Bytes::from_static(b"sk-real-sec"));

    let rendered = format!("{s:?} {stream:?}");
    assert!(!rendered.contains("sk-real"), "{rendered}");
}

#[test]
fn encoded_forms_the_proxy_sends_are_scrubbed_too() {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    let secret = "REAL/SECRET+VALUE=0123";
    let s = scrubber(&[(secret, "DUMMY-VALUE-0123456789")]);
    for user in ["", "u", "us", "client-id"] {
        let basic = format!(
            "Authorization: Basic {}",
            STANDARD.encode(format!("{user}:{secret}"))
        );
        let scrubbed =
            String::from_utf8(s.scrub(basic.as_bytes()).expect("basic scrubbed")).unwrap();
        let credential = scrubbed.strip_prefix("Authorization: Basic ").unwrap();
        let lenient = base64::engine::GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            base64::engine::GeneralPurposeConfig::new()
                .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent)
                .with_decode_allow_trailing_bits(true),
        );
        if let Ok(decoded) = lenient.decode(credential) {
            let decoded = String::from_utf8_lossy(&decoded);
            assert!(!decoded.contains(secret), "{user}: {decoded}");
        }
        assert!(!basic.is_empty() && scrubbed != basic);
    }
    for query in [
        "/x?key=REAL%2FSECRET%2BVALUE%3D0123",
        "/x?key=REAL%2fSECRET%2bVALUE%3d0123",
    ] {
        let scrubbed = s.scrub(query.as_bytes()).expect("query scrubbed");
        assert_eq!(scrubbed, b"/x?key=DUMMY-VALUE-0123456789");
    }
}

#[test]
fn base64url_echoes_are_scrubbed_too() {
    use base64::Engine;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

    let secret = "real-secret-???>>>-value";
    assert!(STANDARD.encode(secret).contains(['+', '/']));
    let s = scrubber(&[(secret, "dummy-secret-0123456789")]);
    for prefix in ["", "{", "{\""] {
        let encoded = URL_SAFE_NO_PAD.encode(format!("{prefix}{secret}\"}}"));
        let scrubbed = s.scrub(encoded.as_bytes()).expect("base64url scrubbed");
        let decoded = URL_SAFE_NO_PAD.decode(&scrubbed).unwrap_or_default();
        assert!(
            !String::from_utf8_lossy(&decoded).contains(secret),
            "{prefix}"
        );
    }
}
