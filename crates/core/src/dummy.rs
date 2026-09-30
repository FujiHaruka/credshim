const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
pub const RANDOM_LEN: usize = 40;

pub const ACCESS_TOKEN_PREFIX: &str = "csh_at_";
pub const REFRESH_TOKEN_PREFIX: &str = "csh_rt_";
pub const ISSUED_PREFIXES: [&str; 2] = [ACCESS_TOKEN_PREFIX, REFRESH_TOKEN_PREFIX];

pub fn generate(prefix: &str) -> String {
    let mut raw = [0u8; RANDOM_LEN];
    getrandom::fill(&mut raw).expect("the OS random number generator is unavailable");
    let mut dummy = String::with_capacity(prefix.len() + RANDOM_LEN);
    dummy.push_str(prefix);
    dummy.extend(
        raw.iter()
            .map(|byte| ALPHABET[usize::from(*byte) % ALPHABET.len()] as char),
    );
    dummy
}

pub fn find_issued(haystack: &[u8]) -> impl Iterator<Item = &str> {
    ISSUED_PREFIXES.iter().flat_map(move |prefix| {
        let prefix = prefix.as_bytes();
        let len = prefix.len() + RANDOM_LEN;
        (0..haystack.len().saturating_sub(len - 1)).filter_map(move |at| {
            let candidate = &haystack[at..at + len];
            let random = &candidate[prefix.len()..];
            (candidate.starts_with(prefix) && random.iter().all(u8::is_ascii_alphanumeric))
                .then(|| std::str::from_utf8(candidate).ok())
                .flatten()
        })
    })
}
