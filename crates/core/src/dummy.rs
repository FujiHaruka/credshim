const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const RANDOM_LEN: usize = 40;

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
