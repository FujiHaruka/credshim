use bytes::Bytes;
use futures_util::Stream;
use sha2::{Digest, Sha256};

const PERIOD: u64 = 251;

fn byte_at(offset: u64) -> u8 {
    (offset % PERIOD) as u8
}

pub fn bytes(offset: u64, len: usize) -> Vec<u8> {
    (0..len as u64).map(|i| byte_at(offset + i)).collect()
}

pub fn chunks(total: u64, chunk_size: usize) -> impl Stream<Item = Bytes> + Send + 'static {
    futures_util::stream::unfold(0u64, move |offset| async move {
        if offset >= total {
            return None;
        }
        let len = chunk_size.min((total - offset) as usize);
        Some((Bytes::from(bytes(offset, len)), offset + len as u64))
    })
}

pub fn sha256_hex(total: u64) -> String {
    let mut hasher = Sha256::new();
    let mut offset = 0u64;
    while offset < total {
        let len = (64 * 1024).min((total - offset) as usize);
        hasher.update(bytes(offset, len));
        offset += len as u64;
    }
    hex::encode(hasher.finalize())
}

pub fn digest_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}
