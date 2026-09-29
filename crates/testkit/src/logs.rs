use std::io;
use std::sync::{Arc, Mutex, OnceLock};

use tracing_subscriber::EnvFilter;

#[derive(Clone)]
pub struct LogCapture {
    buffer: Arc<Mutex<Vec<u8>>>,
}

struct BufferWriter(Arc<Mutex<Vec<u8>>>);

impl io::Write for BufferWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

static CAPTURE: OnceLock<LogCapture> = OnceLock::new();

pub fn capture_logs() -> LogCapture {
    CAPTURE
        .get_or_init(|| {
            let buffer = Arc::new(Mutex::new(Vec::new()));
            let writer = buffer.clone();
            tracing_subscriber::fmt()
                .with_env_filter(EnvFilter::new("trace"))
                .with_ansi(false)
                .with_writer(move || BufferWriter(writer.clone()))
                .try_init()
                .expect("another global tracing subscriber is already installed");
            LogCapture { buffer }
        })
        .clone()
}

impl LogCapture {
    pub fn contents(&self) -> String {
        String::from_utf8_lossy(&self.buffer.lock().unwrap()).into_owned()
    }

    pub fn assert_absent(&self, needles: &[&str]) {
        let contents = self.contents();
        assert!(
            !contents.is_empty(),
            "log capture is empty; the check would pass vacuously"
        );
        for needle in needles {
            assert!(
                !contents.contains(needle),
                "secret-like value leaked into logs: {}…",
                &needle[..needle.len().min(8)]
            );
        }
    }
}

pub fn fake_secret(label: &str) -> String {
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw).expect("random bytes");
    format!("FAKE-SECRET-{label}-{}", hex::encode(raw))
}
