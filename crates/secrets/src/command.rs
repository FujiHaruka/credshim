use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use secrecy::SecretString;
use zeroize::Zeroizing;

use crate::{SecretInfo, SecretStore, StoreError, check_name};

const NAME_PLACEHOLDER: &str = "{name}";
const MAX_OUTPUT: u64 = 64 * 1024;
const POLL: Duration = Duration::from_millis(10);

pub struct CommandStore {
    argv: Vec<String>,
    timeout: Duration,
}

impl CommandStore {
    pub fn new(argv: Vec<String>, timeout: Duration) -> Result<Self, StoreError> {
        if argv.is_empty() {
            return Err(StoreError::Command {
                name: String::new(),
                reason: "the command is empty".to_string(),
            });
        }
        Ok(Self { argv, timeout })
    }

    fn fetch(&self, name: &str) -> Result<Zeroizing<Vec<u8>>, String> {
        let args: Vec<String> = self
            .argv
            .iter()
            .map(|arg| arg.replace(NAME_PLACEHOLDER, name))
            .collect();
        let mut child = Command::new(&args[0])
            .args(&args[1..])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|err| format!("could not start {:?}: {err}", args[0]))?;
        let stdout = child.stdout.take().expect("stdout is piped");
        let (sent, output) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut output = Zeroizing::new(Vec::new());
            let read = stdout
                .take(MAX_OUTPUT + 1)
                .read_to_end(&mut output)
                .map(|_| output);
            let _ = sent.send(read);
        });
        let deadline = Instant::now() + self.timeout;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() < deadline => std::thread::sleep(POLL),
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("timed out after {:?}", self.timeout));
                }
                Err(err) => return Err(err.to_string()),
            }
        };
        let output = output
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|_| format!("timed out after {:?} waiting for its output to close", self.timeout))?
            .map_err(|err| err.to_string())?;
        if !status.success() {
            return Err(format!("exited with {status}"));
        }
        if output.len() as u64 > MAX_OUTPUT {
            return Err(format!("printed more than {MAX_OUTPUT} bytes"));
        }
        Ok(output)
    }
}

impl SecretStore for CommandStore {
    fn get(&self, name: &str) -> Result<Option<SecretString>, StoreError> {
        check_name(name)?;
        let failed = |reason: String| StoreError::Command {
            name: name.to_string(),
            reason,
        };
        let output = self.fetch(name).map_err(failed)?;
        let text =
            std::str::from_utf8(&output).map_err(|_| failed("output is not UTF-8".into()))?;
        let value = text
            .strip_suffix("\r\n")
            .or_else(|| text.strip_suffix('\n'))
            .unwrap_or(text);
        if value.is_empty() {
            return Ok(None);
        }
        Ok(Some(SecretString::from(value)))
    }

    fn set(&self, _name: &str, _value: SecretString) -> Result<(), StoreError> {
        Err(StoreError::ReadOnly("command"))
    }

    fn list(&self) -> Result<Vec<SecretInfo>, StoreError> {
        Err(StoreError::ListUnsupported("command"))
    }
}
