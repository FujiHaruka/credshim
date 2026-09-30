use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tempfile::TempDir;
use tokio::process::{Child, Command};

pub const HOST_KEY_TYPES: [(&str, &str); 3] = [
    ("ed25519", "ssh-ed25519"),
    ("ecdsa", "ecdsa-sha2-nistp256"),
    ("rsa", "rsa-sha2-512"),
];

pub struct TestSshd {
    dir: TempDir,
    port: u16,
    _child: Child,
}

pub struct SshOutput {
    pub success: bool,
    pub text: String,
}

impl TestSshd {
    pub async fn start(authorized_keys: &str) -> Self {
        let dir = tempfile::Builder::new().prefix("cs").tempdir().unwrap();
        for (kind, _) in HOST_KEY_TYPES {
            keygen(&dir.path().join(format!("host_{kind}")), kind);
        }
        std::fs::write(dir.path().join("authorized_keys"), authorized_keys).unwrap();
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let d = dir.path().display();
        std::fs::write(
            dir.path().join("sshd_config"),
            format!(
                "ListenAddress 127.0.0.1\nPort {port}\n\
                 HostKey {d}/host_ed25519\nHostKey {d}/host_ecdsa\nHostKey {d}/host_rsa\n\
                 PidFile none\nUsePAM no\nStrictModes no\n\
                 PasswordAuthentication no\nKbdInteractiveAuthentication no\n\
                 PubkeyAuthentication yes\nAuthorizedKeysFile {d}/authorized_keys\n\
                 AllowAgentForwarding yes\n"
            ),
        )
        .unwrap();
        let log = std::fs::File::create(dir.path().join("sshd.log")).unwrap();
        let child = Command::new(sshd_path())
            .args(["-D", "-e", "-f"])
            .arg(dir.path().join("sshd_config"))
            .stdout(Stdio::null())
            .stderr(log)
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let sshd = Self {
            dir,
            port,
            _child: child,
        };
        sshd.wait_until_listening().await;
        sshd
    }

    async fn wait_until_listening(&self) {
        for _ in 0..100 {
            if tokio::net::TcpStream::connect(("127.0.0.1", self.port))
                .await
                .is_ok()
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("sshd did not start:\n{}", self.log());
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn dir(&self) -> &Path {
        self.dir.path()
    }

    pub fn log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("sshd.log")).unwrap_or_default()
    }

    pub fn host_key_fingerprint(&self, kind: &str) -> String {
        fingerprint(&self.dir.path().join(format!("host_{kind}.pub")))
    }

    pub fn client_options(&self) -> Vec<String> {
        let mut options: Vec<String> = [
            "-F",
            "/dev/null",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
            "-o",
            "ConnectTimeout=5",
            "-o",
            "PreferredAuthentications=publickey",
            "-o",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        options.push(format!(
            "IdentityFile={}/no-such-key",
            self.dir.path().display()
        ));
        options
    }

    pub fn command(&self, program: &str, agent: &Path) -> Command {
        let mut command = Command::new(program);
        command
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap())
            .env("HOME", self.dir.path())
            .env("SSH_AUTH_SOCK", agent)
            .kill_on_drop(true);
        command
    }

    pub async fn ssh(
        &self,
        agent: &Path,
        host_key_algorithm: &str,
        extra: &[&str],
        remote: &str,
    ) -> SshOutput {
        let out = self
            .command("ssh", agent)
            .args(self.client_options())
            .args(["-o", &format!("HostKeyAlgorithms={host_key_algorithm}")])
            .args(extra)
            .args(["-p", &self.port.to_string()])
            .arg(format!("{}@127.0.0.1", login_user()))
            .arg(remote)
            .output()
            .await
            .unwrap();
        SshOutput {
            success: out.status.success(),
            text: format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        }
    }
}

pub fn login_user() -> String {
    let out = std::process::Command::new("id")
        .arg("-un")
        .output()
        .unwrap();
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

pub fn keygen(path: &Path, kind: &str) {
    let status = std::process::Command::new("ssh-keygen")
        .args(["-q", "-N", "", "-t", kind, "-f"])
        .arg(path)
        .status()
        .unwrap();
    assert!(status.success(), "ssh-keygen -t {kind} failed");
}

pub fn fingerprint(public_key_file: &Path) -> String {
    let out = std::process::Command::new("ssh-keygen")
        .args(["-l", "-E", "sha256", "-f"])
        .arg(public_key_file)
        .output()
        .unwrap();
    String::from_utf8(out.stdout)
        .unwrap()
        .split_whitespace()
        .nth(1)
        .expect("ssh-keygen -l prints a fingerprint")
        .to_string()
}

fn sshd_path() -> PathBuf {
    [
        "/usr/sbin/sshd",
        "/usr/local/sbin/sshd",
        "/opt/homebrew/sbin/sshd",
    ]
    .iter()
    .map(PathBuf::from)
    .find(|path| path.exists())
    .expect("these tests need OpenSSH's sshd (install openssh-server)")
}
