use std::ffi::OsStr;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, bail};

const UPGRADE: &str = include_str!("../../../scripts/install.sh");
#[cfg(target_os = "linux")]
const SETUP: &str = include_str!("../../../scripts/stage-b/setup-linux.sh");
#[cfg(target_os = "linux")]
const RELOAD: &str = include_str!("../../../scripts/stage-b/reload-linux.sh");
#[cfg(target_os = "linux")]
pub const INSTALLED: &str = "/usr/local/libexec/credshim/credshim";
#[cfg(target_os = "macos")]
const SETUP: &str = include_str!("../../../scripts/stage-b/setup-macos.sh");
#[cfg(target_os = "macos")]
const RELOAD: &str = include_str!("../../../scripts/stage-b/reload-macos.sh");
#[cfg(target_os = "macos")]
pub const INSTALLED: &str = "/Library/CredShim/bin/credshim";

pub fn install(print: bool, upgrade: bool, user: Option<String>) -> anyhow::Result<()> {
    if print {
        std::io::stdout().write_all(SETUP.as_bytes())?;
        return Ok(());
    }
    if !rustix::process::geteuid().is_root() {
        bail!(
            "`credshim service install` creates a system user and a system service; run it with sudo (review it first with `credshim service install --print`)"
        );
    }
    let binary = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .context("could not locate the credshim binary")?;
    let installed = Path::new(INSTALLED);
    if installed.exists() && !upgrade && !same_file(&binary, installed)? {
        bail!(
            "{INSTALLED} is already installed; rerun with it (`sudo {INSTALLED} service install`) to refresh the service, or pass --upgrade to replace it with {}",
            binary.display()
        );
    }
    let user = user.or_else(|| {
        std::env::var("SUDO_USER")
            .ok()
            .filter(|name| name != "root")
    });
    run_script(
        SETUP,
        "credshim-service-install",
        std::iter::once(binary.as_os_str()).chain(user.as_deref().map(OsStr::new)),
    )
    .context("service setup failed")
}

pub fn reload(print: bool) -> anyhow::Result<()> {
    if print {
        std::io::stdout().write_all(RELOAD.as_bytes())?;
        return Ok(());
    }
    if !rustix::process::geteuid().is_root() {
        bail!(
            "`credshim service reload` signals the system service; run it with sudo (review it first with `credshim service reload --print`)"
        );
    }
    run_script(
        RELOAD,
        "credshim-service-reload",
        std::iter::empty::<&OsStr>(),
    )
    .context("service reload failed")
}

pub fn upgrade(print: bool, version: Option<String>) -> anyhow::Result<()> {
    if print {
        std::io::stdout().write_all(UPGRADE.as_bytes())?;
        return Ok(());
    }
    if !rustix::process::geteuid().is_root() {
        bail!(
            "`credshim service upgrade` replaces the installed binary and restarts the system service; run it with sudo (review it first with `credshim service upgrade --print`)"
        );
    }
    let version = version.unwrap_or_else(|| "latest".to_owned());
    run_script(UPGRADE, "credshim-service-upgrade", [OsStr::new(&version)])
        .context("service upgrade failed")
}

fn run_script<'a>(
    script: &str,
    name: &str,
    args: impl IntoIterator<Item = &'a OsStr>,
) -> anyhow::Result<()> {
    let status = Command::new("/bin/bash")
        .arg("-c")
        .arg(script)
        .arg(name)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .stdin(Stdio::null())
        .status()
        .context("could not start bash")?;
    if !status.success() {
        bail!("{status}");
    }
    Ok(())
}

fn same_file(a: &Path, b: &Path) -> anyhow::Result<bool> {
    let (a, b) = (std::fs::metadata(a)?, std::fs::metadata(b)?);
    Ok(a.dev() == b.dev() && a.ino() == b.ino())
}
