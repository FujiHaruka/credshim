use std::io::Write;
use std::process::{Command, Stdio};

use anyhow::{Context, bail};

#[cfg(target_os = "linux")]
const SETUP: &str = include_str!("../../../scripts/stage-b/setup-linux.sh");
#[cfg(target_os = "macos")]
const SETUP: &str = include_str!("../../../scripts/stage-b/setup-macos.sh");

pub fn install(print: bool) -> anyhow::Result<()> {
    if print {
        std::io::stdout().write_all(SETUP.as_bytes())?;
        return Ok(());
    }
    if !rustix::process::geteuid().is_root() {
        bail!(
            "`credshim service install` creates a system user and a system service; run it with sudo (review it first with `credshim service install --print`)"
        );
    }
    let binary = std::env::current_exe().context("could not locate the credshim binary")?;
    let status = Command::new("/bin/bash")
        .arg("-c")
        .arg(SETUP)
        .arg("credshim-service-install")
        .arg(&binary)
        .stdin(Stdio::null())
        .status()
        .context("could not start bash")?;
    if !status.success() {
        bail!("service setup failed ({status})");
    }
    Ok(())
}
