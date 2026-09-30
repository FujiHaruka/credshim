use std::os::unix::fs::MetadataExt;
use std::path::Path;

use anyhow::{Context, bail};
use rustix::process::{Resource, Rlimit, geteuid, setrlimit};

pub fn disable_core_dumps() -> anyhow::Result<()> {
    setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .context("could not disable core dumps")?;
    #[cfg(target_os = "linux")]
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
        .context("could not mark the process non-dumpable")?;
    Ok(())
}

pub fn check_private(path: &Path, what: &str) -> anyhow::Result<()> {
    match std::fs::metadata(path) {
        Ok(metadata) => check_owner_only_writable(path, &metadata, what)?,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(err).with_context(|| format!("could not inspect {}", path.display()));
        }
    }
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty() && parent.exists())
    {
        let parent_metadata = std::fs::metadata(parent)
            .with_context(|| format!("could not inspect {}", parent.display()))?;
        check_owner_only_writable(
            parent,
            &parent_metadata,
            &format!("the directory holding the {what}"),
        )?;
    }
    Ok(())
}

fn check_owner_only_writable(
    path: &Path,
    metadata: &std::fs::Metadata,
    what: &str,
) -> anyhow::Result<()> {
    let me = geteuid().as_raw();
    if metadata.uid() != me && metadata.uid() != 0 {
        bail!(
            "refusing to use {what} {}: it is owned by uid {}, not by this user or root",
            path.display(),
            metadata.uid()
        );
    }
    if metadata.mode() & 0o022 != 0 {
        bail!(
            "refusing to use {what} {}: it is writable by group or others (mode {:o}); run `chmod go-w` on it",
            path.display(),
            metadata.mode() & 0o7777
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_dumps_are_disabled() {
        disable_core_dumps().unwrap();
        let limit = rustix::process::getrlimit(Resource::Core);
        assert_eq!(limit.current, Some(0));
        assert_eq!(limit.maximum, Some(0));
        #[cfg(target_os = "linux")]
        assert_eq!(
            rustix::process::dumpable_behavior().unwrap(),
            rustix::process::DumpableBehavior::NotDumpable
        );
    }
}
