use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

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

const MAX_SYMLINK_HOPS: usize = 40;

pub fn check_private(path: &Path, what: &str) -> anyhow::Result<()> {
    check(path, what, 0o022)
}

pub fn check_private_dir(dir: &Path, what: &str) -> anyhow::Result<()> {
    let dir = absolute(dir)?;
    match std::fs::metadata(&dir) {
        Ok(metadata) => check_mode(&dir, &metadata, what, 0o022),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("could not inspect {}", dir.display())),
    }
}

pub fn check_secret(path: &Path, what: &str) -> anyhow::Result<()> {
    check(path, what, 0o066)
}

fn check(path: &Path, what: &str, forbidden: u32) -> anyhow::Result<()> {
    let path = absolute(path)?;
    match std::fs::metadata(&path) {
        Ok(metadata) => check_mode(&path, &metadata, what, forbidden)?,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(err).with_context(|| format!("could not inspect {}", path.display()));
        }
    }
    let holder = format!("the directory holding the {what}");
    let mut hop = path.clone();
    for _ in 0..MAX_SYMLINK_HOPS {
        let Some(parent) = hop.parent() else {
            return Ok(());
        };
        check_private_dir(parent, &holder)?;
        match std::fs::read_link(&hop) {
            Ok(target) => hop = parent.join(target),
            Err(_) => return Ok(()),
        }
    }
    bail!(
        "refusing to use {what} {}: it goes through more than {MAX_SYMLINK_HOPS} symbolic links",
        path.display()
    )
}

fn absolute(path: &Path) -> anyhow::Result<PathBuf> {
    let path = if path.as_os_str().is_empty() {
        Path::new(".")
    } else {
        path
    };
    std::path::absolute(path).with_context(|| format!("could not resolve {}", path.display()))
}

fn check_mode(
    path: &Path,
    metadata: &std::fs::Metadata,
    what: &str,
    forbidden: u32,
) -> anyhow::Result<()> {
    let me = geteuid().as_raw();
    if metadata.uid() != me && metadata.uid() != 0 {
        bail!(
            "refusing to use {what} {}: it is owned by uid {}, not by this user or root",
            path.display(),
            metadata.uid()
        );
    }
    if metadata.mode() & forbidden & 0o022 != 0 {
        bail!(
            "refusing to use {what} {}: it is writable by group or others (mode {:o}); run `chmod go-w` on it",
            path.display(),
            metadata.mode() & 0o7777
        );
    }
    if metadata.mode() & forbidden & 0o044 != 0 {
        bail!(
            "refusing to use {what} {}: it is readable by group or others (mode {:o}); run `chmod go-rwx` on it",
            path.display(),
            metadata.mode() & 0o7777
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(path: &Path, mode: u32) -> PathBuf {
        std::fs::create_dir(path).unwrap();
        std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(mode)).unwrap();
        path.to_path_buf()
    }

    #[test]
    fn every_directory_along_a_symlink_chain_is_checked() {
        let root = tempfile::tempdir().unwrap();
        let private = dir(&root.path().join("private"), 0o700);
        let shared = dir(&root.path().join("shared"), 0o777);
        std::fs::write(private.join("config.toml"), "").unwrap();
        std::os::unix::fs::symlink(private.join("config.toml"), shared.join("cfg")).unwrap();
        std::os::unix::fs::symlink("../shared/cfg", private.join("via-shared.toml")).unwrap();
        std::os::unix::fs::symlink("config.toml", private.join("direct.toml")).unwrap();
        std::os::unix::fs::symlink(shared.join("audit.jsonl"), private.join("audit.jsonl"))
            .unwrap();

        let through_shared = check_private(&private.join("via-shared.toml"), "config file");
        let dangling = check_private(&private.join("audit.jsonl"), "audit log");

        assert!(
            through_shared
                .unwrap_err()
                .to_string()
                .contains("the directory holding the config file"),
        );
        assert!(
            dangling
                .unwrap_err()
                .to_string()
                .contains("the directory holding the audit log"),
        );
        check_private(&private.join("direct.toml"), "config file").unwrap();
    }

    #[test]
    fn a_symlink_loop_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let private = dir(&root.path().join("private"), 0o700);
        std::os::unix::fs::symlink("b", private.join("a")).unwrap();
        std::os::unix::fs::symlink("a", private.join("b")).unwrap();

        assert!(check_private(&private.join("a"), "config file").is_err());
    }

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
