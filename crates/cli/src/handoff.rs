use std::path::{Path, PathBuf};

use crate::service;

pub struct Handoff {
    exe: PathBuf,
    installed: bool,
}

impl Handoff {
    pub fn current() -> Self {
        let exe = std::env::current_exe()
            .and_then(std::fs::canonicalize)
            .unwrap_or_else(|_| PathBuf::from("credshim"));
        let installed = exe == Path::new(service::INSTALLED);
        Self { exe, installed }
    }

    pub fn as_service(&self, args: &str, config: Option<&Path>) -> String {
        let exe = shell_word(&self.exe.display().to_string());
        let mut command = if self.installed {
            format!("sudo -u {} {exe}", service::SERVICE_USER)
        } else {
            exe
        };
        command.push(' ');
        command.push_str(args);
        if let Some(config) = config {
            command.push_str(" --config ");
            command.push_str(&shell_word(&config.display().to_string()));
        }
        command
    }

    pub fn reload(&self) -> String {
        if self.installed {
            format!("sudo {} service reload", shell_word(service::INSTALLED))
        } else {
            "pkill -HUP -f 'credshim run'".to_string()
        }
    }

    pub fn restart(&self) -> String {
        if self.installed {
            format!("sudo {} service install", shell_word(service::INSTALLED))
        } else {
            "restart `credshim run`".to_string()
        }
    }
}

pub fn shell_word(text: &str) -> String {
    if !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "/._-+".contains(c))
    {
        text.to_string()
    } else {
        format!("'{}'", text.replace('\'', r"'\''"))
    }
}
