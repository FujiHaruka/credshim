#[cfg(target_os = "macos")]
pub fn open(url: &str) -> bool {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let Some(script) = open_script(url) else {
        return false;
    };
    let Ok(mut child) = Command::new("/usr/bin/osascript")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    let written = child
        .stdin
        .take()
        .is_some_and(|mut stdin| stdin.write_all(script.as_bytes()).is_ok());
    std::thread::spawn(move || child.wait());
    written
}

#[cfg(not(target_os = "macos"))]
pub fn open(_url: &str) -> bool {
    false
}

#[cfg(any(target_os = "macos", test))]
fn open_script(url: &str) -> Option<String> {
    if !url.starts_with("https://") || url.chars().any(|c| c == '"' || c == '\\' || c.is_control())
    {
        return None;
    }
    Some(format!("open location \"{url}\"\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_url_goes_into_the_script_and_not_into_arguments() {
        let url = "https://oidc.us-east-1.amazonaws.com/authorize?response_type=code&state=abc%22";
        assert_eq!(
            open_script(url).as_deref(),
            Some(format!("open location \"{url}\"\n").as_str())
        );
    }

    #[test]
    fn a_url_that_could_break_out_of_the_script_string_is_not_opened() {
        for url in [
            "https://example.com/\" & do shell script \"id",
            "https://example.com/\\",
            "https://example.com/\nopen location \"https://evil.example\"",
            "http://example.com/",
            "file:///etc/passwd",
        ] {
            assert_eq!(open_script(url), None, "{url:?}");
        }
    }
}
