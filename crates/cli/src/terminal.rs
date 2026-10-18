pub fn printable(text: &str) -> String {
    escape_controls(text, false)
}

pub fn printable_lines(text: &str) -> String {
    escape_controls(text, true)
}

fn escape_controls(text: &str, keep_newlines: bool) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_control() && !(keep_newlines && c == '\n') {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn printed_text_cannot_drive_the_terminal() {
        let text = "a\n\u{1b}[1A\r\u{1b}[2Kb\t";
        assert_eq!(printable_lines(text), "a\n\\u{1b}[1A\\r\\u{1b}[2Kb\\t");
        assert_eq!(printable(text), "a\\n\\u{1b}[1A\\r\\u{1b}[2Kb\\t");
    }
}
