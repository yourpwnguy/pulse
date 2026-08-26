//! Word wrapping for advisory prose.
//!
//! Greedy word wrap preserving blank lines and leaving indented blocks (Markdown
//! code fences, which advisories use heavily) unwrapped.

use unicode_width::UnicodeWidthStr;

use crate::render::line::truncate;

/// Greedy word wrap preserving blank lines and leaving indented blocks (Markdown
/// code fences, which advisories use heavily) unwrapped.
pub(crate) fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();

    for raw in text.lines() {
        let line = raw.trim_end();

        if line.trim().is_empty() {
            if out.last().is_some_and(String::is_empty) {
                continue;
            }
            out.push(String::new());
            continue;
        }

        if line.starts_with("    ") || line.starts_with('\t') || line.starts_with("```") {
            out.push(truncate(line, width));
            continue;
        }

        let mut current = String::new();
        for word in line.split_whitespace() {
            if current.is_empty() {
                // A single word wider than the budget still has to go somewhere;
                // truncating it beats emitting an over-wide line.
                current = truncate(word, width);
            } else if UnicodeWidthStr::width(current.as_str()) + 1 + UnicodeWidthStr::width(word)
                <= width
            {
                current.push(' ');
                current.push_str(word);
            } else {
                out.push(std::mem::take(&mut current));
                current = word.to_string();
            }
        }
        if !current.is_empty() {
            out.push(current);
        }
    }

    while out.last().is_some_and(String::is_empty) {
        out.pop();
    }
    out
}
