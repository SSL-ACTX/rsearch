use std::fmt::Write as FmtWrite;
use std::sync::atomic::{AtomicBool, Ordering};

static COLOR_ENABLED: AtomicBool = AtomicBool::new(true);

pub fn set_color_enabled(enabled: bool) {
    COLOR_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn confidence_tier(confidence: u8) -> (&'static str, &'static str) {
    if confidence >= 7 {
        ("🔴", "loud")
    } else if confidence >= 4 {
        ("🟡", "normal")
    } else {
        ("⚫", "quiet")
    }
}

fn colors_enabled() -> bool {
    COLOR_ENABLED.load(Ordering::Relaxed)
}

/// Prettify and colorize a snippet; returns a String suitable for human output.
pub fn format_prettified(raw: &str, matched_word: &str) -> String {
    format_prettified_with_hint(raw, matched_word, None)
}

pub fn format_prettified_with_hint(raw: &str, matched_word: &str, source_hint: Option<&str>) -> String {
    use owo_colors::OwoColorize;

    if colors_enabled() {
        if let Some(highlighted) = maybe_highlight(raw, source_hint) {
            let _ = matched_word;
            return highlighted;
        }
    }

    let mut out = String::new();
    let mut indentation = 0usize;
    for line in raw.split([';', '{', '}']) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let prefix = "  ".repeat(indentation + 1);
        let highlighted = trimmed.replace(matched_word, &matched_word.bold().bright_yellow().to_string());
        let _ = writeln!(out, "{}{}", prefix, highlighted);

        if raw.contains('{') {
            indentation += 1;
        }
        if raw.contains('}') {
            indentation = indentation.saturating_sub(1);
        }
    }
    out
}

#[cfg(feature = "highlighting")]
fn format_prettified_highlight(raw: &str, source_hint: Option<&str>) -> String {
    use syntect::easy::HighlightLines;
    use syntect::highlighting::{Theme, ThemeSet};
    use syntect::parsing::SyntaxSet;
    use syntect::util::as_24_bit_terminal_escaped;
    use std::sync::OnceLock;

    static SYNTAX_SET: OnceLock<SyntaxSet> = OnceLock::new();
    static THEME: OnceLock<Theme> = OnceLock::new();

    let syntax_set = SYNTAX_SET.get_or_init(SyntaxSet::load_defaults_newlines);
    let theme = THEME.get_or_init(|| {
        let ts = ThemeSet::load_defaults();
        ts.themes
            .get("base16-ocean.dark")
            .cloned()
            .or_else(|| ts.themes.values().next().cloned())
            .unwrap_or_default()
    });

    let syntax = match source_hint.and_then(detect_extension) {
        Some(ext) => syntax_set
            .find_syntax_by_extension(&ext)
            .unwrap_or_else(|| syntax_set.find_syntax_plain_text()),
        None => syntax_set.find_syntax_plain_text(),
    };
    let mut highlighter = HighlightLines::new(syntax, theme);

    let mut out = String::new();
    let mut indentation = 0usize;
    for line in raw.split([';', '{', '}']) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let prefix = "  ".repeat(indentation + 1);
        if let Ok(ranges) = highlighter.highlight_line(trimmed, syntax_set) {
            let escaped = as_24_bit_terminal_escaped(&ranges[..], false);
            let _ = writeln!(out, "{}{}\x1b[0m", prefix, escaped);
        } else {
            let _ = writeln!(out, "{}{}\x1b[0m", prefix, trimmed);
        }

        if raw.contains('{') {
            indentation += 1;
        }
        if raw.contains('}') {
            indentation = indentation.saturating_sub(1);
        }
    }

    out.push_str("\x1b[0m");
    out
}

#[cfg(feature = "highlighting")]
fn maybe_highlight(raw: &str, source_hint: Option<&str>) -> Option<String> {
    if colors_enabled() {
        Some(format_prettified_highlight(raw, source_hint))
    } else {
        None
    }
}

#[cfg(not(feature = "highlighting"))]
fn maybe_highlight(_raw: &str, _source_hint: Option<&str>) -> Option<String> {
    None
}

#[cfg(feature = "highlighting")]
fn detect_extension(source_hint: &str) -> Option<String> {
    let mut end = source_hint.len();
    if let Some(idx) = source_hint.find('?') {
        end = end.min(idx);
    }
    if let Some(idx) = source_hint.find('#') {
        end = end.min(idx);
    }
    let trimmed = &source_hint[..end];
    let file = trimmed.rsplit('/').next().unwrap_or(trimmed);
    let ext = file.rsplit('.').next()?;
    if ext == file || ext.is_empty() {
        None
    } else {
        Some(ext.to_lowercase())
    }
}

/// Scans backwards from the secret's start position to find a variable name or key.
pub fn find_preceding_identifier(bytes: &[u8], start_index: usize) -> Option<String> {
    if start_index == 0 {
        return None;
    }

    let mut cursor = start_index - 1;
    let limit = start_index.saturating_sub(64);

    while cursor > limit {
        let b = bytes[cursor];
        if b == b'"' || b == b'\'' || b == b'`' || b.is_ascii_whitespace() {
            cursor -= 1;
        } else {
            break;
        }
    }

    let mut found_assignment = false;
    while cursor > limit {
        let b = bytes[cursor];
        if b == b'=' || b == b':' {
            found_assignment = true;
            cursor -= 1;
            break;
        } else if b.is_ascii_whitespace() {
            cursor -= 1;
        } else {
            return None;
        }
    }

    if !found_assignment {
        return None;
    }

    while cursor > limit && bytes[cursor].is_ascii_whitespace() {
        cursor -= 1;
    }

    let end_id = cursor + 1;
    while cursor > limit {
        let b = bytes[cursor];
        if b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.' || b == b'$' {
            cursor -= 1;
        } else {
            break;
        }
    }
    let start_id = cursor + 1;

    if start_id < end_id {
        let raw = String::from_utf8_lossy(&bytes[start_id..end_id]);
        let cleaned = raw.trim_matches(|c| c == '"' || c == '\'' || c == '`');
        if !cleaned.is_empty() {
            return Some(cleaned.to_string());
        }
    }

    None
}

#[derive(Clone, Default)]
pub struct LineFilter {
    ranges: Vec<(usize, usize)>,
}

impl LineFilter {
    pub fn new(ranges: Vec<(usize, usize)>) -> Self {
        Self { ranges }
    }

    pub fn allows(&self, line: usize) -> bool {
        self.ranges.iter().any(|(s, e)| line >= *s && line <= *e)
    }
}

