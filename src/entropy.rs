use base64::{engine::general_purpose, Engine as _};
use memchr;
use memchr::memmem;
use log::info;
use std::collections::HashSet;
use std::fmt::Write as FmtWrite;

use crate::output::MatchRecord;
use crate::heuristics::{analyze_flow_context_with_mode, format_flow_compact, FlowMode};
use crate::utils::{find_preceding_identifier, format_prettified};

/// Calculates the Shannon Entropy (randomness) of a byte slice.
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut frequencies = [0u32; 256];
    for &b in data {
        frequencies[b as usize] += 1;
    }

    let len = data.len() as f64;
    frequencies
        .iter()
        .filter(|&&n| n > 0)
        .map(|&n| {
            let p = n as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Checks if a string is valid Base64 that decodes to common readable text.
pub fn is_harmless_text(candidate: &str) -> bool {
    if candidate.contains(|c: char| !c.is_alphanumeric() && c != '+' && c != '/' && c != '=') {
        return false;
    }

    if let Ok(decoded) = general_purpose::STANDARD.decode(candidate) {
        let readable_count = decoded
            .iter()
            .filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
            .count();

        let ratio = readable_count as f64 / decoded.len() as f64;
        return ratio > 0.85;
    }

    false
}

/// Detects standard character sets (alphabets, digits) which have high entropy but are not secrets.
pub fn is_likely_charset(candidate: &str) -> bool {
    if candidate.contains("abcde")
        || candidate.contains("ABCDE")
        || candidate.contains("12345")
        || candidate.contains("vwxyz")
    {
        return true;
    }
    false
}

fn is_likely_url_context(bytes: &[u8], start: usize, end: usize) -> bool {
    let window_start = start.saturating_sub(128);
    let window_end = (end + 128).min(bytes.len());
    let window = &bytes[window_start..window_end];

    memmem::find(window, b"http://").is_some()
        || memmem::find(window, b"https://").is_some()
        || memmem::find(window, b"url(").is_some()
}

pub fn scan_for_secrets(
    source_label: &str,
    bytes: &[u8],
    threshold: f64,
    context_size: usize,
    emit_tags: &HashSet<String>,
    deep_scan: bool,
    flow_mode: FlowMode,
) -> (String, Vec<MatchRecord>) {
    use owo_colors::OwoColorize;

    let mut out = String::new();
    let mut records: Vec<MatchRecord> = Vec::new();
    let mut start = 0;
    let mut in_word = false;
    let min_len = 20;
    let max_len = 120;
    let mut url_hits = 0usize;
    let mut header_written = false;

    let mut ensure_header = |buffer: &mut String| {
        if !header_written {
            let _ = writeln!(
                buffer,
                "\n🔐 Entropy scanning {} (threshold {:.1})...",
                source_label.cyan(),
                threshold
            );
            let _ = writeln!(buffer, "{}", "━".repeat(60).dimmed());
            header_written = true;
        }
    };

    for (i, &b) in bytes.iter().enumerate() {
        let is_secret_char = b.is_ascii_alphanumeric()
            || b == b'+'
            || b == b'/'
            || b == b'='
            || b == b'-'
            || b == b'_';

        if is_secret_char {
            if !in_word {
                start = i;
                in_word = true;
            }
        } else if in_word {
            in_word = false;
            let len = i - start;

            if len >= min_len && len <= max_len {
                let candidate_bytes = &bytes[start..i];
                let score = calculate_entropy(candidate_bytes);

                if score > threshold {
                    let snippet_str = String::from_utf8_lossy(candidate_bytes);

                    if is_likely_url_context(bytes, start, i) {
                        url_hits += 1;
                        if emit_tags.contains("url") {
                            ensure_header(&mut out);
                            let preceding = &bytes[..start];
                            let line = memchr::memchr_iter(b'\n', preceding).count() + 1;
                            let last_nl = preceding.iter().rposition(|&b| b == b'\n').unwrap_or(0);
                            let col = if last_nl == 0 { start } else { start - last_nl };

                            let ctx_start = start.saturating_sub(context_size);
                            let ctx_end = (i + context_size).min(bytes.len());
                            let raw_context = String::from_utf8_lossy(&bytes[ctx_start..ctx_end]);

                            let _ = write!(
                                out,
                                "{}[L:{} C:{} Tag:{}] ",
                                "[".dimmed(),
                                line.bright_magenta(),
                                col.bright_blue(),
                                "url".bright_yellow().bold()
                            );
                            let _ = writeln!(out, "{}", "URL_CONTEXT".cyan().bold());

                            let pretty = format_prettified(&raw_context, &snippet_str);
                            let _ = writeln!(out, "{}", pretty);
                            let _ = writeln!(out, "{}", "─".repeat(40).dimmed());

                            records.push(MatchRecord {
                                source: source_label.to_string(),
                                kind: "url".to_string(),
                                matched: snippet_str.to_string(),
                                line,
                                col,
                                entropy: Some(score),
                                context: raw_context.to_string(),
                                identifier: None,
                            });
                        }
                        continue;
                    }
                    if is_harmless_text(&snippet_str) {
                        continue;
                    }
                    if is_likely_charset(&snippet_str) {
                        continue;
                    }

                    let preceding = &bytes[..start];
                    let line = memchr::memchr_iter(b'\n', preceding).count() + 1;
                    let last_nl = preceding.iter().rposition(|&b| b == b'\n').unwrap_or(0);
                    let col = if last_nl == 0 { start } else { start - last_nl };

                    let ctx_start = start.saturating_sub(context_size);
                    let ctx_end = (i + context_size).min(bytes.len());
                    let raw_context = String::from_utf8_lossy(&bytes[ctx_start..ctx_end]);

                    let identifier = find_preceding_identifier(bytes, start);

                    ensure_header(&mut out);
                    let _ = write!(
                        out,
                        "{}[L:{} C:{} Entropy:{:.1}] ",
                        "[".dimmed(),
                        line.bright_magenta(),
                        col.bright_blue(),
                        score
                    );

                    if let Some(id) = identifier.clone() {
                        let _ = writeln!(out, "{} = {}", id.cyan().bold(), "SECRET_MATCH".red().bold());
                    } else {
                        let _ = writeln!(out, "{}", "Unassigned High-Entropy Block".red().bold());
                    }

                    let pretty = format_prettified(&raw_context, &snippet_str);
                    let _ = writeln!(out, "{}", pretty);

                    if deep_scan {
                        let (count, nearest) = repeat_stats(bytes, candidate_bytes, start);
                        let shape = token_shape_hints(&snippet_str);
                        let shape_str = if shape.is_empty() {
                            "shape n/a".to_string()
                        } else {
                            format!("shape {}", shape.join(","))
                        };
                        let (alpha_pct, digit_pct, other_pct) = composition_percentages(&snippet_str);
                        let id_hint = identifier
                            .as_deref()
                            .map(|id| format!("; id {}", id))
                            .unwrap_or_default();
                        let (signals, confidence) = context_signals(&raw_context, identifier.as_deref(), &snippet_str);
                        let signals_str = if signals.is_empty() {
                            "signals n/a".to_string()
                        } else {
                            format!("signals {}", signals.join(","))
                        };
                        let _ = writeln!(
                            out,
                            "Story: appears {} times; nearest repeat {} bytes away; len {}; {}; mix a{}% d{}% s{}%; {}; conf {}/10{}",
                            count,
                            nearest.map(|d| d.to_string()).unwrap_or_else(|| "n/a".to_string()),
                            snippet_str.len(),
                            shape_str,
                            alpha_pct,
                            digit_pct,
                            other_pct,
                            signals_str,
                            confidence,
                            id_hint
                        );
                    }

                    if flow_mode != FlowMode::Off {
                        if let Some(flow) = analyze_flow_context_with_mode(bytes, start, flow_mode) {
                            if let Some(line) = format_flow_compact(&flow) {
                                let _ = writeln!(out, "Flow: {}", line);
                            }
                        }
                    }

                    let _ = writeln!(out, "{}", "─".repeat(40).dimmed());

                    records.push(MatchRecord {
                        source: source_label.to_string(),
                        kind: "entropy".to_string(),
                        matched: snippet_str.to_string(),
                        line,
                        col,
                        entropy: Some(score),
                        context: raw_context.to_string(),
                        identifier,
                    });
                }
            }
        }
    }

    if url_hits > 0 {
        info!(
            "{}: skipped {} URL-context entropy candidates due to emit-tags",
            source_label,
            url_hits
        );
        ensure_header(&mut out);
        let _ = writeln!(
            out,
            "{} Skipped {} URL-context entropy candidates (tagged as url and held back)",
            "⚠️".bright_yellow().bold(),
            url_hits
        );
    }

    (out, records)
}

fn repeat_stats(bytes: &[u8], needle: &[u8], pos: usize) -> (usize, Option<usize>) {
    if needle.is_empty() {
        return (0, None);
    }
    let mut positions = Vec::new();
    for p in memmem::find_iter(bytes, needle) {
        positions.push(p);
    }
    if positions.is_empty() {
        return (0, None);
    }
    positions.sort_unstable();
    let mut nearest: Option<usize> = None;
    for &p in &positions {
        if p == pos {
            continue;
        }
        let dist = if p >= pos { p - pos } else { pos - p };
        nearest = Some(nearest.map(|d: usize| d.min(dist)).unwrap_or(dist));
    }
    (positions.len(), nearest)
}

fn token_shape_hints(token: &str) -> Vec<&'static str> {
    let mut hints = Vec::new();
    if is_uuid_like(token) {
        hints.push("uuid");
    }
    if is_jwt_like(token) {
        hints.push("jwt");
    }
    if is_hex_like(token) {
        hints.push("hex");
    }
    if is_base64_like(token) {
        hints.push("base64");
    } else if is_base64url_like(token) {
        hints.push("base64url");
    }
    hints
}

fn composition_percentages(token: &str) -> (u8, u8, u8) {
    let mut alpha = 0usize;
    let mut digit = 0usize;
    let mut other = 0usize;
    for ch in token.chars() {
        if ch.is_ascii_alphabetic() {
            alpha += 1;
        } else if ch.is_ascii_digit() {
            digit += 1;
        } else {
            other += 1;
        }
    }
    let len = token.chars().count().max(1);
    let ap = ((alpha * 100) / len) as u8;
    let dp = ((digit * 100) / len) as u8;
    let op = ((other * 100) / len) as u8;
    (ap, dp, op)
}

fn is_hex_like(token: &str) -> bool {
    let len = token.len();
    len >= 16
        && len % 2 == 0
        && token.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_base64_like(token: &str) -> bool {
    let len = token.len();
    len >= 16
        && len % 4 == 0
        && token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
}

fn is_base64url_like(token: &str) -> bool {
    let len = token.len();
    len >= 16
        && token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '=')
}

fn is_uuid_like(token: &str) -> bool {
    if token.len() != 36 {
        return false;
    }
    let bytes = token.as_bytes();
    for &i in &[8usize, 13, 18, 23] {
        if bytes[i] != b'-' {
            return false;
        }
    }
    token
        .chars()
        .enumerate()
        .all(|(i, c)| if [8, 13, 18, 23].contains(&i) { c == '-' } else { c.is_ascii_hexdigit() })
}

fn is_jwt_like(token: &str) -> bool {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    parts.iter().all(|p| is_base64url_like(p))
}

fn context_signals(raw: &str, identifier: Option<&str>, token: &str) -> (Vec<&'static str>, u8) {
    let mut signals = Vec::new();
    let mut score = 0u8;
    let lower = raw.to_lowercase();

    if lower.contains("authorization") || lower.contains("bearer ") {
        signals.push("auth-header");
        score = score.saturating_add(3);
    }
    if lower.contains("x-") || lower.contains("-h ") || lower.contains("header") {
        signals.push("header");
        score = score.saturating_add(2);
    }
    if lower.contains("api_key") || lower.contains("apikey") || lower.contains("secret") || lower.contains("token") {
        signals.push("secret-keyword");
        score = score.saturating_add(2);
    }
    if lower.contains("password") || lower.contains("passwd") || lower.contains("pwd") {
        signals.push("password");
        score = score.saturating_add(2);
    }
    if lower.contains("?" ) && lower.contains("=") {
        signals.push("url-param");
        score = score.saturating_add(1);
    }
    if let Some(id) = identifier {
        let id_l = id.to_lowercase();
        if id_l.contains("key") || id_l.contains("token") || id_l.contains("secret") || id_l.contains("pass") {
            signals.push("id-hint");
            score = score.saturating_add(2);
        }
    }
    if is_jwt_like(token) {
        signals.push("jwt");
        score = score.saturating_add(3);
    } else if is_base64_like(token) || is_base64url_like(token) {
        signals.push("b64");
        score = score.saturating_add(1);
    }

    (signals, score.min(10))
}

