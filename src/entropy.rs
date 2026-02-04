use base64::{engine::general_purpose, Engine as _};
use memchr;
use memchr::memmem;
use log::info;
use std::collections::HashSet;
use std::fmt::Write as FmtWrite;
use std::path::Path;

use crate::output::MatchRecord;
use crate::heuristics::{analyze_flow_context_with_mode, format_context_graph, format_flow_compact, is_likely_code_for_path, FlowMode};
use crate::utils::{find_preceding_identifier, format_prettified_with_hint, LineFilter};

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
    line_filter: Option<&LineFilter>,
    request_trace: bool,
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
    let mut candidates: Vec<CandidatePos> = Vec::new();

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

                            if let Some(filter) = line_filter {
                                if !filter.allows(line) {
                                    continue;
                                }
                            }

                            let _ = write!(
                                out,
                                "{}[L:{} C:{} Tag:{}] ",
                                "[".dimmed(),
                                line.bright_magenta(),
                                col.bright_blue(),
                                "url".bright_yellow().bold()
                            );
                            let _ = writeln!(out, "{}", "URL_CONTEXT".cyan().bold());

                            let pretty = format_prettified_with_hint(&raw_context, &snippet_str, Some(source_label));
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

                    if let Some(filter) = line_filter {
                        if !filter.allows(line) {
                            continue;
                        }
                    }

                    let identifier = find_preceding_identifier(bytes, start);
                    candidates.push(CandidatePos { start, line, col });

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

                    let pretty = format_prettified_with_hint(&raw_context, &snippet_str, Some(source_label));
                    let _ = writeln!(out, "{}", pretty);

                    let flow = if flow_mode != FlowMode::Off {
                        analyze_flow_context_with_mode(bytes, start, flow_mode)
                    } else {
                        None
                    };

                    if deep_scan {
                        let (count, nearest) = repeat_stats(bytes, candidate_bytes, start);
                        let shape = token_shape_hints(&snippet_str);
                        let shape_str = if shape.is_empty() {
                            "shape n/a".to_string()
                        } else {
                            format!("shape {}", shape.join(","))
                        };
                        let type_str = token_type_hint_with_context(&snippet_str, &raw_context)
                            .map(|t| format!("type {}", t))
                            .unwrap_or_else(|| "type n/a".to_string());
                        let (alpha_pct, digit_pct, other_pct) = composition_percentages(&snippet_str);
                        let id_hint = identifier
                            .as_deref()
                            .map(|id| format!("; id {}", id))
                            .unwrap_or_default();
                        let (signals, confidence) = context_signals(&raw_context, identifier.as_deref(), &snippet_str, score, source_label);
                        let sink_hint = sink_provenance_hint(&raw_context);
                        let sink_str = sink_hint
                            .as_deref()
                            .map(|s| format!("; sink {}", s))
                            .unwrap_or_default();
                        let tension = surface_tension_hint(bytes, start, i, score, threshold);
                        let tension_str = tension
                            .as_deref()
                            .map(|t| format!("; tension {}", t))
                            .unwrap_or_default();
                        let signals_str = if signals.is_empty() {
                            "signals n/a".to_string()
                        } else {
                            format!("signals {}", signals.join(","))
                        };
                        let _ = writeln!(
                            out,
                            "{} appears {} times; nearest repeat {} bytes away; len {}; {}; {}; mix a{}% d{}% s{}%; {}; conf {}/10{}{}{}",
                            "Story:".bright_green().bold(),
                            count.to_string().bright_yellow(),
                            nearest
                                .map(|d| d.to_string())
                                .unwrap_or_else(|| "n/a".to_string())
                                .bright_yellow(),
                            snippet_str.len().to_string().bright_yellow(),
                            shape_str.bright_cyan(),
                            type_str.bright_cyan(),
                            alpha_pct.to_string().bright_magenta(),
                            digit_pct.to_string().bright_magenta(),
                            other_pct.to_string().bright_magenta(),
                            signals_str.bright_blue(),
                            confidence.to_string().bright_red(),
                            sink_str,
                            tension_str,
                            id_hint
                        );
                        let owner = preferred_owner_identifier(identifier.as_deref(), &raw_context, &snippet_str);
                        if let Some(flow) = flow.as_ref() {
                            if let Some(lines) = format_context_graph(flow, owner.as_deref()) {
                                let _ = writeln!(out, "{}", "Context:".bright_cyan().bold());
                                for line in lines {
                                    let styled = style_context_line(&line);
                                    let _ = writeln!(out, "{}", styled);
                                }
                            }
                        }
                    }

                    if request_trace {
                        if let Some(lines) = request_trace_lines(&raw_context) {
                            let _ = writeln!(out, "{}", "Request:".bright_cyan().bold());
                            for line in lines {
                                let _ = writeln!(out, "{}", line);
                            }
                        }
                    }

                    if let Some(flow) = flow.as_ref() {
                        if let Some(line) = format_flow_compact(flow) {
                            let _ = writeln!(out, "{} {}", "Flow:".bright_magenta().bold(), line.bright_cyan());
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

    if deep_scan && !candidates.is_empty() {
        let mut clusters = cluster_candidates(&mut candidates);
        if !clusters.is_empty() {
            clusters.sort_by(|a, b| b.size.cmp(&a.size));
            ensure_header(&mut out);
            let max_size = clusters.first().map(|c| c.size).unwrap_or(0);
            let _ = writeln!(
                out,
                "Cluster: {} clusters; largest {}",
                clusters.len(),
                max_size
            );
            for cluster in clusters.iter().take(3) {
                let _ = writeln!(
                    out,
                    "  • L{}:C{} → L{}:C{} ({} hits)",
                    cluster.start_line,
                    cluster.start_col,
                    cluster.end_line,
                    cluster.end_col,
                    cluster.size
                );
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

pub fn scan_for_requests(
    source_label: &str,
    bytes: &[u8],
    context_size: usize,
    flow_mode: FlowMode,
    line_filter: Option<&LineFilter>,
    source_path: Option<&Path>,
) -> (String, Vec<MatchRecord>) {
    use owo_colors::OwoColorize;

    let mut out = String::new();
    let mut records: Vec<MatchRecord> = Vec::new();
    let mut header_written = false;
    let mut obf_emitted = false;
    let obf_signatures = detect_obfuscation_signatures(bytes);

    if let Some(path) = source_path {
        if path_has_component(path, ".git") {
            return (out, records);
        }
        if !is_likely_code_for_path(path, bytes) {
            return (out, records);
        }
    }

    let mut ensure_header = |buffer: &mut String, records: &mut Vec<MatchRecord>| {
        if !header_written {
            let _ = writeln!(
                buffer,
                "\n🌐 Request tracing {}...",
                source_label.cyan()
            );
            let _ = writeln!(buffer, "{}", "━".repeat(60).dimmed());
            header_written = true;
        }
        if !obf_emitted && !obf_signatures.is_empty() {
            let _ = writeln!(
                buffer,
                "{} {}",
                "Obfuscation:".bright_cyan().bold(),
                obf_signatures.join(", ").bright_magenta()
            );
            for sig in &obf_signatures {
                records.push(MatchRecord {
                    source: source_label.to_string(),
                    kind: "obfuscation-signature".to_string(),
                    matched: sig.clone(),
                    line: 0,
                    col: 0,
                    entropy: None,
                    context: "request-trace".to_string(),
                    identifier: None,
                });
            }
            obf_emitted = true;
        }
    };

    let patterns: &[(&[u8], &str)] = &[
        (b"fetch(", "fetch"),
        (b"axios.", "axios"),
        (b"XMLHttpRequest", "xhr"),
        (b".open(", "xhr"),
        (b"http://", "http"),
        (b"https://", "http"),
    ];

    let mut hits: Vec<(usize, &str)> = Vec::new();
    let mut seen = HashSet::new();
    for (pat, label) in patterns {
        for pos in memmem::find_iter(bytes, pat) {
            if seen.insert(pos) {
                hits.push((pos, *label));
            }
        }
    }

    hits.sort_by_key(|(p, _)| *p);
    hits.truncate(50);

    for (pos, label) in hits {
        let preceding = &bytes[..pos];
        let line = memchr::memchr_iter(b'\n', preceding).count() + 1;
        let last_nl = preceding.iter().rposition(|&b| b == b'\n').unwrap_or(0);
        let col = if last_nl == 0 { pos } else { pos - last_nl };

        if let Some(filter) = line_filter {
            if !filter.allows(line) {
                continue;
            }
        }

        let start = pos.saturating_sub(context_size);
        let end = (pos + context_size).min(bytes.len());
        let raw_snippet = String::from_utf8_lossy(&bytes[start..end]);

        if label == "http" && !has_request_token(&raw_snippet) {
            continue;
        }

        if let Some(lines) = request_trace_lines(&raw_snippet) {
            ensure_header(&mut out, &mut records);
            let _ = writeln!(
                out,
                "{}[L:{} C:{} Request:{}]{}",
                "[".dimmed(),
                line.bright_magenta(),
                col.bright_blue(),
                label.bright_yellow().bold(),
                "]".dimmed()
            );

            let pretty = format_prettified_with_hint(&raw_snippet, label, Some(source_label));
            let _ = writeln!(out, "{}", pretty);

            let _ = writeln!(out, "{}", "Request:".bright_cyan().bold());
            for line in lines {
                let _ = writeln!(out, "{}", line);
            }

            let flow = if flow_mode != FlowMode::Off {
                analyze_flow_context_with_mode(bytes, pos, flow_mode)
            } else {
                None
            };

            if let Some(flow) = flow.as_ref() {
                if let Some(lines) = format_context_graph(flow, None) {
                    let _ = writeln!(out, "{}", "Context:".bright_cyan().bold());
                    for line in lines {
                        let styled = style_context_line(&line);
                        let _ = writeln!(out, "{}", styled);
                    }
                }
            }

            if let Some(flow) = flow.as_ref() {
                if let Some(line) = format_flow_compact(flow) {
                    let _ = writeln!(out, "{} {}", "Flow:".bright_magenta().bold(), line.bright_cyan());
                }
            }

            let _ = writeln!(out, "{}", "─".repeat(40).dimmed());

            records.push(MatchRecord {
                source: source_label.to_string(),
                kind: "request-trace".to_string(),
                matched: label.to_string(),
                line,
                col,
                entropy: None,
                context: raw_snippet.to_string(),
                identifier: None,
            });
        }
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

struct CandidatePos {
    start: usize,
    line: usize,
    col: usize,
}

struct Cluster {
    size: usize,
    start_line: usize,
    start_col: usize,
    end_line: usize,
    end_col: usize,
}

fn cluster_candidates(cands: &mut Vec<CandidatePos>) -> Vec<Cluster> {
    const WINDOW: usize = 128;
    cands.sort_by(|a, b| a.start.cmp(&b.start));
    let mut clusters = Vec::new();
    let mut current: Vec<&CandidatePos> = Vec::new();

    for cand in cands.iter() {
        if let Some(last) = current.last() {
            if cand.start.saturating_sub(last.start) <= WINDOW {
                current.push(cand);
                continue;
            }
            if current.len() >= 2 {
                clusters.push(build_cluster(&current));
            }
            current.clear();
        }
        current.push(cand);
    }

    if current.len() >= 2 {
        clusters.push(build_cluster(&current));
    }

    clusters
}

fn build_cluster(group: &[&CandidatePos]) -> Cluster {
    let first = group.first().unwrap();
    let last = group.last().unwrap();
    Cluster {
        size: group.len(),
        start_line: first.line,
        start_col: first.col,
        end_line: last.line,
        end_col: last.col,
    }
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

fn token_type_hint(token: &str) -> Option<&'static str> {
    if token.starts_with("AKIA") && token.len() >= 20 {
        return Some("aws-access-key-id");
    }
    if token.starts_with("ASIA") && token.len() >= 20 {
        return Some("aws-temp-key-id");
    }
    if token.starts_with("ghp_") || token.starts_with("gho_") || token.starts_with("ghu_") {
        return Some("github-pat");
    }
    if token.starts_with("xoxb-") || token.starts_with("xoxa-") || token.starts_with("xoxp-") {
        return Some("slack-token");
    }
    if token.starts_with("sk_live_") || token.starts_with("rk_live_") {
        return Some("stripe-key");
    }
    if is_jwt_like(token) {
        return Some("jwt");
    }
    if is_uuid_like(token) {
        return Some("uuid");
    }
    if is_hex_like(token) {
        return Some("hex");
    }
    if is_base64url_like(token) {
        return Some("base64url");
    }
    if is_base64_like(token) {
        return Some("base64");
    }
    None
}

fn token_type_hint_with_context(token: &str, context: &str) -> Option<&'static str> {
    if is_telegram_bot_token_context(token, context) {
        return Some("telegram-bot-token");
    }
    token_type_hint(token)
}

fn context_signals(raw: &str, identifier: Option<&str>, token: &str, entropy: f64, source_label: &str) -> (Vec<&'static str>, u8) {
    adaptive_confidence_entropy(raw, identifier, token, entropy, source_label)
}

pub fn adaptive_confidence_entropy(
    raw: &str,
    identifier: Option<&str>,
    token: &str,
    entropy: f64,
    source_label: &str,
) -> (Vec<&'static str>, u8) {
    let mut signals = Vec::new();
    let mut score: i32 = 0;
    let lower = raw.to_lowercase();
    let source = source_label.to_lowercase();

    if lower.contains("authorization") || lower.contains("bearer ") {
        signals.push("auth-header");
        score += 3;
    }
    if lower.contains("x-") || lower.contains("-h ") || lower.contains("header") {
        signals.push("header");
        score += 2;
    }
    if lower.contains("api_key") || lower.contains("apikey") || lower.contains("secret") || lower.contains("token") {
        signals.push("secret-keyword");
        score += 2;
    }
    if lower.contains("password") || lower.contains("passwd") || lower.contains("pwd") {
        signals.push("password");
        score += 2;
    }
    if lower.contains("?") && lower.contains("=") {
        signals.push("url-param");
        score += 1;
    }
    if let Some(id) = identifier {
        let id_l = id.to_lowercase();
        if id_l.contains("key") || id_l.contains("token") || id_l.contains("secret") || id_l.contains("pass") {
            signals.push("id-hint");
            score += 2;
        }
    }

    if let Some(t) = token_type_hint_with_context(token, raw) {
        signals.push("typed");
        score += 2;
        if matches!(t, "aws-access-key-id" | "aws-temp-key-id" | "github-pat" | "stripe-key" | "telegram-bot-token" | "jwt") {
            signals.push("high-value-type");
            score += 2;
        }
    } else if is_base64_like(token) || is_base64url_like(token) {
        signals.push("b64");
        score += 1;
    }

    if is_telegram_bot_token_context(token, raw) {
        signals.push("telegram");
        score += 3;
    }

    if entropy >= 5.5 {
        signals.push("high-entropy");
        score += 3;
    } else if entropy >= 5.0 {
        signals.push("entropy");
        score += 2;
    } else if entropy < 4.7 {
        signals.push("low-entropy");
        score -= 1;
    }

    if token.len() >= 40 {
        signals.push("long-token");
        score += 1;
    } else if token.len() < 20 {
        signals.push("short-token");
        score -= 1;
    }

    let doc_words = ["example", "sample", "demo", "test", "placeholder", "dummy", "mock", "lorem"];
    if doc_words.iter().any(|w| lower.contains(w)) || source.contains("/docs") || source.contains("/examples") || source.contains("/test") {
        signals.push("doc-context");
        score -= 2;
    }

    let infra_words = ["/infra", "/k8s", "/kubernetes", "/terraform", "/helm", "/deploy", "/ops", "/ansible"]; 
    if infra_words.iter().any(|w| source.contains(w)) {
        signals.push("infra-context");
        score += 2;
    }
    if lower.contains("localhost") || lower.contains("127.0.0.1") {
        signals.push("dev-context");
        score -= 1;
    }

    let confidence = score.clamp(1, 10) as u8;
    (signals, confidence)
}

fn is_telegram_bot_token_context(token: &str, context: &str) -> bool {
    if token.len() < 30 || token.len() > 64 {
        return false;
    }
    let bytes = context.as_bytes();
    let mut start = 0usize;
    while let Some(idx) = context[start..].find(token) {
        let pos = start + idx;
        if pos > 0 && bytes[pos - 1] == b':' {
            let mut i = pos - 1;
            let mut digits = 0usize;
            while i > 0 {
                i -= 1;
                let b = bytes[i];
                if b.is_ascii_digit() {
                    digits += 1;
                    continue;
                }
                break;
            }
            if digits >= 6 && digits <= 12 {
                return true;
            }
        }
        start = pos + token.len();
    }
    false
}

fn preferred_owner_identifier(
    identifier: Option<&str>,
    context: &str,
    token: &str,
) -> Option<String> {
    if let Some(id) = identifier {
        if !id.chars().all(|c| c.is_ascii_digit()) {
            return Some(id.to_string());
        }
    }

    if is_telegram_bot_token_context(token, context) {
        if let Some(assign) = find_assignment_lhs(context) {
            return Some(assign);
        }
    }

    None
}

pub(crate) fn request_trace_lines(raw: &str) -> Option<Vec<String>> {
    use owo_colors::OwoColorize;

    let mut parts = extract_request_candidates(raw);
    if parts.is_empty() {
        return None;
    }

    if !has_strong_request_signal(&parts, raw) {
        return None;
    }

    parts.retain(|p| request_strength(p) > 0);
    if parts.is_empty() {
        return None;
    }

    parts.sort_by_key(|p| std::cmp::Reverse(request_strength(p)));
    let mut deduped: Vec<RequestParts> = Vec::new();
    let mut seen = HashSet::new();
    for part in parts {
        let key = request_key(&part);
        if seen.insert(key) {
            deduped.push(part);
        }
        if deduped.len() >= 3 {
            break;
        }
    }

    if deduped.is_empty() {
        return None;
    }

    let mut lines = Vec::new();
    deduped.truncate(2);
    for (idx, part) in deduped.into_iter().enumerate() {
        lines.push(format!(
            "  • {} {}",
            format!("request #{}", idx + 1).bright_magenta(),
            part.source.bright_white()
        ));

        let method = part
            .method
            .as_ref()
            .cloned()
            .or_else(|| if part.body.is_some() { Some("POST".to_string()) } else { None });

        if let Some(m) = method {
            lines.push(format!("    {} {}", "method".bright_magenta(), m.bright_white()));
        }
        if let Some(u) = part.url.as_ref().or_else(|| part.url_hint.as_ref()) {
            lines.push(format!("    {} {}", "url".bright_magenta(), u.bright_white()));
        }

        if !part.headers.is_empty() {
            lines.push(format!(
                "    {} {}",
                "headers".bright_magenta(),
                part.headers.join(", ").bright_white()
            ));
        }
        if let Some(b) = part.body.as_ref() {
            lines.push(format!("    {} {}", "body".bright_magenta(), b.bright_white()));
        }

        let warnings = intent_consistency_warnings(&part, raw);
        for warning in warnings {
            lines.push(format!(
                "    {} {}",
                "intent".bright_magenta(),
                warning.bright_yellow()
            ));
        }
    }

    Some(lines)
}

struct RequestParts {
    source: &'static str,
    method: Option<String>,
    url: Option<String>,
    url_hint: Option<String>,
    headers: Vec<String>,
    body: Option<String>,
}

fn intent_consistency_warnings(part: &RequestParts, raw: &str) -> Vec<String> {
    let mut warnings = Vec::new();
    let scope = intent_scope(raw);

    let method = part
        .method
        .clone()
        .or_else(|| if part.body.is_some() { Some("POST".to_string()) } else { None })
        .unwrap_or_default()
        .to_uppercase();

    if method.is_empty() {
        return warnings;
    }

    let read_intent = contains_intent_word(&scope, &["get", "list", "read", "load", "query", "search"]);
    let create_intent = contains_intent_word(&scope, &["create", "add", "new", "insert", "register", "signup", "provision"]);
    let update_intent = contains_intent_word(&scope, &["update", "edit", "set", "patch", "put", "save", "write", "modify"]);
    let delete_intent = contains_intent_word(&scope, &["delete", "remove", "destroy", "revoke", "purge", "drop"]);
    let write_intent = create_intent || update_intent || delete_intent;

    if method == "GET" && part.body.is_some() {
        warnings.push("GET with body present".to_string());
    }

    if method == "GET" && write_intent {
        warnings.push("GET with write intent".to_string());
    }

    if method != "GET" && method != "HEAD" && read_intent && !write_intent {
        warnings.push(format!("{} with read intent", method));
    }

    warnings
}

fn intent_scope(raw: &str) -> String {
    let mut parts = Vec::new();
    if let Some(name) = extract_function_name(raw) {
        parts.push(name);
    }
    if let Some(line) = extract_request_line(raw) {
        parts.push(line);
    }

    if parts.is_empty() {
        return raw.to_lowercase();
    }

    parts.join(" ").to_lowercase()
}

fn extract_request_line(raw: &str) -> Option<String> {
    let lower = raw.to_lowercase();
    let tokens = [
        "fetch(",
        "requests.",
        "httpx.",
        "axios",
        "xmlhttprequest",
        ".open(",
    ];
    let mut best: Option<usize> = None;
    for token in tokens.iter() {
        if let Some(pos) = lower.find(token) {
            best = Some(best.map(|b| b.min(pos)).unwrap_or(pos));
        }
    }

    let pos = best?;
    let line_start = raw[..pos].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let line_end = raw[pos..]
        .find('\n')
        .map(|i| pos + i)
        .unwrap_or(raw.len());
    Some(raw[line_start..line_end].to_string())
}

fn extract_function_name(raw: &str) -> Option<String> {
    let lower = raw.to_lowercase();
    let patterns = ["function ", "def ", "fn "];
    for pat in patterns.iter() {
        if let Some(idx) = lower.find(pat) {
            let start = idx + pat.len();
            let slice = &raw[start..];
            let mut name = String::new();
            let mut started = false;
            for ch in slice.chars() {
                if !started && (ch.is_whitespace() || ch == '*') {
                    continue;
                }
                started = true;
                if ch.is_ascii_alphanumeric() || ch == '_' || ch == '$' {
                    name.push(ch);
                } else {
                    break;
                }
            }
            if !name.is_empty() {
                return Some(name);
            }
        }
    }
    None
}

fn contains_intent_word(haystack: &str, needles: &[&str]) -> bool {
    for needle in needles {
        let mut idx = 0usize;
        while let Some(pos) = haystack[idx..].find(needle) {
            let start = idx + pos;
            let end = start + needle.len();
            let before = haystack[..start].chars().last();
            let after = haystack[end..].chars().next();

            let before_ok = before
                .map(|c| !c.is_ascii_alphanumeric() && c != '_')
                .unwrap_or(true);
            let after_ok = after
                .map(|c| !c.is_ascii_alphanumeric() || c == '_' || c.is_ascii_uppercase())
                .unwrap_or(true);

            if before_ok && after_ok {
                return true;
            }
            idx = end;
        }
    }
    false
}

fn has_strong_request_signal(parts: &[RequestParts], raw: &str) -> bool {
    for part in parts {
        if part.source != "url-literal" && part.source != "heuristic" {
            return true;
        }
        if part.method.is_some()
            || part.body.is_some()
            || !part.headers.is_empty()
            || part.url_hint.is_some()
        {
            return true;
        }
    }
    has_request_token(raw)
}

fn request_strength(part: &RequestParts) -> u8 {
    let mut score = 0u8;
    if part.source != "url-literal" {
        score += 1;
    }
    if part.method.is_some() {
        score += 2;
    }
    if !part.headers.is_empty() {
        score += 2;
    }
    if part.body.is_some() {
        score += 2;
    }
    if part.url_hint.is_some() {
        score += 1;
    }
    score
}

fn request_key(part: &RequestParts) -> String {
    if let Some(url) = part.url.as_ref() {
        return normalize_url_key(url);
    }
    if let Some(hint) = part.url_hint.as_ref() {
        return normalize_url_key(hint);
    }
    part.source.to_string()
}

fn normalize_url_key(raw: &str) -> String {
    raw.chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .trim_matches(|c: char| c == ')' || c == ';' || c == ',' || c == '`')
        .to_string()
}

fn has_request_token(raw: &str) -> bool {
    let lower = raw.to_lowercase();
    lower.contains("fetch(")
        || lower.contains("axios.")
        || lower.contains("xmlhttprequest")
        || lower.contains(".open(")
        || lower.contains("curl ")
        || lower.contains("requests.")
        || lower.contains("httpx.")
        || lower.contains("got(")
        || lower.contains("ky(")
        || lower.contains("$.ajax")
        || lower.contains("jQuery.ajax")
        || lower.contains("$.get")
        || lower.contains("$.post")
        || lower.contains("new request(")
        || lower.contains("send(")
        || lower.contains("method:")
        || lower.contains("headers:")
        || lower.contains("body:")
}

fn path_has_component(path: &Path, target: &str) -> bool {
    path.components().any(|c| c.as_os_str() == target)
}

pub(crate) fn sink_provenance_hint(raw: &str) -> Option<String> {
    let lower = raw.to_lowercase();

    let network = [
        "fetch(",
        "axios",
        "requests.",
        "httpx.",
        "xmlhttprequest",
        ".open(",
        "curl ",
        "send(",
    ];
    let disk = [
        "fs::write",
        "write_file",
        "write_to",
        "file::create",
        "file::open",
        "open(",
        "save(",
        "write_all",
        "to_file",
    ];
    let log = [
        "console.log",
        "println!",
        "print(",
        "log::",
        "logger",
        "warn(",
        "error(",
        "debug(",
    ];

    if network.iter().any(|t| lower.contains(t)) {
        return Some("network".to_string());
    }
    if disk.iter().any(|t| lower.contains(t)) {
        return Some("disk".to_string());
    }
    if log.iter().any(|t| lower.contains(t)) {
        return Some("log".to_string());
    }

    None
}

pub(crate) fn surface_tension_hint(
    bytes: &[u8],
    start: usize,
    end: usize,
    candidate_entropy: f64,
    threshold: f64,
) -> Option<String> {
    let window = 48usize;
    let min_len = 16usize;
    let left_start = start.saturating_sub(window);
    let left = &bytes[left_start..start];
    let right_end = (end + window).min(bytes.len());
    let right = &bytes[end..right_end];

    let mut neighbor_scores = Vec::new();
    if left.len() >= min_len {
        neighbor_scores.push(calculate_entropy(left));
    }
    if right.len() >= min_len {
        neighbor_scores.push(calculate_entropy(right));
    }
    if neighbor_scores.is_empty() {
        return None;
    }

    let avg = neighbor_scores.iter().sum::<f64>() / neighbor_scores.len() as f64;
    let delta = (candidate_entropy - avg).abs();

    let high_neighbor = avg >= (threshold - 0.4).max(3.5);
    let low_neighbor = avg <= (threshold - 1.2).max(2.5);

    if high_neighbor && delta <= 0.6 {
        return Some("layered-obfuscation".to_string());
    }
    if low_neighbor && candidate_entropy >= threshold + 0.6 {
        return Some("isolated-secret".to_string());
    }
    None
}

pub(crate) fn detect_obfuscation_signatures(bytes: &[u8]) -> Vec<String> {
    let raw = String::from_utf8_lossy(bytes);
    let lower = raw.to_lowercase();
    let mut out = Vec::new();

    let patterns = [
        ("eval(function(p,a,c,k,e,d)", "packer-eval"),
        ("javascript:eval", "eval-uri"),
        ("atob(", "base64-decode"),
        ("fromcharcode", "charcode"),
        ("string.fromcharcode", "charcode"),
        ("unescape(", "unescape"),
        ("decodeuricomponent(", "uri-decode"),
        ("window[\"atob\"]", "atob-indirect"),
    ];

    for (pat, label) in patterns {
        if lower.contains(pat) {
            out.push(label.to_string());
        }
    }

    if raw.lines().any(|l| l.len() > 1500) {
        out.push("minified-line".to_string());
    }

    out.sort();
    out.dedup();
    out
}

fn extract_request_candidates(raw: &str) -> Vec<RequestParts> {
    let mut out = Vec::new();
    if let Some(p) = parse_request_parts(raw) {
        out.push(p);
    }
    if let Some(p) = parse_request_parts_fetch(raw) {
        out.push(p);
    }
    if let Some(p) = parse_request_parts_axios(raw) {
        out.push(p);
    }
    if let Some(p) = parse_request_parts_requests(raw) {
        out.push(p);
    }
    if let Some(p) = parse_request_parts_heuristic(raw) {
        out.push(p);
    }

    out.extend(parse_url_requests(raw));

    let mut seen = HashSet::new();
    out.retain(|p| {
        if p.url.is_none() && p.url_hint.is_none() {
            return false;
        }
        let key = format!("{}:{}", p.source, p.url.clone().unwrap_or_default());
        if seen.contains(&key) {
            false
        } else {
            seen.insert(key);
            true
        }
    });
    out
}

fn parse_request_parts(raw: &str) -> Option<RequestParts> {
    let mut method = None;
    let mut url = None;
    let mut headers = Vec::new();
    let mut body = None;
    let curl = extract_curl_block(raw)?;

    for line in curl.lines() {
        let l = line.trim();
        if let Some(m) = extract_curl_method(l) {
            method = Some(m);
        }
        if let Some(u) = extract_curl_url(l) {
            url = Some(u);
        }
        if let Some(h) = extract_curl_header(l) {
            headers.push(h);
        }
        if let Some(b) = extract_curl_body(l) {
            body = Some(b);
        }
    }

    headers.sort();
    headers.dedup();
    headers.truncate(6);

    Some(RequestParts {
        source: "curl",
        method,
        url,
        url_hint: None,
        headers,
        body,
    })
}

fn parse_request_parts_fetch(raw: &str) -> Option<RequestParts> {
    let idx = raw.find("fetch(")?;
    let url = extract_quoted(raw, idx + 6);
    let url_hint = if url.is_none() {
        extract_first_arg_token(raw, idx + 6)
    } else {
        None
    };
    if url.is_none() && url_hint.is_none() {
        return None;
    }
    let mut method = extract_method(raw);
    if method.is_none() && raw.contains("method") {
        method = extract_method(raw);
    }
    let headers = extract_headers_block(raw, "headers");
    let body = if raw.contains("body") {
        extract_body_keys(raw).or(Some("present".to_string()))
    } else {
        None
    };
    Some(RequestParts {
        source: "fetch",
        method,
        url,
        url_hint,
        headers,
        body,
    })
}

fn parse_request_parts_axios(raw: &str) -> Option<RequestParts> {
    let idx = raw.find("axios.")?;
    let rest = &raw[idx + 6..];
    let method = rest.split('(').next().map(|m| m.to_uppercase());
    let url = extract_quoted(rest, 0);
    let url_hint = if url.is_none() {
        if let Some(paren) = rest.find('(') {
            extract_first_arg_token(rest, paren + 1)
        } else {
            None
        }
    } else {
        None
    };
    if url.is_none() && url_hint.is_none() {
        return None;
    }
    Some(RequestParts {
        source: "axios",
        method,
        url,
        url_hint,
        headers: extract_headers_block(raw, "headers"),
        body: if raw.contains("data") {
            extract_body_keys(raw).or(Some("present".to_string()))
        } else {
            None
        },
    })
}

fn parse_request_parts_requests(raw: &str) -> Option<RequestParts> {
    let idx = raw.find("requests.")?;
    let rest = &raw[idx + 9..];
    let method = rest.split('(').next().map(|m| m.to_uppercase());
    let url = extract_quoted(rest, 0);
    let url_hint = if url.is_none() {
        if let Some(paren) = rest.find('(') {
            extract_first_arg_token(rest, paren + 1)
        } else {
            None
        }
    } else {
        None
    };
    if url.is_none() && url_hint.is_none() {
        return None;
    }
    Some(RequestParts {
        source: "requests",
        method,
        url,
        url_hint,
        headers: extract_headers_block(raw, "headers"),
        body: if raw.contains("data") || raw.contains("json=") {
            extract_body_keys(raw).or(Some("present".to_string()))
        } else {
            None
        },
    })
}

fn parse_request_parts_heuristic(raw: &str) -> Option<RequestParts> {
    let url = extract_url(raw);
    if url.is_none() {
        return None;
    }
    let method = extract_method(raw);
    let headers = extract_headers(raw);
    let body = extract_body_hint(raw);

    Some(RequestParts {
        source: "heuristic",
        method,
        url,
        url_hint: None,
        headers,
        body,
    })
}

fn parse_url_requests(raw: &str) -> Vec<RequestParts> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while let Some(idx) = raw[cursor..].find("http") {
        let pos = cursor + idx;
        if raw[pos..].starts_with("http://") || raw[pos..].starts_with("https://") {
            let window_start = pos.saturating_sub(200);
            let window_end = (pos + 200).min(raw.len());
            let window = &raw[window_start..window_end];
            let (url, url_hint) = extract_url_or_hint_from_window(window)
                .unwrap_or_else(|| (Some(read_url_from(raw, pos)), None));
            let method = extract_method_from_window(window);
            let headers = extract_headers_from_window(window);
            let body = extract_body_keys(window).or_else(|| extract_body_hint(window));
            let source = if window.contains("fetch(") {
                "fetch"
            } else if window.contains("axios") {
                "axios"
            } else if window.contains("XMLHttpRequest") || window.contains(".open(") {
                "xhr"
            } else {
                "url-literal"
            };
            out.push(RequestParts {
                source,
                method,
                url,
                url_hint,
                headers,
                body,
            });
        }
        cursor = pos + 4;
    }
    out
}

fn extract_method(raw: &str) -> Option<String> {
    for m in ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"] {
        if raw.contains(m) {
            return Some(m.to_string());
        }
    }
    if raw.contains("method") {
        for m in ["get", "post", "put", "patch", "delete"] {
            if raw.to_lowercase().contains(m) {
                return Some(m.to_uppercase());
            }
        }
    }
    None
}

fn extract_url(raw: &str) -> Option<String> {
    if let Some(idx) = raw.find("http://") {
        return Some(read_url_from(raw, idx));
    }
    if let Some(idx) = raw.find("https://") {
        return Some(read_url_from(raw, idx));
    }
    if let Some(idx) = raw.find("fetch(") {
        if let Some(u) = extract_quoted(raw, idx + 6) {
            return Some(u);
        }
    }
    None
}

fn extract_url_or_hint_from_window(raw: &str) -> Option<(Option<String>, Option<String>)> {
    if let Some(tpl) = extract_template_url(raw) {
        return Some((Some(tpl), None));
    }
    if let Some(concat) = extract_concat_url(raw) {
        return Some((Some(concat), None));
    }
    if let Some(decoded) = extract_base64_url(raw) {
        return Some((Some(decoded), None));
    }
    if let Some(idx) = raw.find("http://") {
        return Some((Some(read_url_from(raw, idx)), None));
    }
    if let Some(idx) = raw.find("https://") {
        return Some((Some(read_url_from(raw, idx)), None));
    }
    if let Some(hint) = extract_xhr_url_hint(raw) {
        return Some((None, Some(hint)));
    }
    if let Some(idx) = raw.find("fetch(") {
        if let Some(hint) = extract_first_arg_token(raw, idx + 6) {
            return Some((None, Some(hint)));
        }
    }
    None
}

fn read_url_from(raw: &str, idx: usize) -> String {
    let bytes = raw.as_bytes();
    let mut end = idx;
    while end < bytes.len() {
        let b = bytes[end];
        if b.is_ascii_whitespace() || b == b'\'' || b == b'"' || b == b')' {
            break;
        }
        end += 1;
    }
    raw[idx..end].to_string()
}

fn extract_first_arg_token(raw: &str, start: usize) -> Option<String> {
    let bytes = raw.as_bytes();
    let mut i = start.min(bytes.len());
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= bytes.len() {
        return None;
    }
    if bytes[i] == b'\'' || bytes[i] == b'"' {
        return extract_quoted(raw, i);
    }
    let mut end = i;
    while end < bytes.len() {
        let b = bytes[end];
        if b == b',' || b == b')' || b == b'\n' || b == b'\r' {
            break;
        }
        if b.is_ascii_whitespace() {
            break;
        }
        end += 1;
    }
    if end > i {
        let token = raw[i..end].trim();
        if token.len() <= 64 && !token.is_empty() {
            return Some(token.to_string());
        }
    }
    None
}

fn extract_xhr_url_hint(raw: &str) -> Option<String> {
    let idx = raw.find(".open(")?;
    let after = idx + 6;
    let bytes = raw.as_bytes();
    let mut i = after.min(bytes.len());
    // skip first arg (method)
    let mut commas = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b',' {
            commas += 1;
            i += 1;
            if commas == 1 {
                break;
            }
        } else if b == b')' || b == b'\n' || b == b'\r' {
            break;
        } else {
            i += 1;
        }
    }
    if commas == 1 {
        return extract_first_arg_token(raw, i);
    }
    None
}

fn extract_concat_url(raw: &str) -> Option<String> {
    let bytes = raw.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'\'' || bytes[i] == b'"' {
            let quote = bytes[i];
            let start = i + 1;
            let mut j = start;
            while j < bytes.len() && bytes[j] != quote {
                j += 1;
            }
            if j <= bytes.len() {
                let token = &raw[start..j];
                if token.contains("http://") || token.contains("https://") {
                    let mut out = token.to_string();
                    let mut k = j + 1;
                    let mut parts = 0usize;
                    while k < bytes.len() && parts < 4 {
                        while k < bytes.len() && bytes[k].is_ascii_whitespace() {
                            k += 1;
                        }
                        if k < bytes.len() && bytes[k] == b'+' {
                            k += 1;
                            while k < bytes.len() && bytes[k].is_ascii_whitespace() {
                                k += 1;
                            }
                            if k < bytes.len() && (bytes[k] == b'\'' || bytes[k] == b'"') {
                                let q2 = bytes[k];
                                let s2 = k + 1;
                                let mut e2 = s2;
                                while e2 < bytes.len() && bytes[e2] != q2 {
                                    e2 += 1;
                                }
                                if e2 <= bytes.len() {
                                    out.push_str(&raw[s2..e2]);
                                    k = e2 + 1;
                                    parts += 1;
                                    continue;
                                }
                            }
                        }
                        if raw[k..].starts_with(".concat(") {
                            k += ".concat(".len();
                            while k < bytes.len() && bytes[k].is_ascii_whitespace() {
                                k += 1;
                            }
                            if k < bytes.len() && (bytes[k] == b'\'' || bytes[k] == b'"') {
                                let q2 = bytes[k];
                                let s2 = k + 1;
                                let mut e2 = s2;
                                while e2 < bytes.len() && bytes[e2] != q2 {
                                    e2 += 1;
                                }
                                if e2 <= bytes.len() {
                                    out.push_str(&raw[s2..e2]);
                                    k = e2 + 1;
                                    parts += 1;
                                    continue;
                                }
                            }
                        }
                        break;
                    }
                    return Some(out);
                }
            }
            i = j + 1;
            continue;
        }
        i += 1;
    }
    None
}

fn extract_template_url(raw: &str) -> Option<String> {
    let bytes = raw.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'`' {
            let mut j = i + 1;
            let mut out = String::new();
            while j < bytes.len() {
                if bytes[j] == b'`' {
                    break;
                }
                if bytes[j] == b'$' && j + 1 < bytes.len() && bytes[j + 1] == b'{' {
                    out.push_str("{...}");
                    j += 2;
                    let mut depth = 1usize;
                    while j < bytes.len() && depth > 0 {
                        if bytes[j] == b'{' {
                            depth += 1;
                        } else if bytes[j] == b'}' {
                            depth -= 1;
                        }
                        j += 1;
                    }
                    continue;
                }
                out.push(bytes[j] as char);
                j += 1;
            }
            if out.contains("http://") || out.contains("https://") {
                return Some(out);
            }
            i = j + 1;
            continue;
        }
        i += 1;
    }
    None
}

fn extract_base64_url(raw: &str) -> Option<String> {
    if let Some(idx) = raw.find("atob(") {
        if let Some(b64) = extract_quoted(raw, idx + 5) {
            if let Ok(decoded) = general_purpose::STANDARD.decode(b64.as_bytes()) {
                if let Ok(text) = String::from_utf8(decoded) {
                    if text.starts_with("http://") || text.starts_with("https://") {
                        return Some(text);
                    }
                }
            }
        }
    }
    if let Some(idx) = raw.find("Buffer.from(") {
        if let Some(b64) = extract_quoted(raw, idx + 12) {
            if raw[idx..raw.len().min(idx + 60)].contains("base64") {
                if let Ok(decoded) = general_purpose::STANDARD.decode(b64.as_bytes()) {
                    if let Ok(text) = String::from_utf8(decoded) {
                        if text.starts_with("http://") || text.starts_with("https://") {
                            return Some(text);
                        }
                    }
                }
            }
        }
    }
    None
}

fn extract_quoted(raw: &str, start: usize) -> Option<String> {
    let bytes = raw.as_bytes();
    let mut i = start.min(bytes.len());
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= bytes.len() {
        return None;
    }
    let quote = bytes[i];
    if quote != b'\'' && quote != b'"' {
        return None;
    }
    i += 1;
    let start_q = i;
    while i < bytes.len() && bytes[i] != quote {
        i += 1;
    }
    if i > start_q {
        return Some(raw[start_q..i].to_string());
    }
    None
}

fn extract_headers(raw: &str) -> Vec<String> {
    let mut headers = Vec::new();
    for line in raw.lines() {
        let l = line.trim();
        if let Some(rest) = l.strip_prefix("-H ") {
            if let Some(name) = rest.split(':').next() {
                headers.push(name.trim_matches('"').trim_matches('\'').to_string());
            }
        } else if l.contains(':') && !l.starts_with("http") {
            let name = l.split(':').next().unwrap_or("");
            if name.len() <= 40 && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' ) {
                headers.push(name.to_string());
            }
        }
    }
    headers.sort();
    headers.dedup();
    headers.truncate(4);
    headers
}

fn extract_headers_from_window(raw: &str) -> Vec<String> {
    let mut headers = extract_headers(raw);
    if raw.contains("setRequestHeader") {
        let mut cursor = 0usize;
        while let Some(idx) = raw[cursor..].find("setRequestHeader(") {
            let pos = cursor + idx + "setRequestHeader(".len();
            if let Some(name) = extract_quoted(raw, pos) {
                headers.push(name);
            }
            cursor = pos;
        }
    }
    headers.sort();
    headers.dedup();
    headers.truncate(6);
    headers
}

fn extract_method_from_window(raw: &str) -> Option<String> {
    if let Some(idx) = raw.find(".open(") {
        if let Some(m) = extract_quoted(raw, idx + 6) {
            return Some(m.to_uppercase());
        }
    }
    extract_method(raw)
}

fn extract_headers_block(raw: &str, key: &str) -> Vec<String> {
    let mut out = Vec::new();
    let lower = raw.to_lowercase();
    if let Some(idx) = lower.find(key) {
        let snippet = &raw[idx..raw.len().min(idx + 400)];
        let bytes = snippet.as_bytes();
        let mut i = 0usize;
        while i < bytes.len() {
            if bytes[i] == b'\'' || bytes[i] == b'"' {
                let quote = bytes[i];
                let start = i + 1;
                let mut j = start;
                while j < bytes.len() && bytes[j] != quote {
                    j += 1;
                }
                if j < bytes.len() {
                    let token = &snippet[start..j];
                    let mut k = j + 1;
                    while k < bytes.len() && bytes[k].is_ascii_whitespace() {
                        k += 1;
                    }
                    if k < bytes.len() && bytes[k] == b':' {
                        if looks_like_header_name(token) {
                            out.push(token.to_string());
                        }
                    }
                }
                i = j + 1;
                continue;
            }
            i += 1;
        }
    }
    out.sort();
    out.dedup();
    out.truncate(6);
    out
}

fn looks_like_header_name(name: &str) -> bool {
    let trimmed = name.trim();
    if trimmed.len() < 2 || trimmed.len() > 40 {
        return false;
    }
    let lower = trimmed.to_lowercase();
    let common = [
        "authorization",
        "content-type",
        "accept",
        "user-agent",
        "referer",
        "origin",
        "cookie",
        "x-api-key",
        "x-auth-token",
        "x-csrf-token",
        "x-requested-with",
    ];
    if common.contains(&lower.as_str()) {
        return true;
    }
    if trimmed.starts_with("X-") || trimmed.starts_with("x-") {
        return true;
    }
    trimmed.contains('-')
        && trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
}

fn extract_curl_method(line: &str) -> Option<String> {
    if let Some(idx) = line.find("-X ") {
        let rest = &line[idx + 3..];
        let m = rest.split_whitespace().next()?;
        return Some(m.to_uppercase());
    }
    None
}

fn extract_curl_header(line: &str) -> Option<String> {
    if let Some(idx) = line.find("-H ") {
        let rest = &line[idx + 3..];
        let val = rest.trim_matches('"').trim_matches('\'');
        let name = val.split(':').next()?;
        if !name.is_empty() {
            return Some(name.to_string());
        }
    }
    None
}

fn extract_curl_body(line: &str) -> Option<String> {
    if line.contains("--data") || line.contains("--data-raw") || line.contains("-d ") {
        if let Some(keys) = extract_body_keys(line) {
            return Some(keys);
        }
        return Some("present".to_string());
    }
    None
}

fn extract_curl_url(line: &str) -> Option<String> {
    if let Some(idx) = line.find("http://") {
        return Some(read_url_from(line, idx));
    }
    if let Some(idx) = line.find("https://") {
        return Some(read_url_from(line, idx));
    }
    None
}

fn extract_body_hint(raw: &str) -> Option<String> {
    let lower = raw.to_lowercase();
    if lower.contains("--data") || lower.contains("data:") || lower.contains("body:") {
        if let Some(keys) = extract_body_keys(raw) {
            return Some(keys);
        }
        return Some("present".to_string());
    }
    None
}

fn extract_curl_block(raw: &str) -> Option<String> {
    let mut out = String::new();
    let mut capture = false;
    for line in raw.lines() {
        let l = line.trim_end();
        if l.trim_start().starts_with("curl ") {
            capture = true;
        }
        if capture {
            out.push_str(l.trim_start());
            out.push('\n');
            if !l.ends_with('\\') {
                break;
            }
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn extract_body_keys(raw: &str) -> Option<String> {
    let mut keys = Vec::new();
    for cap in raw.split(|c| c == '"' || c == '\'') {
        if cap.contains(':') {
            let name = cap.split(':').next().unwrap_or("").trim();
            if !name.is_empty() && name.len() <= 30 {
                let lower = name.to_lowercase();
                if lower == "http" || lower == "https" || lower.contains("://") {
                    continue;
                }
                if name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
                    keys.push(name.to_string());
                }
            }
        }
    }
    keys.sort();
    keys.dedup();
    if keys.is_empty() {
        None
    } else {
        keys.truncate(5);
        Some(format!("keys: {}", keys.join(",")))
    }
}

fn style_context_line(line: &str) -> String {
    use owo_colors::OwoColorize;
    if let Some((prefix, rest)) = line.split_once(' ') {
        if prefix == "├─" || prefix == "└─" {
            return format!("{} {}", prefix.bright_cyan(), rest.bright_white());
        }
    }
    line.bright_white().to_string()
}

fn find_assignment_lhs(context: &str) -> Option<String> {
    if let Some(eq_idx) = context.find('=') {
        let left = &context[..eq_idx];
        let mut end = left.len();
        let bytes = left.as_bytes();
        while end > 0 && bytes[end - 1].is_ascii_whitespace() {
            end -= 1;
        }
        let mut start = end;
        while start > 0 {
            let b = bytes[start - 1];
            if b.is_ascii_alphanumeric() || b == b'_' {
                start -= 1;
            } else {
                break;
            }
        }
        if start < end {
            return Some(left[start..end].to_string());
        }
    }
    None
}

