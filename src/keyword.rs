use aho_corasick::AhoCorasick;
use memchr;
use memchr::memmem;
use std::fmt::Write as FmtWrite;
use std::collections::HashMap;

use crate::output::MatchRecord;
use crate::heuristics::{analyze_flow_context_with_mode, format_context_graph, format_flow_compact, FlowMode};
use crate::entropy::{request_trace_lines, sink_provenance_hint};
use crate::utils::{find_preceding_identifier, format_prettified_with_hint, LineFilter};

pub fn process_search(
    bytes: &[u8],
    label: &str,
    keywords: &[String],
    context_size: usize,
    deep_scan: bool,
    flow_mode: FlowMode,
    line_filter: Option<&LineFilter>,
) -> (String, Vec<MatchRecord>) {
    use owo_colors::OwoColorize;

    let mut out = String::new();
    let mut records: Vec<MatchRecord> = Vec::new();

    if keywords.is_empty() {
        return (out, records);
    }

    // Construct Aho-Corasick automaton for keyword matching.
    let ac = match AhoCorasick::new(keywords) {
        Ok(ac) => ac,
        Err(e) => {
            let _ = writeln!(out, "Warning: failed to build Aho-Corasick automaton: {}", e);
            return (out, records);
        }
    };

    // Perform the search first so we can buffer output per-file and avoid interleaving.
    let matches: Vec<_> = ac.find_iter(bytes).collect();

    let word_stats = if deep_scan {
        build_word_stats(bytes, keywords)
    } else {
        HashMap::new()
    };

    if matches.is_empty() {
        return (out, records);
    }

    let _ = writeln!(out, "\n🔍 Scanning {} for {} patterns...", label.cyan(), keywords.len().yellow());
    let _ = writeln!(out, "{}", "━".repeat(60).dimmed());

    for mat in &matches {
        let pos = mat.start();
        let matched_word = &keywords[mat.pattern().as_usize()];

        let preceding = &bytes[..pos];
        let line = memchr::memchr_iter(b'\n', preceding).count() + 1;
        let last_nl = preceding.iter().rposition(|&b| b == b'\n').unwrap_or(0);
        let col = if last_nl == 0 { pos } else { pos - last_nl };

        let start = pos.saturating_sub(context_size);
        let end = (pos + mat.len() + context_size).min(bytes.len());
        let raw_snippet = String::from_utf8_lossy(&bytes[start..end]);

        if let Some(filter) = line_filter {
            if !filter.allows(line) {
                continue;
            }
        }

        let _ = writeln!(
            out,
            "{}[L:{} C:{} Match:{}]{}",
            "[".dimmed(),
            line.bright_magenta(),
            col.bright_blue(),
            matched_word.bright_yellow().bold(),
            "]".dimmed()
        );

        let pretty = format_prettified_with_hint(&raw_snippet, matched_word, Some(label));
        let _ = writeln!(out, "{}", pretty);

        let identifier = find_preceding_identifier(bytes, pos);

        let flow = if flow_mode != FlowMode::Off {
            analyze_flow_context_with_mode(bytes, pos, flow_mode)
        } else {
            None
        };
        if deep_scan {
            if let Some(stats) = word_stats.get(matched_word) {
                let occ_index = stats.occurrence_index(pos);
                let neighbor_dist = stats.nearest_neighbor_distance(pos);
                let (call_sites, nearest_call) = stats.call_sites_info(bytes, pos);
                let span = stats.positions.last().zip(stats.positions.first()).map(|(l, f)| l.saturating_sub(*f));
                let density = (stats.positions.len() * 1024) / bytes.len().max(1);
                let id_hint = identifier
                    .as_deref()
                    .map(|id| format!("; id {}", id))
                    .unwrap_or_default();
                let (signals, confidence) = keyword_context_signals(&raw_snippet, identifier.as_deref(), matched_word, label);
                let sink_hint = sink_provenance_hint(&raw_snippet);
                let sink_str = sink_hint
                    .as_deref()
                    .map(|s| format!("; sink {}", s))
                    .unwrap_or_default();
                let signals_str = if signals.is_empty() {
                    "signals n/a".to_string()
                } else {
                    format!("signals {}", signals.join(","))
                };

                let _ = writeln!(
                    out,
                    "{} appears {} times; occurrence {}/{}; nearest neighbor {} bytes away; call-sites {}; span {} bytes; density {}/KiB; {}; conf {}/10{}{}{}",
                    "Story:".bright_green().bold(),
                    stats.positions.len().to_string().bright_yellow(),
                    (occ_index + 1).to_string().bright_yellow(),
                    stats.positions.len().to_string().bright_yellow(),
                    neighbor_dist
                        .map(|d| d.to_string())
                        .unwrap_or_else(|| "n/a".to_string())
                        .bright_yellow(),
                    call_sites.to_string().bright_yellow(),
                    span
                        .map(|d| d.to_string())
                        .unwrap_or_else(|| "n/a".to_string())
                        .bright_yellow(),
                    density.to_string().bright_yellow(),
                    signals_str.bright_blue(),
                    confidence.to_string().bright_red(),
                    sink_str,
                    match nearest_call {
                        Some((line, col, dist)) => format!("; nearest call at L:{} C:{} ({} bytes)", line, col, dist),
                        None => "; no call-sites detected".to_string(),
                    },
                    id_hint
                );
            }
            if let Some(flow) = flow.as_ref() {
                if let Some(lines) = format_context_graph(flow, identifier.as_deref()) {
                    let _ = writeln!(out, "{}", "Context:".bright_cyan().bold());
                    for line in lines {
                        let styled = style_context_line(&line);
                        let _ = writeln!(out, "{}", styled);
                    }
                }
            }
        }

        if let Some(flow) = flow.as_ref() {
            if let Some(line) = format_flow_compact(flow) {
                let _ = writeln!(out, "{} {}", "Flow:".bright_magenta().bold(), line.bright_cyan());
            }
        }

        if deep_scan {
            let lower = matched_word.to_lowercase();
            if lower.contains("fetch")
                || lower.contains("axios")
                || lower.contains("xhr")
                || lower.contains("xmlhttprequest")
                || lower.contains("request")
            {
                if let Some(lines) = request_trace_lines(&raw_snippet) {
                    let _ = writeln!(out, "{}", "Request:".bright_cyan().bold());
                    for line in lines {
                        let _ = writeln!(out, "{}", line);
                    }
                }
            }
        }

        let _ = writeln!(out, "{}", "─".repeat(40).dimmed());

        records.push(MatchRecord {
            source: label.to_string(),
            kind: "keyword".to_string(),
            matched: matched_word.to_string(),
            line,
            col,
            entropy: None,
            context: raw_snippet.to_string(),
            identifier,
        });
    }
    let _ = writeln!(out, "✨ Found {} keyword matches.", matches.len().green().bold());

    (out, records)
}

#[derive(Default)]
struct WordStats {
    positions: Vec<usize>,
    call_sites: Vec<usize>,
}

impl WordStats {
    fn occurrence_index(&self, pos: usize) -> usize {
        match self.positions.binary_search(&pos) {
            Ok(idx) => idx,
            Err(idx) => idx.saturating_sub(1),
        }
    }

    fn nearest_neighbor_distance(&self, pos: usize) -> Option<usize> {
        if self.positions.len() < 2 {
            return None;
        }
        let idx = self.occurrence_index(pos);
        let mut best = None;
        if idx > 0 {
            best = Some(pos.saturating_sub(self.positions[idx - 1]));
        }
        if idx + 1 < self.positions.len() {
            let next = self.positions[idx + 1].saturating_sub(pos);
            best = Some(best.map(|b| b.min(next)).unwrap_or(next));
        }
        best
    }

    fn call_sites_info(&self, bytes: &[u8], pos: usize) -> (usize, Option<(usize, usize, usize)>) {
        if self.call_sites.is_empty() {
            return (0, None);
        }
        let idx = match self.call_sites.binary_search(&pos) {
            Ok(i) => i,
            Err(i) => i,
        };
        let mut candidates = Vec::new();
        if idx < self.call_sites.len() {
            candidates.push(self.call_sites[idx]);
        }
        if idx > 0 {
            candidates.push(self.call_sites[idx - 1]);
        }
        let nearest = candidates.into_iter().min_by_key(|p| {
            if *p >= pos { *p - pos } else { pos - *p }
        });
        if let Some(call_pos) = nearest {
            let dist = if call_pos >= pos { call_pos - pos } else { pos - call_pos };
            let (line, col) = line_col(bytes, call_pos);
            return (self.call_sites.len(), Some((line, col, dist)));
        }
        (self.call_sites.len(), None)
    }
}

fn build_word_stats(bytes: &[u8], keywords: &[String]) -> HashMap<String, WordStats> {
    let mut map = HashMap::new();
    for kw in keywords {
        let mut stats = WordStats::default();
        let kw_bytes = kw.as_bytes();
        for pos in memmem::find_iter(bytes, kw_bytes) {
            stats.positions.push(pos);

            // simple call-site detection: keyword followed by optional spaces then '(' within 4 bytes
            let mut cursor = pos + kw_bytes.len();
            let mut steps = 0;
            while cursor < bytes.len() && steps < 4 {
                let b = bytes[cursor];
                if b.is_ascii_whitespace() {
                    cursor += 1;
                    steps += 1;
                    continue;
                }
                if b == b'(' {
                    stats.call_sites.push(pos);
                }
                break;
            }
        }
        stats.positions.sort_unstable();
        stats.call_sites.sort_unstable();
        map.insert(kw.clone(), stats);
    }
    map
}

fn line_col(bytes: &[u8], pos: usize) -> (usize, usize) {
    let preceding = &bytes[..pos.min(bytes.len())];
    let line = memchr::memchr_iter(b'\n', preceding).count() + 1;
    let last_nl = preceding.iter().rposition(|&b| b == b'\n').unwrap_or(0);
    let col = if last_nl == 0 { pos } else { pos - last_nl };
    (line, col)
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

fn keyword_context_signals(raw: &str, identifier: Option<&str>, keyword: &str, source_label: &str) -> (Vec<&'static str>, u8) {
    let mut signals = Vec::new();
    let mut score: i32 = 0;
    let lower = raw.to_lowercase();
    let kw = keyword.to_lowercase();
    let source = source_label.to_lowercase();

    if lower.contains("authorization") || lower.contains("bearer ") {
        signals.push("auth-header");
        score += 3;
    }
    if lower.contains("x-") || lower.contains("-h ") || lower.contains("header") {
        signals.push("header");
        score += 2;
    }
    if kw.contains("token") || kw.contains("secret") || kw.contains("key") || kw.contains("pass") {
        signals.push("keyword-hint");
        score += 2;
    }
    if lower.contains("?" ) && lower.contains("=") {
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
    if kw.contains("password") || kw.contains("secret") || kw.contains("private") {
        signals.push("high-risk-keyword");
        score += 1;
    }
    if lower.contains("example") || lower.contains("demo") || lower.contains("test") {
        signals.push("doc-context");
        score -= 2;
    }
    if source.contains("/docs") || source.contains("/examples") || source.contains("/test") {
        signals.push("doc-path");
        score -= 1;
    }

    let confidence = score.clamp(1, 10) as u8;
    (signals, confidence)
}

