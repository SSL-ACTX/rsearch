use ignore::WalkBuilder;
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use log::warn;
use memmap2::Mmap;
use rayon::prelude::*;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::process::Command;
use std::fs;

use crate::cli::Cli;
use crate::entropy::{scan_for_requests, scan_for_secrets};
use crate::keyword::process_search;
use crate::heuristics::flow_mode_for_source;
use crate::output::{handle_output, MatchRecord, OutputMode};
use std::fmt::Write as FmtWrite;
use crate::utils::LineFilter;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

const MAX_MMAP_SIZE: u64 = 200 * 1024 * 1024; // 200 MB
const DEFAULT_EXCLUDES: &[&str] = &[
    "**/.git/**",
    "**/*.lock",
    "**/Cargo.lock",
    "**/package-lock.json",
    "**/yarn.lock",
    "**/pnpm-lock.yaml",
    "**/poetry.lock",
    "**/Pipfile.lock",
    "**/Gemfile.lock",
    "**/composer.lock",
    "**/go.sum",
];

pub fn run_analysis(
    source_label: &str,
    bytes: &[u8],
    cli: &Cli,
    source_path: Option<&Path>,
    source_hint: Option<&str>,
    heatmap: Option<&Arc<Mutex<Heatmap>>>,
    lineage: Option<&Arc<Mutex<Lineage>>>,
    diff_summary: Option<&Arc<Mutex<DiffSummary>>>,
    suppression_rules: Option<&[SuppressionRule]>,
    diff_map: Option<&DiffMap>,
) -> (String, Vec<MatchRecord>) {
    let mut file_output = String::new();
    let mut records: Vec<MatchRecord> = Vec::new();

    let tag_set = parse_emit_tags(&cli.emit_tags);
    let flow_mode = flow_mode_for_source(source_path, source_hint, cli.flow_scan, bytes);
    let line_filter = diff_map
        .and_then(|map| source_path.and_then(|p| map.get(p)))
        .map(|ranges| LineFilter::new(ranges.clone()));

    if !cli.keyword.is_empty() {
        let (s, mut r) = process_search(
            bytes,
            source_label,
            &cli.keyword,
            cli.context,
            cli.deep_scan,
            flow_mode,
            line_filter.as_ref(),
        );
        file_output.push_str(&s);
        records.append(&mut r);
    }

    if cli.entropy {
        let (s, mut r) = scan_for_secrets(
            source_label,
            bytes,
            cli.threshold,
            cli.context,
            &tag_set,
            cli.deep_scan,
            flow_mode,
            line_filter.as_ref(),
            cli.request_trace,
        );
        file_output.push_str(&s);
        records.append(&mut r);
    }

    if cli.request_trace {
        let (s, mut r) = scan_for_requests(
            source_label,
            bytes,
            cli.context,
            flow_mode,
            line_filter.as_ref(),
            source_path,
        );
        file_output.push_str(&s);
        records.append(&mut r);
    }

    if let Some(rules) = suppression_rules {
        let (filtered, suppressed) = apply_suppression_rules(&records, rules);
        records = filtered;
        if suppressed > 0 && !cli.json {
            use owo_colors::OwoColorize;
            let _ = writeln!(
                file_output,
                "{} suppressed {} finding(s) via rules",
                "🧹".bright_yellow().bold(),
                suppressed
            );
        }
    };

    let endpoint_hints = extract_attack_surface_hints(bytes);
    let attack_links = build_attack_surface_links(&records, &endpoint_hints);
    if !records.is_empty() && endpoint_hints.iter().any(|h| h.class == "public") {
        if !cli.json {
            use owo_colors::OwoColorize;
            let summary = summarize_endpoints(&endpoint_hints);
            let _ = writeln!(
                file_output,
                "{} {}",
                "⚠️ Attack Surface:".bright_yellow().bold(),
                summary.bright_yellow()
            );
            let _ = writeln!(file_output, "{}", "Top endpoints:".bright_cyan().bold());
            for hint in endpoint_hints.iter().take(3) {
                let suffix = hint
                    .name
                    .as_ref()
                    .map(|n| format!(" ({})", n))
                    .unwrap_or_default();
                let _ = writeln!(
                    file_output,
                    "  • {}{} [{}]",
                    hint.url.bright_white(),
                    suffix.dimmed(),
                    hint.class.bright_magenta()
                );
            }
        }
        records.push(MatchRecord {
            source: source_label.to_string(),
            kind: "attack-surface".to_string(),
            matched: "public-endpoint".to_string(),
            line: 0,
            col: 0,
            entropy: None,
            context: format!(
                "public endpoints with findings: {}",
                endpoint_hints
                    .iter()
                    .filter(|h| h.class == "public")
                    .take(5)
                    .map(|h| h.url.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            identifier: None,
        });
    }

    if !attack_links.is_empty() {
        if !cli.json {
            use owo_colors::OwoColorize;
            let _ = writeln!(file_output, "{}", "🔗 Attack Surface Links".bright_cyan().bold());
            for link in attack_links.iter().take(5) {
                let _ = writeln!(
                    file_output,
                    "  • request L{} → {} [{}]",
                    link.request_line,
                    link.endpoint.bright_white(),
                    link.class.bright_magenta()
                );
            }
        }
        for link in attack_links {
            records.push(MatchRecord {
                source: source_label.to_string(),
                kind: "attack-surface-link".to_string(),
                matched: link.endpoint.clone(),
                line: link.request_line,
                col: link.request_col,
                entropy: None,
                context: format!(
                    "request L{} → endpoint {} ({})",
                    link.request_line, link.endpoint, link.class
                ),
                identifier: None,
            });
        }
    }

    let suppression_hints = build_suppression_hints(&records);
    if !suppression_hints.is_empty() {
        if !cli.json {
            use owo_colors::OwoColorize;
            let _ = writeln!(file_output, "{}", "🧯 Suppression Hints".bright_cyan().bold());
            for hint in suppression_hints.iter().take(5) {
                let _ = writeln!(
                    file_output,
                    "  • {} — {} (conf {}/10, decay {}d)",
                    hint.rule.bright_white(),
                    hint.reason.dimmed(),
                    hint.confidence,
                    hint.decay_days
                );
            }
        }
        for hint in &suppression_hints {
            records.push(MatchRecord {
                source: source_label.to_string(),
                kind: "suppression-hint".to_string(),
                matched: hint.rule.clone(),
                line: hint.line,
                col: hint.col,
                entropy: None,
                context: format!("{}; decay {}d", hint.reason, hint.decay_days),
                identifier: None,
            });
        }
    }

    if let Some(path) = cli.suppress_out.as_deref() {
        if !suppression_hints.is_empty() {
            let _ = write_suppression_hints(path, &suppression_hints);
        }
    }

    if let Some(map) = heatmap {
        if let Ok(mut guard) = map.lock() {
            guard.update(source_label, &records);
        }
    }

    if let Some(chain) = lineage {
        if let Ok(mut guard) = chain.lock() {
            guard.update(source_label, &records);
        }
    }

    if diff_map.is_some() {
        if let Some(summary) = diff_summary {
            if let Ok(mut guard) = summary.lock() {
                guard.update(source_label, &records);
            }
        }
    }

    (file_output, records)
}

pub fn run_recursive_scan(
    input: &str,
    cli: &Cli,
    output_mode: &OutputMode,
    heatmap: Option<&Arc<Mutex<Heatmap>>>,
    lineage: Option<&Arc<Mutex<Lineage>>>,
    diff_summary: Option<&Arc<Mutex<DiffSummary>>>,
    suppression_rules: Option<&[SuppressionRule]>,
    diff_map: Option<&DiffMap>,
) {
    let exclude_matcher = build_exclude_matcher(&cli.exclude);
    let walker = WalkBuilder::new(input)
        .hidden(false)
        .git_ignore(true)
        .build();

    walker.into_iter().par_bridge().for_each(|result| {
        match result {
            Ok(entry) => {
                let path = entry.path();
                if path.is_file() {
                    if let Some(map) = diff_map {
                        if !map.contains_key(path) {
                            return;
                        }
                    }
                    if is_excluded_path(path, &exclude_matcher) {
                        return;
                    }

                    let metadata = match path.metadata() {
                        Ok(m) => m,
                        Err(_) => return,
                    };
                    if metadata.len() == 0 {
                        return;
                    }

                    if metadata.len() > MAX_MMAP_SIZE {
                        warn!("Skipping large file {} ({} bytes)", path.display(), metadata.len());
                        return;
                    }

                    if let Ok(mut file) = File::open(path) {
                        let mut peek = [0u8; 1024];
                        match file.read(&mut peek) {
                            Ok(n) if n > 0 => {
                                if peek[..n].contains(&0) {
                                    warn!("Skipping binary file {}", path.display());
                                    return;
                                }
                            }
                            _ => {}
                        }

                        match unsafe { Mmap::map(&file) } {
                            Ok(mmap) => {
                                let (out, recs) = run_analysis(
                                    &path.to_string_lossy(),
                                    &mmap,
                                    cli,
                                    Some(path),
                                    Some(&path.to_string_lossy()),
                                    heatmap,
                                    lineage,
                                    diff_summary,
                                    suppression_rules,
                                    diff_map,
                                );
                                handle_output(output_mode, cli, &out, recs, Some(path), &path.to_string_lossy());
                            }
                            Err(e) => {
                                warn!("Could not map file {}: {}", path.display(), e);
                            }
                        }
                    }
                }
            }
            Err(err) => {
                warn!("Walker error: {}", err);
            }
        }
    });
}

pub fn build_exclude_matcher(patterns: &[String]) -> Gitignore {
    let mut builder = GitignoreBuilder::new(".");
    for pat in DEFAULT_EXCLUDES {
        let _ = builder.add_line(None, pat);
    }
    for pat in patterns {
        let _ = builder.add_line(None, pat);
    }
    builder.build().unwrap_or_else(|_| Gitignore::empty())
}

pub type DiffMap = HashMap<std::path::PathBuf, Vec<(usize, usize)>>;

pub fn load_diff_map(base: &str) -> Option<DiffMap> {
    let root = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()?;
    if !root.status.success() {
        return None;
    }
    let root_path = String::from_utf8_lossy(&root.stdout).trim().to_string();

    let diff = Command::new("git")
        .current_dir(&root_path)
        .args(["diff", "--unified=0", base, "--"])
        .output()
        .ok()?;
    if !diff.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&diff.stdout);
    Some(parse_unified_diff(&root_path, &text))
}

pub fn parse_unified_diff(root: &str, diff: &str) -> DiffMap {
    let mut map: DiffMap = HashMap::new();
    let mut current: Option<std::path::PathBuf> = None;

    for line in diff.lines() {
        if line.starts_with("+++") {
            let path = line.trim_start_matches("+++ ").trim();
            if let Some(path) = path.strip_prefix("b/") {
                let full = std::path::Path::new(root).join(path);
                current = Some(full);
            } else {
                current = None;
            }
            continue;
        }
        if line.starts_with("@@") {
            if let Some(path) = current.clone() {
                if let Some((start, count)) = parse_hunk_added(line) {
                    if count > 0 {
                        let end = start + count - 1;
                        map.entry(path).or_default().push((start, end));
                    }
                }
            }
        }
    }

    map
}

fn parse_hunk_added(line: &str) -> Option<(usize, usize)> {
    let plus = line.find('+')?;
    let mut rest = &line[plus + 1..];
    if let Some(end) = rest.find(' ') {
        rest = &rest[..end];
    }
    let mut parts = rest.split(',');
    let start = parts.next()?.parse::<usize>().ok()?;
    let count = parts.next().map(|p| p.parse::<usize>().ok()).flatten().unwrap_or(1);
    Some((start, count))
}

pub struct EndpointHint {
    pub url: String,
    pub class: &'static str,
    pub line: usize,
    pub col: usize,
    pub kind: &'static str,
    pub name: Option<String>,
}

pub struct AttackSurfaceLink {
    pub request_line: usize,
    pub request_col: usize,
    pub endpoint: String,
    pub class: &'static str,
}

pub struct SuppressionHint {
    pub rule: String,
    pub reason: String,
    pub confidence: u8,
    pub decay_days: u16,
    pub line: usize,
    pub col: usize,
}

#[derive(Clone)]
pub enum SuppressionRule {
    Id(String),
    SourceLineKind { source: String, line: usize, kind: String },
}

pub fn build_attack_surface_links(
    records: &[MatchRecord],
    hints: &[EndpointHint],
) -> Vec<AttackSurfaceLink> {
    let mut out = Vec::new();
    if records.is_empty() || hints.is_empty() {
        return out;
    }

    for rec in records.iter().filter(|r| r.kind == "request-trace") {
        if let Some(link) = find_best_link(rec, hints) {
            out.push(link);
        }
    }

    out
}

pub fn build_suppression_hints(records: &[MatchRecord]) -> Vec<SuppressionHint> {
    let mut out = Vec::new();
    for rec in records {
        if rec.kind != "entropy" && rec.kind != "keyword" {
            continue;
        }
        let signal = suppression_signals(rec);
        if let Some((reasons, confidence, decay_days)) = signal {
            let rule = if let Some(id) = rec.identifier.as_ref() {
                format!("id:{}", id)
            } else {
                format!("{}:{}:{}", rec.source, rec.line, rec.kind)
            };
            out.push(SuppressionHint {
                rule,
                reason: reasons.join(", "),
                confidence,
                decay_days,
                line: rec.line,
                col: rec.col,
            });
        }
    }

    let mut deduped = Vec::new();
    let mut seen = HashSet::new();
    for hint in out {
        if seen.insert(hint.rule.clone()) {
            deduped.push(hint);
        }
    }
    deduped
}

pub fn load_suppression_rules(path: &str) -> Vec<SuppressionRule> {
    let mut rules = Vec::new();
    let Ok(text) = fs::read_to_string(path) else {
        return rules;
    };
    for line in text.lines() {
        let raw = line.trim();
        if raw.is_empty() || raw.starts_with('#') {
            continue;
        }
        if let Some(rest) = raw.strip_prefix("id:") {
            let id = rest.trim();
            if !id.is_empty() {
                rules.push(SuppressionRule::Id(id.to_string()));
            }
            continue;
        }
        let mut parts = raw.rsplitn(3, ':').collect::<Vec<_>>();
        if parts.len() == 3 {
            let kind = parts.remove(0).to_string();
            let line_str = parts.remove(0);
            let source = parts.remove(0).to_string();
            if let Ok(line) = line_str.parse::<usize>() {
                rules.push(SuppressionRule::SourceLineKind { source, line, kind });
                continue;
            }
        }
    }
    rules
}

pub fn apply_suppression_rules(
    records: &[MatchRecord],
    rules: &[SuppressionRule],
) -> (Vec<MatchRecord>, usize) {
    if rules.is_empty() {
        return (records.to_vec(), 0);
    }
    let mut kept = Vec::new();
    let mut suppressed = 0usize;
    for rec in records {
        if rec.kind == "suppression-hint" {
            kept.push(rec.clone());
            continue;
        }
        if should_suppress(rec, rules) {
            suppressed += 1;
            continue;
        }
        kept.push(rec.clone());
    }
    (kept, suppressed)
}

fn should_suppress(rec: &MatchRecord, rules: &[SuppressionRule]) -> bool {
    for rule in rules {
        match rule {
            SuppressionRule::Id(id) => {
                if rec.identifier.as_deref() == Some(id.as_str()) {
                    return true;
                }
            }
            SuppressionRule::SourceLineKind { source, line, kind } => {
                if rec.line == *line && rec.kind == *kind && rec.source.contains(source) {
                    return true;
                }
            }
        }
    }
    false
}

fn write_suppression_hints(path: &str, hints: &[SuppressionHint]) -> std::io::Result<()> {
    use std::io::Write as IoWrite;
    let mut file = fs::OpenOptions::new().create(true).append(true).open(path)?;
    for hint in hints {
        let _ = writeln!(
            file,
            "{} # {} | conf {}/10 | decay {}d",
            hint.rule, hint.reason, hint.confidence, hint.decay_days
        );
    }
    Ok(())
}

pub fn extract_attack_surface_hints(bytes: &[u8]) -> Vec<EndpointHint> {
    let mut out = Vec::new();
    let raw = String::from_utf8_lossy(bytes);

    for (idx, line) in raw.lines().enumerate() {
        let line_no = idx + 1;
        for (url, col, kind) in extract_line_urls(line) {
            let class = classify_endpoint(&url);
            out.push(EndpointHint {
                url,
                class,
                line: line_no,
                col,
                kind,
                name: None,
            });
        }
        if let Some((name, url, col)) = extract_base_url_constant(line) {
            let class = classify_endpoint(&url);
            out.push(EndpointHint {
                url,
                class,
                line: line_no,
                col,
                kind: "base-url",
                name: Some(name),
            });
        }
    }

    let mut deduped: Vec<EndpointHint> = Vec::new();
    let mut seen: HashMap<String, usize> = HashMap::new();
    for hint in out {
        let key = normalize_url_key(&hint.url);
        if let Some(idx) = seen.get(&key).copied() {
            if hint.kind == "base-url" && deduped[idx].kind != "base-url" {
                deduped[idx] = hint;
            }
        } else {
            let idx = deduped.len();
            deduped.push(hint);
            seen.insert(key, idx);
        }
    }

    let base_map = build_base_url_map(&deduped);
    let mut resolved = Vec::with_capacity(deduped.len());
    for mut hint in deduped {
        if hint.class == "unknown" {
            if let Some(class) = resolve_class_from_base(&hint.url, &base_map) {
                hint.class = class;
            }
        }
        resolved.push(hint);
    }

    resolved
}

pub fn classify_endpoint(url: &str) -> &'static str {
    let lower = url.to_lowercase();
    if lower.starts_with("http://localhost")
        || lower.starts_with("https://localhost")
        || lower.starts_with("http://127.")
        || lower.starts_with("https://127.")
        || lower.starts_with("http://0.0.0.0")
        || lower.starts_with("https://0.0.0.0")
        || lower.starts_with("http://[::1]")
        || lower.starts_with("https://[::1]")
    {
        return "localhost";
    }
    if lower.contains(".local") || lower.contains(".lan") || lower.contains("internal") {
        return "internal";
    }
    if lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.starts_with("ws://")
        || lower.starts_with("wss://")
    {
        return "public";
    }
    if lower.starts_with("/") {
        return "relative";
    }
    "unknown"
}

fn summarize_endpoints(hints: &[EndpointHint]) -> String {
    let mut public = 0usize;
    let mut localhost = 0usize;
    let mut internal = 0usize;
    let mut relative = 0usize;
    let mut total = 0usize;
    for h in hints {
        total += 1;
        match h.class {
            "public" => public += 1,
            "localhost" => localhost += 1,
            "internal" => internal += 1,
            "relative" => relative += 1,
            _ => {}
        }
    }
    format!(
        "{} endpoints (public {}, localhost {}, internal {}, relative {})",
        total, public, localhost, internal, relative
    )
}

fn build_base_url_map(hints: &[EndpointHint]) -> HashMap<String, (&'static str, String)> {
    let mut map = HashMap::new();
    for hint in hints {
        if hint.kind == "base-url" {
            if let Some(name) = hint.name.as_ref() {
                map.insert(name.clone(), (hint.class, hint.url.clone()));
            }
        }
    }
    map
}

fn resolve_class_from_base(url: &str, base_map: &HashMap<String, (&'static str, String)>) -> Option<&'static str> {
    let vars = extract_template_vars(url);
    let mut best: Option<&'static str> = None;
    for var in vars {
        let key = var.split('.').last().unwrap_or(var.as_str());
        if let Some((class, _base)) = base_map.get(key) {
            best = Some(best_class(best, *class));
        }
    }
    if best.is_none() {
        for (name, (class, _base)) in base_map {
            if url.contains(name) {
                best = Some(best_class(best, *class));
            }
        }
    }
    if best.is_none() && url.contains("${") && base_map.len() == 1 {
        if let Some((class, _)) = base_map.values().next() {
            return Some(*class);
        }
    }
    best
}

fn extract_base_url_constant(line: &str) -> Option<(String, String, usize)> {
    let upper = line.to_uppercase();
    if !(upper.contains("BASE_URL") || upper.contains("API_URL") || upper.contains("ENDPOINT")) {
        return None;
    }
    let eq = line.find('=')?;
    let name = extract_lhs_ident(&line[..eq])?;
    let url = extract_quoted_value(line, eq + 1)?;
    let col = line.find(&url).unwrap_or(eq + 1);
    Some((name.to_string(), url, col))
}

fn extract_lhs_ident(lhs: &str) -> Option<String> {
    let bytes = lhs.as_bytes();
    let mut end = bytes.len();
    while end > 0 && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    let mut start = end;
    while start > 0 {
        let b = bytes[start - 1];
        if b.is_ascii_alphanumeric() || b == b'_' || b == b'$' {
            start -= 1;
        } else {
            break;
        }
    }
    if start < end {
        Some(lhs[start..end].to_string())
    } else {
        None
    }
}

fn extract_template_vars(url: &str) -> Vec<String> {
    let mut vars = Vec::new();
    let bytes = url.as_bytes();
    let mut i = 0usize;
    while i + 2 < bytes.len() {
        if bytes[i] == b'$' && bytes[i + 1] == b'{' {
            let mut j = i + 2;
            while j < bytes.len() && bytes[j] != b'}' {
                j += 1;
            }
            if j < bytes.len() {
                let var = url[i + 2..j].trim();
                if !var.is_empty() {
                    vars.push(var.to_string());
                }
                i = j + 1;
                continue;
            }
        }
        i += 1;
    }
    vars
}

fn best_class(current: Option<&'static str>, candidate: &'static str) -> &'static str {
    let rank = |c: &'static str| match c {
        "public" => 4,
        "localhost" => 3,
        "internal" => 2,
        "relative" => 1,
        _ => 0,
    };
    match current {
        Some(cur) if rank(cur) >= rank(candidate) => cur,
        _ => candidate,
    }
}

fn extract_line_urls(line: &str) -> Vec<(String, usize, &'static str)> {
    let mut out = Vec::new();
    for token in ["http://", "https://", "ws://", "wss://"] {
        let mut cursor = 0usize;
        while let Some(idx) = line[cursor..].find(token) {
            let start = cursor + idx;
            let url = read_url_from(line, start);
            out.push((url, start + 1, "url"));
            cursor = start + token.len();
        }
    }
    if line.contains("fetch(") {
        if let Some(arg) = extract_quoted_value(line, line.find("fetch(").unwrap_or(0) + 6) {
            let col = line.find(&arg).unwrap_or(0) + 1;
            out.push((arg, col, "fetch"));
        }
    }
    out
}

fn extract_quoted_value(line: &str, start: usize) -> Option<String> {
    let bytes = line.as_bytes();
    let mut i = start.min(bytes.len());
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= bytes.len() {
        return None;
    }
    let quote = bytes[i];
    if quote != b'\'' && quote != b'"' && quote != b'`' {
        return None;
    }
    i += 1;
    let start_q = i;
    while i < bytes.len() && bytes[i] != quote {
        i += 1;
    }
    if i > start_q {
        return Some(line[start_q..i].to_string());
    }
    None
}

fn read_url_from(raw: &str, idx: usize) -> String {
    let bytes = raw.as_bytes();
    let mut end = idx;
    while end < bytes.len() {
        let b = bytes[end];
        if b.is_ascii_whitespace() || b == b'\'' || b == b'"' || b == b')' || b == b'`' {
            break;
        }
        end += 1;
    }
    raw[idx..end].to_string()
}

fn normalize_url_key(raw: &str) -> String {
    raw.chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .trim_matches(|c: char| c == ')' || c == ';' || c == ',' || c == '`')
        .to_string()
}

fn find_best_link(rec: &MatchRecord, hints: &[EndpointHint]) -> Option<AttackSurfaceLink> {
    let rec_line = rec.line;
    let rec_col = rec.col;
    let rec_ctx = rec.context.as_str();

    let base_map = build_base_url_map(hints);

    let mut best: Option<(&EndpointHint, usize, bool)> = None;
    for hint in hints {
        let matches_context = rec_ctx.contains(&hint.url)
            || rec_ctx.contains(&normalize_url_key(&hint.url));
        let distance = if hint.line > rec_line {
            hint.line - rec_line
        } else {
            rec_line - hint.line
        };

        let resolved_class = resolve_class_from_base(&hint.url, &base_map).unwrap_or(hint.class);
        if matches_context {
            return Some(AttackSurfaceLink {
                request_line: rec_line,
                request_col: rec_col,
                endpoint: hint.url.clone(),
                class: resolved_class,
            });
        }

        let within = distance <= 40;
        if within {
            let candidate = (hint, distance, matches_context);
            match best {
                None => best = Some(candidate),
                Some((_b_hint, b_dist, _)) if distance < b_dist => best = Some(candidate),
                _ => {}
            }
        }
    }

    best.map(|(hint, _dist, _)| AttackSurfaceLink {
        request_line: rec_line,
        request_col: rec_col,
        endpoint: hint.url.clone(),
        class: resolve_class_from_base(&hint.url, &base_map).unwrap_or(hint.class),
    })
}

fn suppression_signals(rec: &MatchRecord) -> Option<(Vec<String>, u8, u16)> {
    let ctx = rec.context.to_lowercase();
    let id = rec.identifier.as_deref().unwrap_or("").to_lowercase();
    let source = rec.source.to_lowercase();

    let mut reasons = Vec::new();
    let mut score: i32 = 0;

    let keywords = ["example", "sample", "demo", "test", "placeholder", "dummy", "mock", "lorem"];
    if keywords.iter().any(|k| ctx.contains(k) || id.contains(k)) {
        reasons.push("example/test context".to_string());
        score += 3;
    }

    let path_hints = ["/test", "/tests", "/spec", "/example", "/examples", "/demo", "/fixture", "/docs", "readme"];
    if path_hints.iter().any(|p| source.contains(p)) {
        reasons.push("test/docs path".to_string());
        score += 2;
    }

    if ctx.contains("localhost") || ctx.contains("127.0.0.1") || ctx.contains("0.0.0.0") {
        reasons.push("local/dev context".to_string());
        score += 2;
    }

    if rec.kind == "entropy" {
        if let Some(entropy) = rec.entropy {
            if entropy < 4.9 {
                reasons.push("low entropy margin".to_string());
                score += 2;
            }
            if entropy < 4.7 {
                score += 1;
            }
        }
    }

    if rec.kind == "keyword" {
        let weak = ["token", "secret", "key", "password"];
        if weak.iter().any(|k| rec.matched.to_lowercase().contains(k)) && !ctx.contains("auth") {
            reasons.push("generic keyword".to_string());
            score += 1;
        }
    }

    if reasons.is_empty() {
        return None;
    }

    let confidence = score.clamp(4, 9) as u8;
    let decay_days = match confidence {
        9 => 7,
        8 => 14,
        7 => 21,
        6 => 30,
        _ => 45,
    };
    Some((reasons, confidence, decay_days))
}

pub fn is_excluded_path(path: &Path, matcher: &Gitignore) -> bool {
    matcher.matched(path, path.is_dir()).is_ignore()
}

#[derive(Default)]
pub struct Lineage {
    tokens: HashMap<String, Vec<LineageEvent>>,
}

#[derive(Clone)]
struct LineageEvent {
    source: String,
    line: usize,
    col: usize,
    kind: String,
}

impl Lineage {
    pub fn update(&mut self, source: &str, recs: &[MatchRecord]) {
        for rec in recs {
            if rec.matched.len() < 12 {
                continue;
            }
            if rec.kind != "entropy" && rec.kind != "keyword" {
                continue;
            }
            let entry = self.tokens.entry(rec.matched.clone()).or_default();
            entry.push(LineageEvent {
                source: source.to_string(),
                line: rec.line,
                col: rec.col,
                kind: rec.kind.clone(),
            });
        }
    }

    pub fn render(&self) -> Option<String> {
        if self.tokens.is_empty() {
            return None;
        }
        let mut entries: Vec<(&String, &Vec<LineageEvent>)> = self.tokens.iter().collect();
        entries.sort_by(|a, b| b.1.len().cmp(&a.1.len()));

        let mut out = String::new();
        use owo_colors::OwoColorize;
        let _ = writeln!(out, "\n🧬 Secret Lineage (top chains)");
        let _ = writeln!(out, "{}", "━".repeat(60).dimmed());

        for (idx, (token, events)) in entries.iter().take(5).enumerate() {
            let mut sources: HashMap<&str, usize> = HashMap::new();
            for e in events.iter() {
                *sources.entry(e.source.as_str()).or_insert(0) += 1;
            }
            let mut origin = events[0].clone();
            for e in events.iter() {
                if e.source < origin.source || (e.source == origin.source && e.line < origin.line) {
                    origin = e.clone();
                }
            }
            let token_preview = trim_token(token, 28);
            let _ = writeln!(
                out,
                "{}. {} — occurrences {} in {} files | origin {}:{}:{} ({})",
                idx + 1,
                token_preview.bright_yellow(),
                events.len(),
                sources.len(),
                origin.source.bright_cyan(),
                origin.line,
                origin.col,
                origin.kind
            );
        }

        Some(out)
    }
}

#[derive(Default)]
pub struct Heatmap {
    files: HashMap<String, FileRisk>,
}

#[derive(Default, Clone)]
struct FileRisk {
    matches: usize,
    entropy_hits: usize,
    keyword_hits: usize,
    max_entropy: f64,
    score: f64,
}

impl Heatmap {
    pub fn update(&mut self, source: &str, recs: &[MatchRecord]) {
        if recs.is_empty() {
            return;
        }
        let entry = self.files.entry(source.to_string()).or_default();
        for rec in recs {
            if rec.kind == "suppression-hint" {
                continue;
            }
            entry.matches += 1;
            let mut weight = 1.0;
            if rec.kind == "entropy" {
                entry.entropy_hits += 1;
                if let Some(e) = rec.entropy {
                    entry.max_entropy = entry.max_entropy.max(e);
                    weight += e.min(8.0);
                }
            } else if rec.kind == "keyword" {
                entry.keyword_hits += 1;
                weight += 0.5;
            }
            if let Some(id) = &rec.identifier {
                if !id.is_empty() {
                    weight += 0.2;
                }
            }
            if rec.matched.len() >= 40 {
                weight += 0.3;
            }
            entry.score += weight;
        }
    }

    pub fn render(&self) -> Option<String> {
        if self.files.is_empty() {
            return None;
        }
        let mut entries: Vec<(&String, &FileRisk)> = self.files.iter().collect();
        entries.sort_by(|a, b| b.1.score.partial_cmp(&a.1.score).unwrap_or(std::cmp::Ordering::Equal));

        let mut out = String::new();
        use owo_colors::OwoColorize;
        let _ = writeln!(out, "\n🔥 Risk Heatmap (top files)");
        let _ = writeln!(out, "{}", "━".repeat(60).dimmed());

        for (idx, (path, risk)) in entries.iter().take(5).enumerate() {
            let _ = writeln!(
                out,
                "{}. {} — score {:.1} | hits {} (entropy {}, keyword {}) | max H {:.1}",
                idx + 1,
                path.bright_cyan(),
                risk.score,
                risk.matches,
                risk.entropy_hits,
                risk.keyword_hits,
                risk.max_entropy
            );
        }

        Some(out)
    }
}

#[derive(Default)]
pub struct DiffSummary {
    files: HashMap<String, DiffFileSummary>,
    totals: DiffTotals,
}

#[derive(Default, Clone)]
struct DiffFileSummary {
    matches: usize,
    entropy_hits: usize,
    keyword_hits: usize,
    request_hits: usize,
    attack_hits: usize,
}

#[derive(Default, Clone)]
struct DiffTotals {
    matches: usize,
    entropy_hits: usize,
    keyword_hits: usize,
    request_hits: usize,
    attack_hits: usize,
}

impl DiffSummary {
    pub fn update(&mut self, source: &str, recs: &[MatchRecord]) {
        if recs.is_empty() {
            return;
        }
        let entry = self.files.entry(source.to_string()).or_default();
        for rec in recs {
            if rec.kind == "suppression-hint" {
                continue;
            }
            entry.matches += 1;
            self.totals.matches += 1;
            match rec.kind.as_str() {
                "entropy" => {
                    entry.entropy_hits += 1;
                    self.totals.entropy_hits += 1;
                }
                "keyword" => {
                    entry.keyword_hits += 1;
                    self.totals.keyword_hits += 1;
                }
                "request-trace" => {
                    entry.request_hits += 1;
                    self.totals.request_hits += 1;
                }
                "attack-surface" | "attack-surface-link" => {
                    entry.attack_hits += 1;
                    self.totals.attack_hits += 1;
                }
                _ => {}
            }
        }
    }

    pub fn render(&self) -> Option<String> {
        if self.files.is_empty() {
            return None;
        }
        let mut entries: Vec<(&String, &DiffFileSummary)> = self.files.iter().collect();
        entries.sort_by(|a, b| b.1.matches.cmp(&a.1.matches));

        let mut out = String::new();
        use owo_colors::OwoColorize;
        let _ = writeln!(out, "\n🧪 Diff Summary (added lines)");
        let _ = writeln!(out, "{}", "━".repeat(60).dimmed());
        let _ = writeln!(
            out,
            "Totals: {} hits | entropy {} | keyword {} | request {} | attack {}",
            self.totals.matches,
            self.totals.entropy_hits,
            self.totals.keyword_hits,
            self.totals.request_hits,
            self.totals.attack_hits
        );

        for (idx, (path, summary)) in entries.iter().take(5).enumerate() {
            let _ = writeln!(
                out,
                "{}. {} — hits {} (entropy {}, keyword {}, request {}, attack {})",
                idx + 1,
                path.bright_cyan(),
                summary.matches,
                summary.entropy_hits,
                summary.keyword_hits,
                summary.request_hits,
                summary.attack_hits
            );
        }

        Some(out)
    }
}

fn trim_token(value: &str, max_len: usize) -> String {
    if value.len() <= max_len {
        return value.to_string();
    }
    let mut out = value.chars().take(max_len.saturating_sub(1)).collect::<String>();
    out.push('…');
    out
}

fn parse_emit_tags(raw: &Option<String>) -> HashSet<String> {
    let mut set = HashSet::new();
    if let Some(s) = raw {
        for part in s.split(',') {
            let tag = part.trim().to_lowercase();
            if !tag.is_empty() {
                set.insert(tag);
            }
        }
    }
    set
}

