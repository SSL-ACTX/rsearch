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
    lateral: Option<&Arc<Mutex<LateralLinkage>>>,
    diff_summary: Option<&Arc<Mutex<DiffSummary>>>,
    suppression_audit: Option<&Arc<Mutex<SuppressionAuditTracker>>>,
    suppression_rules: Option<&[SuppressionRule]>,
    diff_map: Option<&DiffMap>,
) -> (String, Vec<MatchRecord>) {
    let mut file_output = String::new();
    let mut records: Vec<MatchRecord> = Vec::new();

    let tag_set = parse_emit_tags(&cli.emit_tags);
    let flow_mode = flow_mode_for_source(source_path, source_hint, cli.flow_scan, bytes);
    let tuning = cli.output_tuning();
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
            &tuning,
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
            &tuning,
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
            &tuning,
        );
        file_output.push_str(&s);
        records.append(&mut r);
    }

    if let Some(tracker) = suppression_audit {
        if let Ok(mut guard) = tracker.lock() {
            guard.update(&records);
        }
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

    let drift_hints = build_protocol_drift_hints(&endpoint_hints);
    if !drift_hints.is_empty() {
        if !cli.json {
            use owo_colors::OwoColorize;
            let _ = writeln!(file_output, "{}", "🧭 Protocol Drift".bright_cyan().bold());
            for hint in drift_hints.iter().take(5) {
                let scheme_str = hint.schemes.join(" ↔ ");
                let class_str = hint.classes.join("/");
                let _ = writeln!(
                    file_output,
                    "  • {} — {} [{}]",
                    hint.base.bright_white(),
                    scheme_str.bright_magenta(),
                    class_str.bright_magenta()
                );
            }
        }
        for hint in &drift_hints {
            records.push(MatchRecord {
                source: source_label.to_string(),
                kind: "protocol-drift".to_string(),
                matched: hint.base.clone(),
                line: 0,
                col: 0,
                entropy: None,
                context: format!(
                    "protocol drift: {} [{}]",
                    hint.schemes.join("->"),
                    hint.classes.join("/")
                ),
                identifier: None,
            });
        }
    }

    let capability_hints = build_api_capability_hints(&records, &endpoint_hints);
    if !capability_hints.is_empty() {
        if !cli.json {
            use owo_colors::OwoColorize;
            let _ = writeln!(file_output, "{}", "🛡️ API Capability".bright_cyan().bold());
            for hint in capability_hints.iter().take(5) {
                let _ = writeln!(
                    file_output,
                    "  • {} — {} [{}]",
                    hint.endpoint.bright_white(),
                    hint.capability.bright_magenta(),
                    hint.class.bright_magenta()
                );
            }
        }
        for hint in &capability_hints {
            records.push(MatchRecord {
                source: source_label.to_string(),
                kind: "capability-hint".to_string(),
                matched: hint.endpoint.clone(),
                line: hint.line,
                col: 0,
                entropy: None,
                context: format!(
                    "capability {} ({})",
                    hint.capability, hint.class
                ),
                identifier: None,
            });
        }
    }

    let comment_hints = build_comment_escalation_hints(&records, &endpoint_hints);
    if !comment_hints.is_empty() {
        if !cli.json {
            use owo_colors::OwoColorize;
            let _ = writeln!(file_output, "{}", "🧷 Comment Escalation".bright_cyan().bold());
            for hint in comment_hints.iter().take(5) {
                let _ = writeln!(
                    file_output,
                    "  • {} L{} — {}",
                    hint.kind.bright_magenta(),
                    hint.line,
                    hint.reason.dimmed()
                );
            }
        }
        for hint in &comment_hints {
            records.push(MatchRecord {
                source: hint.source.clone(),
                kind: "comment-escalation".to_string(),
                matched: hint.kind.clone(),
                line: hint.line,
                col: hint.col,
                entropy: None,
                context: hint.reason.clone(),
                identifier: None,
            });
        }
    }

    let response_hints = build_response_class_hints(&records, &endpoint_hints);
    if !response_hints.is_empty() {
        if !cli.json {
            use owo_colors::OwoColorize;
            let _ = writeln!(file_output, "{}", "🧾 Response Class".bright_cyan().bold());
            for hint in response_hints.iter().take(5) {
                let _ = writeln!(
                    file_output,
                    "  • {} — {} [{}]",
                    hint.endpoint.bright_white(),
                    hint.response.bright_magenta(),
                    hint.class.bright_magenta()
                );
            }
        }
        for hint in &response_hints {
            records.push(MatchRecord {
                source: source_label.to_string(),
                kind: "response-class".to_string(),
                matched: hint.endpoint.clone(),
                line: hint.line,
                col: 0,
                entropy: None,
                context: format!("response {} ({})", hint.response, hint.class),
                identifier: None,
            });
        }
    }

    let auth_drift = build_auth_drift_hints(&records, &endpoint_hints);
    if !auth_drift.is_empty() {
        if !cli.json {
            use owo_colors::OwoColorize;
            let _ = writeln!(file_output, "{}", "🕵️ Auth Drift".bright_cyan().bold());
            for hint in auth_drift.iter().take(5) {
                let _ = writeln!(
                    file_output,
                    "  • {} — {} [{}]",
                    hint.endpoint.bright_white(),
                    hint.reason.dimmed(),
                    hint.class.bright_magenta()
                );
            }
        }
        for hint in &auth_drift {
            records.push(MatchRecord {
                source: source_label.to_string(),
                kind: "auth-drift".to_string(),
                matched: hint.endpoint.clone(),
                line: hint.line,
                col: 0,
                entropy: None,
                context: hint.reason.clone(),
                identifier: None,
            });
        }
    }

    let morph_hints = build_endpoint_shape_morphing_hints(&endpoint_hints);
    if !morph_hints.is_empty() {
        if !cli.json {
            use owo_colors::OwoColorize;
            let _ = writeln!(file_output, "{}", "🧬 Endpoint Morphing".bright_cyan().bold());
            for hint in morph_hints.iter().take(5) {
                let classes = hint.classes.join("/");
                let _ = writeln!(
                    file_output,
                    "  • {} — classes {}",
                    hint.endpoint.bright_white(),
                    classes.bright_magenta()
                );
            }
        }
        for hint in &morph_hints {
            records.push(MatchRecord {
                source: source_label.to_string(),
                kind: "endpoint-morphing".to_string(),
                matched: hint.endpoint.clone(),
                line: hint.line,
                col: 0,
                entropy: None,
                context: format!("morph classes {}", hint.classes.join("/")),
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

    let shadowing_hints = build_shadowing_hints(&records);
    if !shadowing_hints.is_empty() {
        if !cli.json {
            use owo_colors::OwoColorize;
            let _ = writeln!(file_output, "{}", "🌓 Credential Shadowing".bright_cyan().bold());
            for hint in shadowing_hints.iter().take(5) {
                let _ = writeln!(
                    file_output,
                    "  • {} — placeholder L{} → {} L{}",
                    hint.identifier.bright_white(),
                    hint.earlier_line,
                    hint.kind.dimmed(),
                    hint.line
                );
            }
        }
        for hint in &shadowing_hints {
            records.push(MatchRecord {
                source: hint.source.clone(),
                kind: "shadowing-hint".to_string(),
                matched: hint.identifier.clone(),
                line: hint.line,
                col: hint.col,
                entropy: None,
                context: format!(
                    "placeholder at L{} → {} at L{}",
                    hint.earlier_line, hint.kind, hint.line
                ),
                identifier: Some(hint.identifier.clone()),
            });
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

    if let Some(linkage) = lateral {
        if let Ok(mut guard) = linkage.lock() {
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
    lateral: Option<&Arc<Mutex<LateralLinkage>>>,
    diff_summary: Option<&Arc<Mutex<DiffSummary>>>,
    suppression_audit: Option<&Arc<Mutex<SuppressionAuditTracker>>>,
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
                                    lateral,
                                    diff_summary,
                                    suppression_audit,
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

pub struct ProtocolDriftHint {
    pub base: String,
    pub schemes: Vec<String>,
    pub classes: Vec<&'static str>,
}

pub struct CapabilityHint {
    pub endpoint: String,
    pub class: &'static str,
    pub capability: String,
    pub line: usize,
}

pub struct CommentEscalationHint {
    pub source: String,
    pub line: usize,
    pub col: usize,
    pub kind: String,
    pub reason: String,
}

pub struct ResponseClassHint {
    pub endpoint: String,
    pub class: &'static str,
    pub response: String,
    pub line: usize,
}

pub struct AuthDriftHint {
    pub endpoint: String,
    pub class: &'static str,
    pub line: usize,
    pub reason: String,
}

pub struct EndpointMorphHint {
    pub endpoint: String,
    pub classes: Vec<&'static str>,
    pub line: usize,
}

pub struct SuppressionHint {
    pub rule: String,
    pub reason: String,
    pub confidence: u8,
    pub decay_days: u16,
    pub line: usize,
    pub col: usize,
}

pub struct ShadowingHint {
    pub identifier: String,
    pub source: String,
    pub line: usize,
    pub col: usize,
    pub earlier_line: usize,
    pub kind: String,
}

pub struct SuppressionAudit {
    pub rule: String,
    pub status: &'static str,
    pub hits: usize,
    pub unique_kinds: usize,
    pub unique_signatures: usize,
    pub unique_sources: usize,
}

pub struct SuppressionAuditTracker {
    rules: Vec<SuppressionRule>,
    hits: Vec<usize>,
    kinds: Vec<HashSet<String>>,
    signatures: Vec<HashSet<String>>,
    sources: Vec<HashSet<String>>,
}

#[derive(Default)]
pub struct LateralLinkage {
    fingerprints: HashMap<String, Vec<LateralEvent>>,
}

#[derive(Clone)]
struct LateralEvent {
    source: String,
}

#[derive(Clone)]
pub enum SuppressionRule {
    Id(String),
    SourceLineKind { source: String, line: usize, kind: String },
}

impl SuppressionAuditTracker {
    pub fn new(rules: &[SuppressionRule]) -> Self {
        let len = rules.len();
        Self {
            rules: rules.to_vec(),
            hits: vec![0; len],
            kinds: (0..len).map(|_| HashSet::new()).collect(),
            signatures: (0..len).map(|_| HashSet::new()).collect(),
            sources: (0..len).map(|_| HashSet::new()).collect(),
        }
    }

    pub fn update(&mut self, records: &[MatchRecord]) {
        if self.rules.is_empty() {
            return;
        }
        for rec in records.iter().filter(|r| r.kind != "suppression-hint") {
            let matched = match_suppression_rules(rec, &self.rules);
            if matched.is_empty() {
                continue;
            }
            let signature = if let Some(id) = rec.identifier.as_ref() {
                format!("id:{}", id)
            } else {
                format!("matched:{}", rec.matched)
            };
            for idx in matched {
                self.hits[idx] += 1;
                self.kinds[idx].insert(rec.kind.clone());
                self.signatures[idx].insert(signature.clone());
                self.sources[idx].insert(rec.source.clone());
            }
        }
    }

    pub fn render(&self) -> Vec<SuppressionAudit> {
        let mut out = Vec::new();
        for (idx, rule) in self.rules.iter().enumerate() {
            let hits = self.hits[idx];
            let unique_kinds = self.kinds[idx].len();
            let unique_signatures = self.signatures[idx].len();
            let unique_sources = self.sources[idx].len();
            if hits == 0 {
                out.push(SuppressionAudit {
                    rule: suppression_rule_label(rule),
                    status: "stale",
                    hits,
                    unique_kinds,
                    unique_signatures,
                    unique_sources,
                });
                continue;
            }
            if unique_signatures > 1 || unique_kinds > 1 {
                out.push(SuppressionAudit {
                    rule: suppression_rule_label(rule),
                    status: "broad",
                    hits,
                    unique_kinds,
                    unique_signatures,
                    unique_sources,
                });
            }
        }
        out
    }
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

pub fn build_protocol_drift_hints(hints: &[EndpointHint]) -> Vec<ProtocolDriftHint> {
    let mut map: HashMap<String, (HashSet<String>, HashSet<&'static str>)> = HashMap::new();
    for hint in hints {
        if let Some((scheme, rest)) = split_scheme(&hint.url) {
            if scheme != "http" && scheme != "https" {
                continue;
            }
            let key = normalize_url_key(rest);
            let entry = map.entry(key).or_insert_with(|| (HashSet::new(), HashSet::new()));
            entry.0.insert(scheme.to_string());
            entry.1.insert(hint.class);
        }
    }

    let mut out = Vec::new();
    for (base, (schemes, classes)) in map {
        if schemes.len() < 2 && classes.len() < 2 {
            continue;
        }
        let mut schemes_vec: Vec<String> = schemes.into_iter().collect();
        schemes_vec.sort();
        let mut classes_vec: Vec<&'static str> = classes.into_iter().collect();
        classes_vec.sort();
        out.push(ProtocolDriftHint {
            base,
            schemes: schemes_vec,
            classes: classes_vec,
        });
    }
    out
}

pub fn build_api_capability_hints(
    records: &[MatchRecord],
    hints: &[EndpointHint],
) -> Vec<CapabilityHint> {
    let mut out = Vec::new();
    if records.is_empty() || hints.is_empty() {
        return out;
    }

    for rec in records.iter().filter(|r| r.kind == "request-trace") {
        let Some(link) = find_best_link(rec, hints) else {
            continue;
        };
        let method = extract_http_method(&rec.context);
        let auth = has_auth_context(&rec.context);
        let sensitive = is_sensitive_endpoint(&link.endpoint);

        if method.is_none() && !auth && !sensitive {
            continue;
        }

        let capability = classify_capability(method, auth, sensitive);
        out.push(CapabilityHint {
            endpoint: link.endpoint,
            class: link.class,
            capability,
            line: rec.line,
        });
    }

    out
}

pub fn build_comment_escalation_hints(
    records: &[MatchRecord],
    hints: &[EndpointHint],
) -> Vec<CommentEscalationHint> {
    let mut out = Vec::new();
    if records.is_empty() || hints.is_empty() {
        return out;
    }

    let has_public_endpoint = hints.iter().any(|h| h.class == "public");
    if !has_public_endpoint {
        return out;
    }

    for rec in records.iter().filter(|r| r.kind == "entropy" || r.kind == "keyword") {
        if !is_sensitive_record(rec) {
            continue;
        }
        if is_doc_like_path(&rec.source) {
            continue;
        }
        if !is_comment_context(&rec.context, &rec.matched) {
            continue;
        }
        out.push(CommentEscalationHint {
            source: rec.source.clone(),
            line: rec.line,
            col: rec.col,
            kind: rec.kind.clone(),
            reason: "secret in comment near public endpoint".to_string(),
        });
    }

    out
}

fn is_doc_like_path(source: &str) -> bool {
    let lower = source.to_lowercase();
    ["/docs", "/examples", "/example", "/test", "/tests", "/readme"].iter().any(|p| lower.contains(p))
}

pub fn build_response_class_hints(
    records: &[MatchRecord],
    hints: &[EndpointHint],
) -> Vec<ResponseClassHint> {
    let mut out = Vec::new();
    if records.is_empty() || hints.is_empty() {
        return out;
    }

    for rec in records.iter().filter(|r| r.kind == "request-trace") {
        let Some(link) = find_best_link(rec, hints) else {
            continue;
        };
        let response = guess_response_class(&rec.context);
        if response.is_none() {
            continue;
        }
        out.push(ResponseClassHint {
            endpoint: link.endpoint,
            class: link.class,
            response: response.unwrap(),
            line: rec.line,
        });
    }

    out
}

pub fn build_auth_drift_hints(
    records: &[MatchRecord],
    hints: &[EndpointHint],
) -> Vec<AuthDriftHint> {
    let mut out = Vec::new();
    if records.is_empty() || hints.is_empty() {
        return out;
    }

    let auth_records: Vec<&MatchRecord> = records
        .iter()
        .filter(|r| r.kind == "request-trace" && has_auth_context(&r.context))
        .collect();
    if auth_records.is_empty() {
        return out;
    }

    for rec in records.iter().filter(|r| r.kind == "request-trace") {
        if has_auth_context(&rec.context) {
            continue;
        }
        let nearest = auth_records
            .iter()
            .map(|r| r.line)
            .min_by_key(|line| if *line > rec.line { *line - rec.line } else { rec.line - *line });
        let Some(nearest_line) = nearest else {
            continue;
        };
        let distance = if nearest_line > rec.line { nearest_line - rec.line } else { rec.line - nearest_line };
        if distance > 40 {
            continue;
        }
        let Some(link) = find_best_link(rec, hints) else {
            continue;
        };
        out.push(AuthDriftHint {
            endpoint: link.endpoint,
            class: link.class,
            line: rec.line,
            reason: format!("auth missing near L{}", nearest_line),
        });
    }

    out
}

pub fn build_endpoint_shape_morphing_hints(hints: &[EndpointHint]) -> Vec<EndpointMorphHint> {
    let base_map = build_base_url_map(hints);
    if base_map.len() < 2 {
        return Vec::new();
    }
    let mut classes: HashSet<&'static str> = HashSet::new();
    for (class, _) in base_map.values() {
        classes.insert(*class);
    }
    if classes.len() < 2 {
        return Vec::new();
    }

    let class_vec = {
        let mut v: Vec<&'static str> = classes.into_iter().collect();
        v.sort();
        v
    };

    let mut out = Vec::new();
    for hint in hints {
        if !hint.url.contains("${") {
            continue;
        }
        let uses_base = base_map.keys().any(|k| hint.url.contains(k));
        if !uses_base {
            continue;
        }
        out.push(EndpointMorphHint {
            endpoint: hint.url.clone(),
            classes: class_vec.clone(),
            line: hint.line,
        });
    }
    out
}

fn guess_response_class(context: &str) -> Option<String> {
    let lower = context.to_lowercase();
    let sensitive = ["token", "password", "secret", "refresh", "auth", "bearer", "otp", "session"];
    let personal = ["email", "profile", "user", "account", "phone", "address", "ssn"];
    let low = ["health", "metrics", "status", "version", "ping"];

    if sensitive.iter().any(|k| lower.contains(k)) {
        return Some("sensitive".to_string());
    }
    if personal.iter().any(|k| lower.contains(k)) {
        return Some("personal".to_string());
    }
    if low.iter().any(|k| lower.contains(k)) {
        return Some("low".to_string());
    }
    None
}

fn is_comment_context(context: &str, matched: &str) -> bool {
    let mut in_block = false;
    for line in context.lines() {
        let trimmed = line.trim_start();
        if trimmed.contains("/*") {
            in_block = true;
        }
        let is_line_comment = trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with('*');
        let contains_match = trimmed.contains(matched);
        if (is_line_comment || in_block) && contains_match {
            return true;
        }
        if trimmed.contains("*/") {
            in_block = false;
        }
    }
    false
}

fn extract_http_method(context: &str) -> Option<&'static str> {
    let lower = context.to_lowercase();
    let compact = lower
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '\\')
        .collect::<String>();
    let patterns = [
        ("method:'delete'", "DELETE"),
        ("method:\"delete\"", "DELETE"),
        ("requests.delete", "DELETE"),
        ("axios.delete", "DELETE"),
        (".delete(", "DELETE"),
        ("method:'patch'", "PATCH"),
        ("method:\"patch\"", "PATCH"),
        ("requests.patch", "PATCH"),
        ("axios.patch", "PATCH"),
        (".patch(", "PATCH"),
        ("method:'put'", "PUT"),
        ("method:\"put\"", "PUT"),
        ("requests.put", "PUT"),
        ("axios.put", "PUT"),
        (".put(", "PUT"),
        ("method:'post'", "POST"),
        ("method:\"post\"", "POST"),
        ("requests.post", "POST"),
        ("axios.post", "POST"),
        (".post(", "POST"),
        ("method:'get'", "GET"),
        ("method:\"get\"", "GET"),
        ("requests.get", "GET"),
        ("axios.get", "GET"),
        (".get(", "GET"),
        ("method:'head'", "HEAD"),
        ("method:\"head\"", "HEAD"),
    ];

    for (pat, method) in patterns {
        if compact.contains(pat) || lower.contains(pat) {
            return Some(method);
        }
    }
    if lower.contains("method") {
        if lower.contains("delete") {
            return Some("DELETE");
        }
        if lower.contains("patch") {
            return Some("PATCH");
        }
        if lower.contains("put") {
            return Some("PUT");
        }
        if lower.contains("post") {
            return Some("POST");
        }
        if lower.contains("get") {
            return Some("GET");
        }
        if lower.contains("head") {
            return Some("HEAD");
        }
    }
    None
}

fn has_auth_context(context: &str) -> bool {
    let lower = context.to_lowercase();
    let tokens = [
        "authorization",
        "bearer ",
        "x-api-key",
        "api-key",
        "apikey",
        "auth-token",
        "access_token",
    ];
    tokens.iter().any(|t| lower.contains(t))
}

fn is_sensitive_endpoint(endpoint: &str) -> bool {
    let lower = endpoint.to_lowercase();
    let markers = ["/admin", "/internal", "/root", "/priv", "/secret", "/manage", "/system"];
    markers.iter().any(|m| lower.contains(m))
}

fn classify_capability(
    method: Option<&'static str>,
    auth: bool,
    sensitive: bool,
) -> String {
    let privileged = auth || sensitive;
    let base = match method.unwrap_or("UNKNOWN") {
        "GET" | "HEAD" => "read",
        "POST" | "PUT" | "PATCH" => "write",
        "DELETE" => "destructive",
        _ => "unknown",
    };
    if privileged {
        format!("privileged-{}", base)
    } else {
        base.to_string()
    }
}

fn split_scheme(url: &str) -> Option<(&'static str, &str)> {
    if let Some(rest) = url.strip_prefix("http://") {
        return Some(("http", rest));
    }
    if let Some(rest) = url.strip_prefix("https://") {
        return Some(("https", rest));
    }
    if let Some(rest) = url.strip_prefix("ws://") {
        return Some(("ws", rest));
    }
    if let Some(rest) = url.strip_prefix("wss://") {
        return Some(("wss", rest));
    }
    None
}

pub fn build_shadowing_hints(records: &[MatchRecord]) -> Vec<ShadowingHint> {
    let mut grouped: HashMap<String, Vec<&MatchRecord>> = HashMap::new();
    for rec in records {
        if rec.kind != "entropy" && rec.kind != "keyword" {
            continue;
        }
        let Some(id) = rec.identifier.as_ref() else {
            continue;
        };
        let key = format!("{}::{}", rec.source, id);
        grouped.entry(key).or_default().push(rec);
    }

    let mut out = Vec::new();
    for (_key, mut group) in grouped {
        group.sort_by_key(|r| r.line);

        let mut placeholder: Option<&MatchRecord> = None;
        for rec in &group {
            if placeholder.is_none() && is_placeholder_record(rec) {
                placeholder = Some(*rec);
                continue;
            }
            if let Some(earlier) = placeholder {
                if rec.line <= earlier.line {
                    continue;
                }
                if is_sensitive_record(rec) && !is_placeholder_record(rec) {
                    let id = rec.identifier.clone().unwrap_or_default();
                    out.push(ShadowingHint {
                        identifier: id,
                        source: rec.source.clone(),
                        line: rec.line,
                        col: rec.col,
                        earlier_line: earlier.line,
                        kind: rec.kind.clone(),
                    });
                    break;
                }
            }
        }
    }

    out
}

fn is_placeholder_record(rec: &MatchRecord) -> bool {
    let mut haystack = String::new();
    haystack.push_str(&rec.source.to_lowercase());
    haystack.push(' ');
    haystack.push_str(&rec.context.to_lowercase());
    if let Some(id) = rec.identifier.as_ref() {
        haystack.push(' ');
        haystack.push_str(&id.to_lowercase());
    }

    let markers = [
        "example",
        "sample",
        "dummy",
        "fake",
        "placeholder",
        "test",
        "mock",
        "todo",
        "changeme",
        "docs/",
        "examples/",
        "/tests/",
    ];
    markers.iter().any(|m| haystack.contains(m))
}

fn is_sensitive_record(rec: &MatchRecord) -> bool {
    if rec.kind == "entropy" {
        return true;
    }
    let lower = rec.matched.to_lowercase();
    let sensitive = [
        "secret",
        "token",
        "apikey",
        "api_key",
        "key",
        "password",
        "pass",
        "auth",
        "bearer",
        "private",
        "credential",
        "session",
    ];
    sensitive.iter().any(|m| lower.contains(m))
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
    !match_suppression_rules(rec, rules).is_empty()
}

fn match_suppression_rules(rec: &MatchRecord, rules: &[SuppressionRule]) -> Vec<usize> {
    let mut matched = Vec::new();
    for (idx, rule) in rules.iter().enumerate() {
        match rule {
            SuppressionRule::Id(id) => {
                if rec.identifier.as_deref() == Some(id.as_str()) {
                    matched.push(idx);
                }
            }
            SuppressionRule::SourceLineKind { source, line, kind } => {
                if rec.line == *line && rec.kind == *kind && rec.source.contains(source) {
                    matched.push(idx);
                }
            }
        }
    }
    matched
}

fn suppression_rule_label(rule: &SuppressionRule) -> String {
    match rule {
        SuppressionRule::Id(id) => format!("id:{}", id),
        SuppressionRule::SourceLineKind { source, line, kind } => {
            format!("{}:{}:{}", source, line, kind)
        }
    }
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
        if let Some((name, url, col)) = extract_named_url_constant(line) {
            let class = classify_endpoint(&url);
            out.push(EndpointHint {
                url,
                class,
                line: line_no,
                col,
                kind: "named-url",
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
                continue;
            }
            if hint.name.is_some() && deduped[idx].name.is_none() {
                deduped[idx] = hint;
                continue;
            }
            continue;
        }
        let idx = deduped.len();
        deduped.push(hint);
        seen.insert(key, idx);
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

fn extract_named_url_constant(line: &str) -> Option<(String, String, usize)> {
    if !line.contains("http://") && !line.contains("https://") {
        return None;
    }
    let eq = line.find('=')?;
    let name = extract_lhs_ident(&line[..eq])?;
    if !name.chars().any(|c| c.is_ascii_uppercase()) {
        return None;
    }
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
        let matches_name = hint
            .name
            .as_ref()
            .map(|n| rec_ctx.contains(n))
            .unwrap_or(false);
        let matches_url = rec_ctx.contains(&hint.url)
            || rec_ctx.contains(&normalize_url_key(&hint.url));
        let distance = if hint.line > rec_line {
            hint.line - rec_line
        } else {
            rec_line - hint.line
        };

        let resolved_class = resolve_class_from_base(&hint.url, &base_map).unwrap_or(hint.class);
        if matches_url {
            return Some(AttackSurfaceLink {
                request_line: rec_line,
                request_col: rec_col,
                endpoint: hint.url.clone(),
                class: resolved_class,
            });
        }

        let within = distance <= 40;
        if within && matches_name {
            let candidate = (hint, distance, matches_name);
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
        let matched = rec.matched.to_lowercase();
        let fn_sig = format!("function {}", matched);
        if ctx.contains(&fn_sig) {
            reasons.push("function name usage".to_string());
            score += 2;
        }
        if ctx.contains("lexer") || ctx.contains("parser") || ctx.contains("tokenize") {
            reasons.push("parser/lexer context".to_string());
            score += 2;
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

impl LateralLinkage {
    pub fn update(&mut self, source: &str, recs: &[MatchRecord]) {
        for rec in recs {
            if rec.kind != "entropy" && rec.kind != "keyword" {
                continue;
            }
            let Some(fp) = fingerprint_token(&rec.matched) else {
                continue;
            };
            let entry = self.fingerprints.entry(fp).or_default();
            entry.push(LateralEvent {
                source: source.to_string(),
            });
        }
    }

    pub fn render(&self) -> Option<String> {
        if self.fingerprints.is_empty() {
            return None;
        }
        let mut entries: Vec<(&String, &Vec<LateralEvent>)> = self.fingerprints.iter().collect();
        entries.retain(|(_, ev)| {
            let mut sources: HashSet<&str> = HashSet::new();
            for e in ev.iter() {
                sources.insert(e.source.as_str());
            }
            sources.len() >= 2
        });
        if entries.is_empty() {
            return None;
        }
        entries.sort_by(|a, b| b.1.len().cmp(&a.1.len()));

        let mut out = String::new();
        use owo_colors::OwoColorize;
        let _ = writeln!(out, "\n🔗 Lateral Linkage (possible reuse)");
        let _ = writeln!(out, "{}", "━".repeat(60).dimmed());

        for (idx, (fp, events)) in entries.iter().take(5).enumerate() {
            let mut sources: HashSet<&str> = HashSet::new();
            for e in events.iter() {
                sources.insert(e.source.as_str());
            }
            let _ = writeln!(
                out,
                "{}. {} — occurrences {} in {} files",
                idx + 1,
                fp.bright_yellow(),
                events.len(),
                sources.len()
            );
        }
        Some(out)
    }
}

fn fingerprint_token(token: &str) -> Option<String> {
    let trimmed = token.trim();
    if trimmed.len() < 12 {
        return None;
    }
    let head = &trimmed[..4];
    let tail = &trimmed[trimmed.len() - 4..];
    Some(format!("{}…{}:{}", head, tail, trimmed.len()))
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

