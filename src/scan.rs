use ignore::WalkBuilder;
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use log::warn;
use memmap2::Mmap;
use rayon::prelude::*;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::process::Command;

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

    if !records.is_empty() && contains_public_endpoint(bytes) {
        if !cli.json {
            use owo_colors::OwoColorize;
            let _ = writeln!(
                file_output,
                "{}",
                "⚠️ Attack Surface: public endpoints detected in this file"
                    .bright_yellow()
                    .bold()
            );
        }
        records.push(MatchRecord {
            source: source_label.to_string(),
            kind: "attack-surface".to_string(),
            matched: "public-endpoint".to_string(),
            line: 0,
            col: 0,
            entropy: None,
            context: "public endpoints detected in file with findings".to_string(),
            identifier: None,
        });
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

    (file_output, records)
}

pub fn run_recursive_scan(
    input: &str,
    cli: &Cli,
    output_mode: &OutputMode,
    heatmap: Option<&Arc<Mutex<Heatmap>>>,
    lineage: Option<&Arc<Mutex<Lineage>>>,
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

fn contains_public_endpoint(bytes: &[u8]) -> bool {
    memchr::memmem::find(bytes, b"http://").is_some()
        || memchr::memmem::find(bytes, b"https://").is_some()
        || memchr::memmem::find(bytes, b"ws://").is_some()
        || memchr::memmem::find(bytes, b"wss://").is_some()
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

