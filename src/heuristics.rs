use memchr;
use std::path::Path;

#[cfg(feature = "js-ast")]
use std::sync::OnceLock;

#[cfg(feature = "js-ast")]
use tree_sitter::Language;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowMode {
    Off,
    Heuristic,
    JsAst,
}

#[derive(Debug, Default)]
pub struct FlowContext {
    pub scope_kind: Option<String>,
    pub scope_name: Option<String>,
    pub scope_container: Option<String>,
    pub scope_path: Option<String>,
    pub block_depth: usize,
    pub nearest_control: Option<String>,
    pub nearest_control_line: Option<usize>,
    pub nearest_control_col: Option<usize>,
    pub assignment_distance: Option<usize>,
    pub return_distance: Option<usize>,
    pub scope_line: Option<usize>,
    pub scope_col: Option<usize>,
    pub scope_distance: Option<usize>,
    pub call_chain_hint: Option<String>,
    pub scope_path_distance: Option<usize>,
    pub scope_path_depth: Option<usize>,
}

pub fn analyze_flow_context(bytes: &[u8], pos: usize) -> FlowContext {
    let window_start = pos.saturating_sub(2048);
    let window_end = (pos + 2048).min(bytes.len());
    let window = &bytes[window_start..window_end];

    let mut ctx = FlowContext::default();

    // Estimate block depth by counting braces in the window prefix.
    let prefix = &window[..pos.saturating_sub(window_start)];
    let mut depth = 0isize;
    for &b in prefix {
        if b == b'{' {
            depth += 1;
        } else if b == b'}' {
            depth -= 1;
        }
    }
    ctx.block_depth = depth.max(0) as usize;

    // Nearest control keyword backwards.
    let controls: &[&[u8]] = &[
        b"if",
        b"else",
        b"for",
        b"while",
        b"switch",
        b"return",
        b"try",
        b"catch",
    ];
    let mut nearest: Option<(String, usize, usize)> = None;
    for kw in controls.iter() {
        if let Some(idx) = rfind_word_token(prefix, kw) {
            let dist = prefix.len().saturating_sub(idx);
            if nearest.as_ref().map(|(_, _, d)| dist < *d).unwrap_or(true) {
                let abs_pos = window_start + idx;
                let (line, col) = line_col_abs(window_start, window, abs_pos);
                nearest = Some((String::from_utf8_lossy(kw).to_string(), line, col));
            }
        }
    }
    if let Some((kw, line, col)) = nearest {
        ctx.nearest_control = Some(kw);
        ctx.nearest_control_line = Some(line);
        ctx.nearest_control_col = Some(col);
    }

    // Nearest assignment '=' not part of '==' or '=>'
    if let Some(idx) = rfind_assignment(prefix) {
        ctx.assignment_distance = Some(prefix.len().saturating_sub(idx));
    }

    // Nearest return (distance)
    if let Some(idx) = rfind_word_token(prefix, b"return") {
        ctx.return_distance = Some(prefix.len().saturating_sub(idx));
    }

    // Heuristic container (class/struct/impl)
    if let Some(container) = find_container_name(prefix) {
        ctx.scope_container = Some(container);
    }

    // Namespace/module breadcrumb
    if let Some(path) = find_scope_path(prefix) {
        ctx.scope_path = Some(path);
        ctx.scope_path_distance = rfind_any_scope_keyword_distance(prefix);
        ctx.scope_path_depth = ctx.scope_path.as_ref().map(|p| p.split("::").count());
    }

    // Heuristic function name detection
    if let Some((name, line, col, abs_pos)) = find_function_name(prefix, window_start) {
        ctx.scope_kind = Some("function".to_string());
        ctx.scope_name = Some(name);
        ctx.scope_line = Some(line);
        ctx.scope_col = Some(col);
        ctx.scope_distance = Some(pos.saturating_sub(abs_pos));
    } else if let Some((name, abs_pos)) = find_assignment_name(window, window_start) {
        let (line, col) = line_col_abs(window_start, window, abs_pos);
        ctx.scope_kind = Some("assignment".to_string());
        ctx.scope_name = Some(name);
        ctx.scope_line = Some(line);
        ctx.scope_col = Some(col);
        ctx.scope_distance = Some(pos.saturating_sub(abs_pos));
    }

    // Call-chain hint from nearby dot-chains or function calls
    if let Some(chain) = infer_call_chain(prefix) {
        ctx.call_chain_hint = Some(chain);
    }

    ctx
}

pub fn analyze_flow_context_with_mode(bytes: &[u8], pos: usize, mode: FlowMode) -> Option<FlowContext> {
    match mode {
        FlowMode::Off => None,
        FlowMode::Heuristic => Some(analyze_flow_context(bytes, pos)),
        FlowMode::JsAst => analyze_flow_context_js(bytes, pos)
            .or_else(|| Some(analyze_flow_context(bytes, pos))),
    }
}

pub fn format_flow_compact(flow: &FlowContext) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();

    if flow.scope_kind.is_some() || flow.scope_name.is_some() {
        let kind = flow.scope_kind.clone().unwrap_or_else(|| "scope".to_string());
        let name = flow
            .scope_name
            .as_deref()
            .and_then(normalize_name)
            .unwrap_or_else(|| "<anon>".to_string());
        let mut s = format!("scope {}:{}", kind, name);
        if let (Some(l), Some(c)) = (flow.scope_line, flow.scope_col) {
            s.push_str(&format!(" L{}:C{}", l, c));
        }
        if let Some(d) = flow.scope_distance {
            s.push_str(&format!(" d{}", d));
        }
        parts.push(format!("[{}]", s));
    }

    if let Some(path) = &flow.scope_path {
        let mut s = format!("path {}", path);
        if let Some(depth) = flow.scope_path_depth {
            s.push_str(&format!(" depth{}", depth));
        }
        if let Some(dist) = flow.scope_path_distance {
            s.push_str(&format!(" d{}", dist));
        }
        parts.push(format!("[{}]", s));
    }

    if let Some(container) = flow.scope_container.as_deref().and_then(normalize_name) {
        parts.push(format!("[container {}]", container));
    }

    if let Some(ctrl) = &flow.nearest_control {
        let mut s = format!("ctrl {}", ctrl);
        if let (Some(l), Some(c)) = (flow.nearest_control_line, flow.nearest_control_col) {
            s.push_str(&format!(" L{}:C{}", l, c));
        }
        parts.push(format!("[{}]", s));
    }

    if let Some(assign) = flow.assignment_distance {
        parts.push(format!("[assign d{}]", assign));
    }

    if let Some(ret) = flow.return_distance {
        parts.push(format!("[return d{}]", ret));
    }

    if let Some(chain) = &flow.call_chain_hint {
        let trimmed = trim_value(chain, 32);
        if trimmed.len() > 1 {
            parts.push(format!("[chain {}]", trimmed));
        }
    }

    if flow.block_depth > 0 {
        parts.push(format!("[depth {}]", flow.block_depth));
    }

    if parts.is_empty() {
        None
    } else {
        Some(trim_value(&parts.join(" "), 180))
    }
}

pub fn is_likely_code(bytes: &[u8]) -> bool {
    let sample_len = bytes.len().min(4096);
    let sample = &bytes[..sample_len];
    let text_ratio = sample
        .iter()
        .filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
        .count() as f64
        / sample_len.max(1) as f64;
    if text_ratio < 0.7 {
        return false;
    }
    // If it looks like markdown or prose-heavy text, skip flow analysis.
    if memchr::memmem::find(sample, b"```").is_some() {
        return false;
    }
    let mut md_lines = 0usize;
    let mut non_empty_lines = 0usize;
    for line in sample.split(|&b| b == b'\n') {
        let mut i = 0;
        while i < line.len() && line[i].is_ascii_whitespace() {
            i += 1;
        }
        let trimmed = &line[i..];
        if trimmed.is_empty() {
            continue;
        }
        non_empty_lines += 1;
        let md = trimmed.starts_with(b"#")
            || trimmed.starts_with(b"-")
            || trimmed.starts_with(b"*")
            || trimmed.starts_with(b">")
            || trimmed.starts_with(b"|")
            || (trimmed.len() > 1 && trimmed[0].is_ascii_digit() && trimmed[1] == b'.')
            || trimmed.starts_with(b"```")
            || trimmed.starts_with(b"- [")
            || trimmed.starts_with(b"* [");
        if md {
            md_lines += 1;
        }
    }
    if non_empty_lines > 0 && md_lines * 2 >= non_empty_lines {
        return false;
    }
    let mut score = 0i32;
    let tokens: &[&[u8]] = &[
        b"function",
        b"class",
        b"struct",
        b"impl",
        b"fn",
        b"def",
        b"trait",
        b"enum",
        b"interface",
        b"let",
        b"const",
        b"var",
        b"import",
        b"export",
        b"using",
        b"async",
        b"=>",
        b"{",
    ];
    let primary: &[&[u8]] = &[
        b"function",
        b"fn",
        b"def",
        b"class",
        b"import",
        b"export",
    ];
    let mut primary_hit = false;
    for token in tokens.iter() {
        if contains_word(sample, token) {
            score += 1;
            if primary.iter().any(|p| *p == *token) {
                primary_hit = true;
            }
        }
    }
    let semicolons = memchr::memmem::find_iter(sample, b";").count();
    let braces = memchr::memmem::find_iter(sample, b"{").count();
    let parens = memchr::memmem::find_iter(sample, b"(").count();
    let code_punct = (semicolons + braces + parens) as i32;
    primary_hit && ((score >= 2 && code_punct >= 2) || (score >= 3))
}

pub fn is_likely_code_for_path(path: &Path, bytes: &[u8]) -> bool {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_lowercase());
    if let Some(ext) = ext.as_deref() {
        if is_data_extension(ext) {
            return false;
        }
        if is_code_extension(ext) {
            return is_likely_code(bytes);
        }
    }
    is_strongly_likely_code(bytes)
}

pub fn flow_mode_for_source(
    source_path: Option<&Path>,
    source_hint: Option<&str>,
    flow_scan: bool,
    bytes: &[u8],
) -> FlowMode {
    if !flow_scan {
        return FlowMode::Off;
    }

    let ext = source_path
        .and_then(|p| p.extension().and_then(|e| e.to_str()).map(|s| s.to_lowercase()))
        .or_else(|| source_hint.and_then(extract_extension_from_hint));

    if let Some(ext) = ext.as_deref() {
        if ext == "js" {
            return if cfg!(feature = "js-ast") {
                FlowMode::JsAst
            } else {
                FlowMode::Off
            };
        }
        if is_data_extension(ext) {
            return FlowMode::Off;
        }
        if is_code_extension(ext) {
            return if is_likely_code(bytes) {
                FlowMode::Heuristic
            } else {
                FlowMode::Off
            };
        }
    }

    if is_strongly_likely_code(bytes) {
        FlowMode::Heuristic
    } else {
        FlowMode::Off
    }
}

fn rfind_word_token(haystack: &[u8], token: &[u8]) -> Option<usize> {
    if token.is_empty() || haystack.len() < token.len() {
        return None;
    }
    for i in (0..=haystack.len() - token.len()).rev() {
        if &haystack[i..i + token.len()] == token {
            if is_word_boundary(haystack, i, token.len()) {
                return Some(i);
            }
        }
    }
    None
}

fn is_word_boundary(haystack: &[u8], start: usize, len: usize) -> bool {
    let left_ok = if start == 0 {
        true
    } else {
        !is_ident_char(haystack[start - 1])
    };
    let right_idx = start + len;
    let right_ok = if right_idx >= haystack.len() {
        true
    } else {
        !is_ident_char(haystack[right_idx])
    };
    left_ok && right_ok
}

fn rfind_assignment(haystack: &[u8]) -> Option<usize> {
    for i in (0..haystack.len()).rev() {
        if haystack[i] == b'=' {
            let prev = if i > 0 { Some(haystack[i - 1]) } else { None };
            let next = if i + 1 < haystack.len() { Some(haystack[i + 1]) } else { None };
            if prev == Some(b'=') || next == Some(b'=') || next == Some(b'>') {
                continue;
            }
            return Some(i);
        }
    }
    None
}

fn find_function_name(prefix: &[u8], window_start: usize) -> Option<(String, usize, usize, usize)> {
    // Prefer nearest "function name" or Rust "fn name" before position.
    if let Some(idx) = rfind_word_token(prefix, b"function") {
        let name = read_identifier(&prefix[idx + 8..]);
        if let Some(name) = name {
            let abs_pos = window_start + idx;
            let (line, col) = line_col_abs(window_start, prefix, abs_pos);
            return Some((name, line, col, abs_pos));
        }
    }
    if let Some(idx) = rfind_word_token(prefix, b"fn") {
        let name = read_identifier(&prefix[idx + 2..]);
        if let Some(name) = name {
            let abs_pos = window_start + idx;
            let (line, col) = line_col_abs(window_start, prefix, abs_pos);
            return Some((name, line, col, abs_pos));
        }
    }
    None
}

fn find_container_name(prefix: &[u8]) -> Option<String> {
    // Look for "class X" / "struct X" / "impl X" backwards.
    let containers: &[&[u8]] = &[b"class", b"struct", b"impl"];
    for kw in containers.iter() {
        if let Some(idx) = rfind_word_token(prefix, kw) {
            let name = read_identifier(&prefix[idx + kw.len()..]);
            if let Some(name) = name {
                return Some(name);
            }
        }
    }
    None
}

fn find_scope_path(prefix: &[u8]) -> Option<String> {
    // Heuristic breadcrumb from nearest module/namespace declarations
    let keywords: &[&[u8]] = &[b"mod", b"module", b"namespace", b"package"];
    let mut parts: Vec<String> = Vec::new();
    for kw in keywords.iter() {
        if let Some(idx) = rfind_word_token(prefix, kw) {
            if let Some(name) = read_identifier(&prefix[idx + kw.len()..]) {
                parts.push(name);
            }
        }
    }
    if parts.is_empty() {
        None
    } else {
        parts.reverse();
        Some(parts.join("::"))
    }
}

fn rfind_any_scope_keyword_distance(prefix: &[u8]) -> Option<usize> {
    let keywords: &[&[u8]] = &[b"mod", b"module", b"namespace", b"package"];
    let mut best: Option<usize> = None;
    for kw in keywords.iter() {
        if let Some(idx) = rfind_word_token(prefix, kw) {
            let dist = prefix.len().saturating_sub(idx);
            best = Some(best.map(|b| b.min(dist)).unwrap_or(dist));
        }
    }
    best
}

fn read_identifier(bytes: &[u8]) -> Option<String> {
    let mut i = 0;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    let start = i;
    while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] == b'$') {
        i += 1;
    }
    if i > start {
        Some(String::from_utf8_lossy(&bytes[start..i]).to_string())
    } else {
        None
    }
}

fn find_assignment_name(window: &[u8], window_start: usize) -> Option<(String, usize)> {
    for i in (0..window.len()).rev() {
        if window[i] == b'=' {
            let prev = if i > 0 { window[i - 1] } else { 0 };
            let next = if i + 1 < window.len() { window[i + 1] } else { 0 };
            if prev == b'=' || next == b'=' || next == b'>' {
                continue;
            }
            let mut j = i;
            while j > 0 && window[j - 1].is_ascii_whitespace() {
                j -= 1;
            }
            let end = j;
            while j > 0 && (window[j - 1].is_ascii_alphanumeric() || window[j - 1] == b'_' || window[j - 1] == b'$') {
                j -= 1;
            }
            if end > j {
                let name = String::from_utf8_lossy(&window[j..end]).to_string();
                return Some((name, window_start + j));
            }
        }
    }
    None
}

fn infer_call_chain(prefix: &[u8]) -> Option<String> {
    // Heuristic: find nearest "identifier.identifier" chain before current position.
    let mut best: Option<String> = None;
    let mut i = prefix.len();
    while i > 0 {
        i -= 1;
        if prefix[i] == b'.' {
            let left = read_ident_backward(prefix, i);
            let right = read_ident_forward(prefix, i + 1);
            if let (Some(l), Some(r)) = (left, right) {
                if is_reasonable_ident(&l) && is_reasonable_ident(&r) && !is_file_extension(&r) {
                    best = Some(format!("{}.{}", l, r));
                    break;
                }
            }
        }
    }
    best
}

fn read_ident_backward(bytes: &[u8], pos: usize) -> Option<String> {
    if pos == 0 {
        return None;
    }
    let mut i = pos;
    while i > 0 && bytes[i - 1].is_ascii_whitespace() {
        i -= 1;
    }
    let end = i;
    while i > 0 && (bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_' || bytes[i - 1] == b'$') {
        i -= 1;
    }
    if end > i {
        Some(String::from_utf8_lossy(&bytes[i..end]).to_string())
    } else {
        None
    }
}

fn read_ident_forward(bytes: &[u8], pos: usize) -> Option<String> {
    let mut i = pos;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    let start = i;
    while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] == b'$') {
        i += 1;
    }
    if i > start {
        Some(String::from_utf8_lossy(&bytes[start..i]).to_string())
    } else {
        None
    }
}

fn line_col_abs(window_start: usize, window: &[u8], abs_pos: usize) -> (usize, usize) {
    let rel = abs_pos.saturating_sub(window_start).min(window.len());
    let preceding = &window[..rel];
    let line = memchr::memchr_iter(b'\n', preceding).count() + 1;
    let last_nl = preceding.iter().rposition(|&b| b == b'\n').unwrap_or(0);
    let col = if last_nl == 0 { rel } else { rel - last_nl };
    (line, col)
}

fn contains_word(haystack: &[u8], needle: &[u8]) -> bool {
    for idx in memchr::memmem::find_iter(haystack, needle) {
        if is_word_boundary(haystack, idx, needle.len()) {
            return true;
        }
    }
    false
}

fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}

fn is_strongly_likely_code(bytes: &[u8]) -> bool {
    let sample_len = bytes.len().min(4096);
    let sample = &bytes[..sample_len];
    if is_prose_like(sample) {
        return false;
    }

    let mut score = 0i32;
    let primary: &[&[u8]] = &[b"function", b"fn", b"def", b"class", b"import", b"export"];
    let tokens: &[&[u8]] = &[
        b"function",
        b"class",
        b"struct",
        b"impl",
        b"fn",
        b"def",
        b"trait",
        b"enum",
        b"interface",
        b"let",
        b"const",
        b"var",
        b"import",
        b"export",
        b"using",
        b"async",
        b"=>",
        b"{",
    ];
    let mut primary_hit = false;
    for token in tokens.iter() {
        if contains_word(sample, token) {
            score += 1;
            if primary.iter().any(|p| *p == *token) {
                primary_hit = true;
            }
        }
    }
    let semicolons = memchr::memmem::find_iter(sample, b";").count();
    let braces = memchr::memmem::find_iter(sample, b"{").count();
    let parens = memchr::memmem::find_iter(sample, b"(").count();
    let code_punct = (semicolons + braces + parens) as i32;
    primary_hit && score >= 4 && code_punct >= 6
}

fn is_prose_like(sample: &[u8]) -> bool {
    let text_ratio = sample
        .iter()
        .filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
        .count() as f64
        / sample.len().max(1) as f64;
    if text_ratio < 0.7 {
        return true;
    }
    if memchr::memmem::find(sample, b"```").is_some() {
        return true;
    }
    let lt = memchr::memmem::find_iter(sample, b"<").count();
    let gt = memchr::memmem::find_iter(sample, b">").count();
    if lt > 10 && gt > 10 && memchr::memmem::find(sample, b"<script").is_none() {
        return true;
    }
    let mut md_lines = 0usize;
    let mut non_empty_lines = 0usize;
    for line in sample.split(|&b| b == b'\n') {
        let mut i = 0;
        while i < line.len() && line[i].is_ascii_whitespace() {
            i += 1;
        }
        let trimmed = &line[i..];
        if trimmed.is_empty() {
            continue;
        }
        non_empty_lines += 1;
        let md = trimmed.starts_with(b"#")
            || trimmed.starts_with(b"-")
            || trimmed.starts_with(b"*")
            || trimmed.starts_with(b">")
            || trimmed.starts_with(b"|")
            || (trimmed.len() > 1 && trimmed[0].is_ascii_digit() && trimmed[1] == b'.')
            || trimmed.starts_with(b"```")
            || trimmed.starts_with(b"- [")
            || trimmed.starts_with(b"* [");
        if md {
            md_lines += 1;
        }
    }
    non_empty_lines > 0 && md_lines * 2 >= non_empty_lines
}

fn normalize_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.len() < 2 {
        return None;
    }
    if trimmed.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    if trimmed.chars().any(|c| c.is_whitespace()) {
        return None;
    }
    Some(trimmed.to_string())
}

fn is_reasonable_ident(raw: &str) -> bool {
    let s = raw.trim();
    if s.len() < 2 || s.len() > 32 {
        return false;
    }
    if s.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let first = s.chars().next().unwrap_or('_');
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    !s.chars().any(|c| c.is_whitespace())
}

fn is_file_extension(raw: &str) -> bool {
    matches!(raw.to_ascii_lowercase().as_str(), "js" | "css" | "png" | "jpg" | "jpeg" | "svg" | "html")
}

fn is_code_extension(ext: &str) -> bool {
    matches!(
        ext,
        "rs" | "js" | "jsx" | "ts" | "tsx" | "py" | "go" | "java" | "c" | "cpp" | "h" | "hpp"
            | "cs" | "rb" | "php" | "swift" | "kt" | "kts" | "scala" | "sh" | "bash" | "zsh"
            | "ps1" | "sql" | "lua" | "r" | "m" | "mm" | "dart" | "clj" | "ex" | "exs"
            | "el" | "erl" | "hs" | "ml" | "fs" | "fsx" | "s" | "asm"
    )
}

fn is_data_extension(ext: &str) -> bool {
    matches!(
        ext,
        "md"
            | "markdown"
            | "txt"
            | "rst"
            | "adoc"
            | "json"
            | "yaml"
            | "yml"
            | "toml"
            | "lock"
            | "csv"
            | "tsv"
            | "log"
            | "html"
            | "htm"
            | "xml"
            | "env"
    )
}

fn extract_extension_from_hint(hint: &str) -> Option<String> {
    let mut end = hint.len();
    if let Some(idx) = hint.find('?') {
        end = end.min(idx);
    }
    if let Some(idx) = hint.find('#') {
        end = end.min(idx);
    }
    let trimmed = &hint[..end];
    let file = trimmed.rsplit('/').next().unwrap_or(trimmed);
    let ext = file.rsplit('.').next()?;
    if ext == file || ext.is_empty() {
        None
    } else {
        Some(ext.to_lowercase())
    }
}

#[cfg(feature = "js-ast")]
fn analyze_flow_context_js(bytes: &[u8], pos: usize) -> Option<FlowContext> {
    use std::cell::RefCell;
    use tree_sitter::{Parser, Query, Range};

    thread_local! {
        static PARSER: RefCell<Parser> = {
            let mut parser = Parser::new();
            let _ = parser.set_language(js_language());
            RefCell::new(parser)
        };
    }

    static FUNC_QUERY: OnceLock<Result<Query, tree_sitter::QueryError>> = OnceLock::new();
    static CTRL_QUERY: OnceLock<Result<Query, tree_sitter::QueryError>> = OnceLock::new();
    static ASSIGN_QUERY: OnceLock<Result<Query, tree_sitter::QueryError>> = OnceLock::new();

    let func_query = FUNC_QUERY.get_or_init(|| {
        Query::new(
            js_language(),
            "(function_declaration name: (identifier) @name) @func\
             (method_definition name: (property_identifier) @name) @func\
             (function_expression name: (identifier) @name) @func\
             (arrow_function) @func",
        )
    });
    let ctrl_query = CTRL_QUERY.get_or_init(|| {
        Query::new(
            js_language(),
            "(if_statement) @ctrl\
             (for_statement) @ctrl\
             (for_in_statement) @ctrl\
             (while_statement) @ctrl\
             (do_statement) @ctrl\
             (switch_statement) @ctrl\
             (try_statement) @ctrl\
             (catch_clause) @ctrl\
             (return_statement) @ctrl",
        )
    });
    let assign_query = ASSIGN_QUERY.get_or_init(|| {
        Query::new(
            js_language(),
            "(assignment_expression) @assign (variable_declarator) @assign",
        )
    });

    let window = 4096usize;
    let start = pos.saturating_sub(window);
    let end = (pos + window).min(bytes.len());
    let start_point = byte_to_point(bytes, start);
    let end_point = byte_to_point(bytes, end);
    let range = Range {
        start_byte: start,
        end_byte: end,
        start_point,
        end_point,
    };

    let tree = PARSER.with(|parser| {
        let mut parser = parser.borrow_mut();
        let _ = parser.set_included_ranges(&[range]);
        parser.parse(bytes, None)
    })?;

    let root = tree.root_node();
    let node = root.descendant_for_byte_range(pos, pos)?;

    let mut ctx = FlowContext::default();

    let mut depth = 0usize;
    let mut cursor = Some(node);
    while let Some(n) = cursor {
        if n.kind() == "statement_block" || n.kind() == "block" {
            depth += 1;
        }
        cursor = n.parent();
    }
    ctx.block_depth = depth;

    if let Ok(func_query) = func_query {
        if let Some((func_node, name)) = find_js_enclosing_function(root, node, bytes, func_query) {
            ctx.scope_kind = Some("function".to_string());
            ctx.scope_name = name;
            let start = func_node.start_position();
            ctx.scope_line = Some(start.row + 1);
            ctx.scope_col = Some(start.column + 1);
            ctx.scope_distance = Some(pos.saturating_sub(func_node.start_byte()));
        }
    }

    if let Ok(ctrl_query) = ctrl_query {
        if let Some(ctrl_node) = find_js_control_ancestor(root, node, bytes, ctrl_query) {
            ctx.nearest_control = Some(ctrl_node.kind().to_string());
            let start = ctrl_node.start_position();
            ctx.nearest_control_line = Some(start.row + 1);
            ctx.nearest_control_col = Some(start.column + 1);
        }
    }

    if let Ok(assign_query) = assign_query {
        if let Some(assign) = find_js_assignment_ancestor(root, node, bytes, assign_query) {
            ctx.assignment_distance = Some(pos.saturating_sub(assign.start_byte()));
        }
    }

    if let Some(ret) = find_js_return_ancestor(node) {
        ctx.return_distance = Some(pos.saturating_sub(ret.start_byte()));
    }

    if let Some(chain) = find_js_call_chain(node, bytes) {
        ctx.call_chain_hint = Some(chain);
    }

    Some(ctx)
}

#[cfg(feature = "js-ast")]
static JS_LANGUAGE: OnceLock<Language> = OnceLock::new();

#[cfg(feature = "js-ast")]
fn js_language() -> &'static Language {
    JS_LANGUAGE.get_or_init(|| tree_sitter_javascript::LANGUAGE.into())
}

#[cfg(not(feature = "js-ast"))]
fn analyze_flow_context_js(_bytes: &[u8], _pos: usize) -> Option<FlowContext> {
    None
}

#[cfg(feature = "js-ast")]
fn find_js_enclosing_function<'a>(
    root: tree_sitter::Node<'a>,
    node: tree_sitter::Node<'a>,
    bytes: &'a [u8],
    query: &tree_sitter::Query,
) -> Option<(tree_sitter::Node<'a>, Option<String>)> {
    use tree_sitter::StreamingIterator;
    let mut cursor = tree_sitter::QueryCursor::new();
    let mut best: Option<(tree_sitter::Node<'a>, Option<String>, usize)> = None;
    let mut matches = cursor.matches(query, root, bytes);
    while let Some(m) = matches.next() {
        let func_node = m.captures.iter().find(|c| c.node.kind().contains("function") || c.node.kind() == "method_definition").map(|c| c.node).unwrap_or_else(|| m.captures[0].node);
        let name = m
            .captures
            .iter()
            .find(|c| c.node.kind() == "identifier" || c.node.kind() == "property_identifier")
            .map(|c| node_text(bytes, c.node));
        let start = func_node.start_byte();
        if start <= node.start_byte() {
            let dist = node.start_byte().saturating_sub(start);
            if best.as_ref().map(|(_, _, d)| dist < *d).unwrap_or(true) {
                best = Some((func_node, name, dist));
            }
        }
    }
    best.map(|(n, name, _)| (n, name))
}

#[cfg(feature = "js-ast")]
fn find_js_control_ancestor<'a>(
    root: tree_sitter::Node<'a>,
    node: tree_sitter::Node<'a>,
    bytes: &'a [u8],
    query: &tree_sitter::Query,
) -> Option<tree_sitter::Node<'a>> {
    use tree_sitter::StreamingIterator;
    let mut cursor = tree_sitter::QueryCursor::new();
    let mut best: Option<(tree_sitter::Node<'a>, usize)> = None;
    let mut matches = cursor.matches(query, root, bytes);
    while let Some(m) = matches.next() {
        let ctrl_node = m.captures[0].node;
        let start = ctrl_node.start_byte();
        if start <= node.start_byte() {
            let dist = node.start_byte().saturating_sub(start);
            if best.as_ref().map(|(_, d)| dist < *d).unwrap_or(true) {
                best = Some((ctrl_node, dist));
            }
        }
    }
    best.map(|(n, _)| n)
}

#[cfg(feature = "js-ast")]
fn find_js_assignment_ancestor<'a>(
    root: tree_sitter::Node<'a>,
    node: tree_sitter::Node<'a>,
    bytes: &'a [u8],
    query: &tree_sitter::Query,
) -> Option<tree_sitter::Node<'a>> {
    use tree_sitter::StreamingIterator;
    let mut cursor = tree_sitter::QueryCursor::new();
    let mut best: Option<(tree_sitter::Node<'a>, usize)> = None;
    let mut matches = cursor.matches(query, root, bytes);
    while let Some(m) = matches.next() {
        let assign_node = m.captures[0].node;
        let start = assign_node.start_byte();
        if start <= node.start_byte() {
            let dist = node.start_byte().saturating_sub(start);
            if best.as_ref().map(|(_, d)| dist < *d).unwrap_or(true) {
                best = Some((assign_node, dist));
            }
        }
    }
    best.map(|(n, _)| n)
}

#[cfg(feature = "js-ast")]
fn find_js_return_ancestor<'a>(node: tree_sitter::Node<'a>) -> Option<tree_sitter::Node<'a>> {
    let mut cursor = Some(node);
    while let Some(n) = cursor {
        if n.kind() == "return_statement" {
            return Some(n);
        }
        cursor = n.parent();
    }
    None
}

#[cfg(feature = "js-ast")]
fn find_js_call_chain<'a>(node: tree_sitter::Node<'a>, bytes: &'a [u8]) -> Option<String> {
    let mut cursor = Some(node);
    while let Some(n) = cursor {
        if n.kind() == "member_expression" {
            let obj = n.child_by_field_name("object");
            let prop = n.child_by_field_name("property");
            if let (Some(o), Some(p)) = (obj, prop) {
                let left = node_text(bytes, o);
                let right = node_text(bytes, p);
                if is_reasonable_ident(&left) && is_reasonable_ident(&right) {
                    return Some(format!("{}.{}", left, right));
                }
            }
        }
        cursor = n.parent();
    }
    None
}

#[cfg(feature = "js-ast")]
fn node_text<'a>(bytes: &'a [u8], node: tree_sitter::Node<'a>) -> String {
    let range = node.byte_range();
    String::from_utf8_lossy(&bytes[range]).to_string()
}

#[cfg(feature = "js-ast")]
fn byte_to_point(bytes: &[u8], pos: usize) -> tree_sitter::Point {
    let mut row = 0usize;
    let mut col = 0usize;
    let end = pos.min(bytes.len());
    for &b in &bytes[..end] {
        if b == b'\n' {
            row += 1;
            col = 0;
        } else {
            col += 1;
        }
    }
    tree_sitter::Point { row, column: col }
}

fn trim_value(value: &str, max_len: usize) -> String {
    if value.len() <= max_len {
        return value.to_string();
    }
    let mut out = value.chars().take(max_len.saturating_sub(1)).collect::<String>();
    out.push('…');
    out
}