pub mod cli;
pub mod entropy;
pub mod heuristics;
pub mod keyword;
pub mod output;
pub mod scan;
pub mod utils;

#[cfg(test)]
mod tests {
    use super::entropy::{calculate_entropy, is_harmless_text, is_likely_charset, scan_for_secrets, scan_for_requests};
    use std::collections::HashSet;
    use super::keyword::process_search;
    use super::heuristics::FlowMode;
    use super::scan::{build_exclude_matcher, is_excluded_path, Heatmap, Lineage, parse_unified_diff};
    use super::utils::find_preceding_identifier;
    use std::path::Path;

    #[test]
    fn entropy_uniform_is_zero() {
        let data = b"aaaaaa";
        let e = calculate_entropy(data);
        assert!(e >= 0.0 && e < 0.0001);
    }

    #[test]
    fn harmless_base64_detected() {
        // "hello world" -> aGVsbG8gd29ybGQ=
        let s = "aGVsbG8gd29ybGQ=";
        assert!(is_harmless_text(s));
        assert!(!is_harmless_text("not_base64!$#"));
    }

    #[test]
    fn detect_likely_charset() {
        assert!(is_likely_charset("abcdefgabcde"));
        assert!(is_likely_charset("123456"));
        assert!(!is_likely_charset("randomstringwithhighentropy"));
    }

    #[test]
    fn find_identifier_before_secret() {
        let s = b"const apiKey = \"ABCDEF123456\";";
        // start index of 'ABCDEF123456'
        let start = s.windows(12).position(|w| w == b"ABCDEF123456").unwrap();
        let id = find_preceding_identifier(s, start).unwrap();
        assert_eq!(id, "apiKey");
    }

    #[test]
    fn process_search_records() {
        let data = b"let token = \"secret123\";\n";
        let keywords = vec!["token".to_string()];
        let (out, records) = process_search(data, "test.rs", &keywords, 10, false, FlowMode::Off, None);
        assert!(out.contains("token"));
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, "keyword");
    }

    #[test]
    fn deep_scan_story_includes_counts() {
        let data = b"fn main(){encrypt(x); encrypt(y);} encrypt(z);";
        let keywords = vec!["encrypt".to_string()];
        let (out, _records) = process_search(data, "test.rs", &keywords, 10, true, FlowMode::Heuristic, None);
        assert!(out.contains("Story:"));
        assert!(out.contains("call-sites"));
        assert!(out.contains("Flow:"));
        assert!(out.contains("scope "));
    }

    #[test]
    fn entropy_ignores_url_context() {
        let css = b"@font-face{src:url(https://fonts.gstatic.com/s/roboto/v50/ABCDEFGHIJKLmnopqrstuvwxyz0123456789-XYZ.woff2) format('woff2');}";
        let tags = HashSet::new();
        let (_out, records) = scan_for_secrets("test.css", css, 4.0, 40, &tags, false, FlowMode::Off, None, false);
        assert!(records.is_empty());
    }

    #[test]
    fn entropy_emits_url_tag_when_enabled() {
        let css = b"@font-face{src:url(https://fonts.gstatic.com/s/roboto/v50/ABCDEFGHIJKLmnopqrstuvwxyz0123456789-XYZ.woff2) format('woff2');}";
        let mut tags = HashSet::new();
        tags.insert("url".to_string());
        let (_out, records) = scan_for_secrets("test.css", css, 4.0, 40, &tags, false, FlowMode::Off, None, false);
        assert!(records.iter().any(|r| r.kind == "url"));
    }

    #[test]
    fn exclude_lock_files_by_default() {
        let matcher = build_exclude_matcher(&[]);
        assert!(is_excluded_path(Path::new("Cargo.lock"), &matcher));
        assert!(is_excluded_path(Path::new("package-lock.json"), &matcher));
        assert!(is_excluded_path(Path::new("deps/yarn.lock"), &matcher));
    }

    #[test]
    fn exclude_custom_patterns() {
        let matcher = build_exclude_matcher(&["target/**".to_string(), "**/*.min.js".to_string()]);
        assert!(is_excluded_path(Path::new("target/debug/app"), &matcher));
        assert!(is_excluded_path(Path::new("web/app.min.js"), &matcher));
        assert!(!is_excluded_path(Path::new("src/main.rs"), &matcher));
    }

    #[test]
    fn heatmap_renders_summary() {
        let mut map = Heatmap::default();
        map.update(
            "file.rs",
            &[super::output::MatchRecord {
                source: "file.rs".to_string(),
                kind: "entropy".to_string(),
                matched: "ABCDEF123456".to_string(),
                line: 1,
                col: 1,
                entropy: Some(5.0),
                context: "test".to_string(),
                identifier: Some("token".to_string()),
            }],
        );
        let summary = map.render().unwrap_or_default();
        assert!(summary.contains("Risk Heatmap"));
        assert!(summary.contains("file.rs"));
    }

    #[test]
    fn lineage_renders_summary() {
        let mut lineage = Lineage::default();
        lineage.update(
            "a.rs",
            &[super::output::MatchRecord {
                source: "a.rs".to_string(),
                kind: "entropy".to_string(),
                matched: "ABCDEFGH12345678".to_string(),
                line: 2,
                col: 1,
                entropy: Some(5.5),
                context: "test".to_string(),
                identifier: None,
            }],
        );
        let summary = lineage.render().unwrap_or_default();
        assert!(summary.contains("Secret Lineage"));
        assert!(summary.contains("a.rs"));
    }

    #[test]
    fn parse_diff_added_lines() {
        let diff = "diff --git a/src/a.rs b/src/a.rs\n+++ b/src/a.rs\n@@ -1,0 +5,2 @@\n+foo\n+bar\n@@ -10,2 +20,1 @@\n+baz\n";
        let map = parse_unified_diff("/repo", diff);
        let key = std::path::Path::new("/repo/src/a.rs");
        let ranges = map.get(key).unwrap();
        assert!(ranges.contains(&(5, 6)));
        assert!(ranges.contains(&(20, 20)));
    }

    #[test]
    fn request_trace_standalone_detects_fetch() {
        let js = b"async function run(){const url=apiBase+\"/v1\";return fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:'x'})}";
        let (out, records) = scan_for_requests("test.js", js, 80, FlowMode::Off, None, Some(Path::new("test.js")));
        assert!(out.contains("Request tracing"));
        assert!(out.contains("Request:"));
        assert!(!records.is_empty());
        assert!(records.iter().any(|r| r.kind == "request-trace"));
    }
}
