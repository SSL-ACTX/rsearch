use argus::cli::Cli;
use argus::output::{build_output_mode, finalize_output, handle_output};
use argus::scan::{load_diff_map, load_suppression_rules, run_analysis, run_recursive_scan, DiffSummary, Heatmap, Lineage};
use clap::CommandFactory;
use clap::Parser;
use log::{error, info, warn};
use memmap2::Mmap;
use rayon::ThreadPoolBuilder;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;
use std::sync::{Arc, Mutex};

#[cfg(test)]
mod tests {
    use argus::scan::{apply_suppression_rules, build_attack_surface_links, build_suppression_hints, classify_endpoint, extract_attack_surface_hints, DiffSummary, SuppressionRule};
    use argus::entropy::adaptive_confidence_entropy;
    use argus::output::MatchRecord;

    #[test]
    fn attack_surface_extracts_endpoints() {
        let src = br#"
const API_BASE_URL = "http://localhost:5000";
const PROD = "https://api.example.com";
fetch(`${API_BASE_URL}/api/projects`);
fetch("/api/account/profile/me");
"#;
        let hints = extract_attack_surface_hints(src);
        assert!(hints.iter().any(|h| h.url.contains("localhost:5000")));
        assert!(hints.iter().any(|h| h.url.contains("/api/account/profile/me")));
        assert!(hints.iter().any(|h| h.url.contains("https://api.example.com")));
    }

    #[test]
    fn classify_endpoint_detects_public_localhost() {
        assert_eq!(classify_endpoint("http://localhost:5000"), "localhost");
        assert_eq!(classify_endpoint("https://api.example.com"), "public");
        assert_eq!(classify_endpoint("/api/projects"), "relative");
    }

    #[test]
    fn attack_surface_links_requests_to_endpoints() {
        let src = br#"
const API_BASE_URL = "http://localhost:5000";
fetch(`${API_BASE_URL}/api/projects`);
"#;
        let hints = extract_attack_surface_hints(src);
        let records = vec![MatchRecord {
            source: "test.js".to_string(),
            kind: "request-trace".to_string(),
            matched: "fetch".to_string(),
            line: 2,
            col: 1,
            entropy: None,
            context: "fetch(`${API_BASE_URL}/api/projects`)".to_string(),
            identifier: None,
        }];
        let links = build_attack_surface_links(&records, &hints);
        assert!(!links.is_empty());
        assert!(links.iter().any(|l| l.endpoint.contains("/api/projects")));
        assert!(links.iter().any(|l| l.class == "localhost"));
    }

    #[test]
    fn diff_summary_renders() {
        let mut summary = DiffSummary::default();
        summary.update(
            "src/lib.rs",
            &[MatchRecord {
                source: "src/lib.rs".to_string(),
                kind: "keyword".to_string(),
                matched: "token".to_string(),
                line: 1,
                col: 1,
                entropy: None,
                context: "token".to_string(),
                identifier: None,
            }],
        );
        let out = summary.render().unwrap_or_default();
        assert!(out.contains("Diff Summary"));
        assert!(out.contains("keyword"));
    }

    #[test]
    fn suppression_hints_generated_for_examples() {
        let recs = vec![MatchRecord {
            source: "src/app.js".to_string(),
            kind: "keyword".to_string(),
            matched: "token".to_string(),
            line: 10,
            col: 5,
            entropy: None,
            context: "// example token for docs".to_string(),
            identifier: Some("exampleToken".to_string()),
        }];
        let hints = build_suppression_hints(&recs);
        assert!(!hints.is_empty());
        assert!(hints[0].rule.contains("id:"));
    }

    #[test]
    fn suppression_rules_filter_matches() {
        let recs = vec![MatchRecord {
            source: "src/app.js".to_string(),
            kind: "keyword".to_string(),
            matched: "token".to_string(),
            line: 10,
            col: 5,
            entropy: None,
            context: "token".to_string(),
            identifier: Some("apiToken".to_string()),
        }];
        let rules = vec![SuppressionRule::Id("apiToken".to_string())];
        let (filtered, suppressed) = apply_suppression_rules(&recs, &rules);
        assert_eq!(suppressed, 1);
        assert!(filtered.is_empty());
    }

    #[test]
    fn adaptive_confidence_downweights_docs() {
        let raw = "// example token used in docs";
        let (signals, confidence) = adaptive_confidence_entropy(
            raw,
            Some("exampleToken"),
            "abcdEFGHijklMNOPqrstUVWX",
            5.2,
            "docs/README.md",
        );
        assert!(signals.iter().any(|s| *s == "doc-context"));
        assert!(confidence <= 6);
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let start_time = Instant::now();
    let cli = Cli::parse();

    // If run with no arguments, print help and exit.
    if std::env::args().len() <= 1 {
        Cli::command().print_help()?;
        println!();
        return Ok(());
    }

    // Initialize logging from environment (RUST_LOG)
    env_logger::Builder::from_default_env().format_timestamp(None).init();

    // Handle colorized output toggle
    if cli.no_color {
        owo_colors::set_override(false);
    }

    // Configure global thread pool if -j is set
    if cli.threads > 0 {
        match ThreadPoolBuilder::new().num_threads(cli.threads).build_global() {
            Ok(()) => info!("Set global thread pool to {} threads", cli.threads),
            Err(e) => warn!("Could not set global thread pool: {}. Continuing with default.", e),
        }
    }

    if cli.keyword.is_empty() && !cli.entropy {
        error!("Provide a keyword (-k) OR enable entropy scanning (--entropy)");
        return Ok(());
    }

    // Create a configured HTTP agent with reasonable timeouts to avoid hanging.
    let agent = ureq::AgentBuilder::new()
        .timeout_read(Duration::from_secs(15))
        .timeout_connect(Duration::from_secs(5))
        .build();

    let output_mode = build_output_mode(&cli);

    let heatmap = Arc::new(Mutex::new(Heatmap::default()));
    let lineage = Arc::new(Mutex::new(Lineage::default()));
    let diff_summary = Arc::new(Mutex::new(DiffSummary::default()));

    let diff_map = if cli.diff {
        load_diff_map(&cli.diff_base)
    } else {
        None
    };

    let suppression_rules = cli
        .suppress
        .as_deref()
        .map(load_suppression_rules)
        .unwrap_or_default();

    for input in &cli.target {
        if input.starts_with("http") {
            info!("Streaming {}", input);
            match agent.get(input).call() {
                Ok(response) => {
                    let mut tmp = NamedTempFile::new()?;
                    std::io::copy(&mut response.into_reader(), &mut tmp)?;

                    let file = tmp.as_file();
                    // Safety: Temp file is exclusive to this process.
                    match unsafe { Mmap::map(file) } {
                        Ok(mmap) => {
                            let (out, recs) = run_analysis(
                                input,
                                &mmap,
                                &cli,
                                None,
                                Some(input),
                                Some(&heatmap),
                                Some(&lineage),
                                Some(&diff_summary),
                                Some(&suppression_rules),
                                diff_map.as_ref(),
                            );
                            handle_output(&output_mode, &cli, &out, recs, None, input);
                        }
                        Err(e) => warn!("Could not map streamed file for {}: {}", input, e),
                    }
                }
                Err(e) => warn!("HTTP error fetching {}: {}", input, e),
            }
        } else {
            run_recursive_scan(
                input,
                &cli,
                &output_mode,
                Some(&heatmap),
                Some(&lineage),
                Some(&diff_summary),
                Some(&suppression_rules),
                diff_map.as_ref(),
            );
        }
    }

    if !cli.json {
        if let Ok(guard) = heatmap.lock() {
            if let Some(summary) = guard.render() {
                println!("{}", summary);
            }
        }
        if let Ok(guard) = lineage.lock() {
            if let Some(summary) = guard.render() {
                println!("{}", summary);
            }
        }
        if cli.diff {
            if let Ok(guard) = diff_summary.lock() {
                if let Some(summary) = guard.render() {
                    println!("{}", summary);
                }
            }
        }
    }

    let duration = start_time.elapsed();
    println!("🏁 Scan completed in {:.2?}", duration);

    finalize_output(&output_mode, &cli);

    Ok(())
}