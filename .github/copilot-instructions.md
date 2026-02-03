# Copilot Instructions (argus)

## Big-picture architecture
- Single-binary Rust CLI; core logic is in [../src/main.rs](../src/main.rs).
- Two scan paths:
  - Local/recursive scanning via `run_recursive_scan()` using `ignore::WalkBuilder` + `rayon` with `mmap` (memmap2).
  - Remote URL scanning via `ureq` streaming into a temp file, then `mmap`.
- Two detection engines:
  - Keyword search: `process_search()` uses Aho-Corasick.
  - Entropy search: `scan_for_secrets()` with Shannon entropy + heuristics (`is_harmless_text`, `is_likely_charset`).
- Output handling is centralized in `run_analysis()` and `OutputMode` (single JSON array, NDJSON streaming, or per-file JSON).
- Attack surface hints live in `scan.rs` (`extract_attack_surface_hints`, `classify_endpoint`, `build_attack_surface_links`).

## Key workflows (TDD)
- Build: `cargo build`
- Tests: `cargo test`
- Run: `cargo run -- --help` or `rsearch -t <path_or_url> [--entropy|-k ...]`
- Follow strict TDD: add tests in the `#[cfg(test)]` module in [../src/main.rs](../src/main.rs) before changing logic (attack-surface tests live here).

## Project-specific conventions
- CLI uses `clap` derive; running without args prints help (`Cli::command().print_help()`).
- JSON output is only emitted when `--json` is set; `--output` + `--output-format` controls sinks:
  - `single` (default): collects all matches, writes one JSON file at end.
  - `ndjson`: streams JSON lines during scanning.
  - `per-file`: writes one JSON file per source into the output directory.
- Colorized output uses `owo-colors`; `--no-color` disables via `owo_colors::set_override(false)`.
- Logging uses `env_logger` + `log`; configure with `RUST_LOG` (e.g., `RUST_LOG=info`).
- `--request-trace` runs standalone HTTP request tracing and also enriches secret findings with request context.

## File/data handling details
- Files > 200MB are skipped; binary detection checks for NUL bytes in the first 1KB.
- `run_recursive_scan()` uses `rayon::par_bridge()` for parallel traversal; output buffering prevents interleaving.
- URL scanning uses `ureq` with read/connect timeouts.

## Dependencies to be aware of
- `memmap2`, `ignore`, `rayon`, `aho-corasick`, `ureq`, `serde/serde_json`, `owo-colors`, `env_logger`.

## Examples from this codebase
- Add new output modes or fields in `MatchRecord` in [../src/main.rs](../src/main.rs) and update JSON sinks in `OutputMode`.
- Heuristic changes should update tests in the `tests` module in [../src/main.rs](../src/main.rs).
