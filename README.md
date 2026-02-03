<div align="center">

![argus Banner](https://capsule-render.vercel.app/api?type=waving&color=0:0f1724,100:0b5ed7&height=160&section=header&text=argus&fontSize=80&fontColor=FFFFFF&animation=fadeIn&fontAlignY=35&rotate=2&stroke=0b5ed7&strokeWidth=2&desc=High-performance%20entropy-based%20secret%20scanner&descSize=16&descAlignY=60)

![Language](https://img.shields.io/badge/language-Rust-orange.svg?style=for-the-badge&logo=rust)
![License](https://img.shields.io/badge/license-AGPL_3.0-blue.svg?style=for-the-badge)
![Version](https://img.shields.io/badge/version-0.5.0-green.svg?style=for-the-badge)

[Installation](#installation) • [Usage](#usage) • [Output Modes](#output-modes) • [Performance Notes](#performance-notes) • [License](#license)

</div>

**argus** is a high-performance, multi-threaded security scanner designed to detect secrets, keys, and sensitive information in local files and remote URLs. It combines Shannon entropy analysis with fast multi-pattern matching to find both unknown and known secrets while minimizing false positives.

---

## Overview

argus targets both explicit secret indicators (keywords, tokens) and implicit secrets (high-entropy strings). It is optimized for large codebases and binary artifacts by leveraging memory mapping and parallel scanning.

### Highlights

- High-performance keyword search via Aho-Corasick
- Entropy-based secret detection using Shannon entropy
- Adaptive confidence scoring with explainable signals
- Request tracing (fetch/axios/XHR/curl) with endpoint classification
- Diff-only scan summaries for added lines
- NDJSON output for large scans

---

## Installation

Prerequisites: Rust toolchain (rustup).

Build from source:

```bash
git clone https://github.com/SSL-ACTX/argus.git
cd argus
cargo build --release

# run the binary
./target/release/argus --help
```

Install globally:

```bash
cargo install --path .
```

---

## Usage

At minimum, provide one or more targets (`-t`) and choose a scanning mode (`--entropy` or `-k`).

```bash
argus -t <path_or_url> [OPTIONS]
```

### Common examples

- Scan a directory for high-entropy secrets:

```bash
argus -t ./src --entropy
```

- Scan a remote file for keywords:

```bash
argus -t https://example.com/app.js -k API_KEY -k secret
```

- Emit machine-readable JSON to a file (single file):

```bash
argus -t ./repo --entropy --json --output ./results.json
```

---

## Quick Start

> [!TIP]
Use this quick command to scan the current repository for high-entropy secrets and stream results as NDJSON (low memory):

```bash
argus -t . --entropy --json --output ./results.ndjson --output-format ndjson -j 4
```

> [!TIP]
If you prefer a single JSON file with all results (small projects), use `--output-format single` and a `.json` output path.

```bash
argus -t ./repo --entropy --json --output ./results.json --output-format single
```

> [!NOTE]
`--output-format per-file` will create one JSON file per scanned source inside the directory you provide to `--output`.

---

## Project Layout

> [!NOTE]
Core logic is now organized under `src/lib.rs` with focused modules for CLI, scanning, output, entropy, keyword search, and utilities. The binary entry point in `src/main.rs` is intentionally thin.
- All unit tests are consolidated in `src/lib.rs` under the `#[cfg(test)]` module to keep test discovery in one place.

---

## Options

Core flags:

- `-t, --target <TARGET>`: Target file, directory, or URL (required; may be repeated)
- `-k, --keyword <KEYWORD>`: Keyword to search for (repeatable)
- `--entropy`: Enable entropy-based secret detection
- `--diff`: Scan only added lines from a git diff and show a Diff Summary in human output
- `--suppress <PATH>`: Load suppression rules and filter findings
- `--suppress-out <PATH>`: Append suppression hints to a file

Output & controls:

- `--json`: Emit JSON output
- `--output <PATH>`: Path or directory for JSON output (behavior depends on `--output-format`)
- `--output-format <single|ndjson|per-file>`: Output mode for JSON (default: `single`)
- `--no-color`: Disable colorized output for CI and non-TTY environments
- `-x, --exclude <PATTERN>`: Exclude glob patterns (repeatable). Lock files are excluded by default.

Tuning:

- `--threshold <FLOAT>`: Entropy threshold (default: 4.5)
- `-c, --context <BYTES>`: Context window size (default: 80)
- `-j, --threads <N>`: Number of threads (0 = auto)
- `--emit-tags <TAGS>`: Comma-separated tag emissions (e.g. `url`). Adds tagged findings without treating them as secrets.

Enrichment:

- `--deep-scan`: Adds a story for each match (counts, neighbors, call-sites)
- `--flow-scan`: Adds lightweight control-flow context using heuristics (no AST). Skips non-code files automatically.
- `--request-trace`: Adds HTTP request context for secrets and runs standalone request tracing

---

## Deep Scan and Flow Scan

`--deep-scan` augments each match with statistics that help triage relevance (frequency in file, nearest neighbor distance, call-site proximity, span/density, and identifier hints). It now adds contextual signals (e.g., header/auth/keyword hints), token typing, a confidence score, and an entropy cluster summary to make the “story” more actionable. When flow is available, it also prints a compact **Context Graph** tree (owner/scope/path/call/control hints).

When running in human output mode, argus also prints a **Risk Heatmap** summary at the end of the scan (top files by weighted score) and a **Secret Lineage** summary that highlights repeated tokens across files (origin → propagation). Attack surface hints now classify endpoints (public/localhost/internal/relative) and link request-trace calls to nearby endpoints.

In deep-scan mode, rsearch also emits **Suppression Hints** (experimental) for likely false positives, with a suggested rule, reasons, confidence, and a decay window.

## Request Tracing

`--request-trace` scans for HTTP calls (fetch/axios/XHR/curl), reconstructs template URLs, and classifies endpoints (public/localhost/internal/relative). In deep-scan output it also links requests to nearby endpoint hints so you can see the likely attack surface at a glance.

## Smart Suppression

Suppression rules can be loaded from a file (`--suppress`) and hints can be appended via `--suppress-out`.

Rule formats:

- `id:<identifier>` — suppress by identifier name
- `<source>:<line>:<kind>` — suppress by source path, line, and kind

`--flow-scan` is a control-flow context pass that tries to associate each match with surrounding structure without parsing an AST by default. It emits a compact, TUI-friendly single-line summary and reports scope and control hints such as:

- Scope kind/name and source location
- Scope path breadcrumb with depth and distance
- Container and block depth
- Nearest control keyword (if/for/while/return) and its location
- Assignment and return distance from the match
- A best-effort call chain hint

Flow scan is only executed for content that looks like code; markdown/prose-heavy content is skipped automatically to avoid noisy context. For JavaScript, heuristic flow is disabled by default; enable the optional AST feature to analyze JS files.

### Optional JS AST (feature flag)

For higher accuracy on JavaScript, enable the lightweight AST parser:

```bash
cargo build --features js-ast
```

With `js-ast` enabled, JS flow context is derived from a real syntax tree. Without it, JS flow output is suppressed to avoid false positives.

### Optional Syntax Highlighting (feature flag)

For syntax-highlighted context output, enable:

```bash
cargo build --features highlighting
```

---

## Output Modes

Three JSON output modes are supported:

- `single`: Collects all matches and writes a single JSON array to `--output` at the end.
- `ndjson`: Streams newline-delimited JSON to `--output` as matches are discovered (low memory footprint).
- `per-file`: Writes one JSON file per scanned source into the directory specified by `--output`.

For large repositories or CI runs prefer `ndjson` to avoid high memory usage.

---

## Performance Notes

argus is I/O-bound; its throughput is limited by disk and network. It minimizes allocations in the hot path and uses a shared thread pool for scanning.

Tips:

- Use `-j` to increase parallelism on multi-core systems.
- Use `ndjson` output for very large runs to avoid accumulating results in memory.

---

## License

This project is licensed under the AGPL-3.0 License. See `LICENSE` for details.

---

<div align="center">

**Author:** Seuriin ([SSL-ACTX](https://github.com/SSL-ACTX))

*v0.5.0*

</div>
