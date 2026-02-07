<div align="center">

![argus Banner](https://capsule-render.vercel.app/api?type=waving&color=0:0f1724,100:0b5ed7&height=160&section=header&text=argus&fontSize=80&fontColor=FFFFFF&animation=fadeIn&fontAlignY=35&rotate=2&stroke=0b5ed7&strokeWidth=2&desc=High-performance%20entropy-based%20secret%20scanner&descSize=16&descAlignY=60)

![Language](https://img.shields.io/badge/language-Rust-orange.svg?style=for-the-badge&logo=rust)
![License](https://img.shields.io/badge/license-AGPL_3.0-blue.svg?style=for-the-badge)
![Version](https://img.shields.io/badge/version-1.1.0-green.svg?style=for-the-badge)

[Installation](#installation) • [Usage](#usage) • [Deep Analysis](#deep-analysis-and-security-heuristics) • [Output Modes](#output-modes) • [License](#license)

</div>

**argus** is a high-performance, multi-threaded security scanner designed to detect secrets, keys, and sensitive information in local files and remote URLs. It combines Shannon entropy analysis with fast multi-pattern matching to find both unknown and known secrets while minimizing false positives.

Unlike traditional regex scanners, argus builds a narrative ("Story") around every finding, analyzing control flow, variable types, and surrounding code topology to distinguish true risks from noise.

---

## Core Capabilities

- **Hybrid Detection Engine**: Combines **Aho-Corasick** keyword search with **Shannon Entropy** analysis to catch both known patterns (API keys, tokens) and unknown random strings.
- **Context-Aware Analysis**: Uses heuristics to understand **flow**, **scope**, and **variable relationships** without requiring a heavy language server.
- **Traffic Reconstruction**: Traces HTTP requests (`fetch`, `axios`, `curl`) to map your application's attack surface and API dependencies.
- **Adaptive Confidence**: Scores every finding based on signals like variable naming, assignment distance, and file type (docs vs source).
- **Git Integration**: Optimized for CI/CD with diff-only scanning (`--diff`) to flag secrets in new code.

---

## Installation

Prerequisites: Rust toolchain (rustup).

### Build from source

```bash
git clone https://github.com/SSL-ACTX/argus.git
cd argus
cargo build --release

# Run the binary
./target/release/argus --help
```

### Install globally

```bash
cargo install --path .
```

---

## Usage

At minimum, provide one or more targets (`-t`) and choose a scanning mode (`--entropy` or `-k`).

```bash
argus -t <path_or_url> [OPTIONS]
```

### Personas (quiet vs debug)

argus ships with two output personas that control noise, story collapsing, and request-trace verbosity:

- **Scan (quiet/CI-safe)**: `--mode scan` or `--quiet` (default)
  - Collapses low-confidence and doc-context stories.
  - Suppresses request-trace details in terminal output.
- **Debug (loud)**: `--mode debug` or `--loud`
  - Expands story blocks and prints request-trace details.

You can override the minimum confidence shown with `--confidence-floor <0-10>` and expand repeated stories with `--expand`.

**Key output controls**
- `--mode scan|debug` — select the output persona.
- `--quiet` / `--loud` — aliases for scan/debug personas.
- `--confidence-floor <0-10>` — drop findings below this confidence.
- `--expand` — expand repeated story blocks.

### Common workflows

**1. Enterprise Secret Scanning (High Precision)**
Scan a repository for high-entropy strings, identifying likely secrets while ignoring common false positives.

```bash
argus -t ./src --entropy --threshold 4.8
```

**2. Targeted Keyword Audit**
Search for specific tokens or legacy keys in a remote file.

```bash
argus -t https://example.com/app.js -k API_KEY -k "Bearer "
```

**3. CI/CD Integration (Machine Readable)**
Output newline-delimited JSON for easy parsing by downstream tools.

```bash
argus -t . --entropy --json --output-format ndjson --output ./results.ndjson
```

**4. Full Security Audit (Deep Scan)**
Enable all heuristics, flow analysis, and request tracing for a comprehensive report.

```bash
argus -t . -k "token" --entropy --deep-scan --flow-scan --request-trace
```

**5. Quiet CI Scan (Noise-Reduced)**

```bash
argus -t . -k "token" --deep-scan --flow-scan --request-trace --quiet --confidence-floor 4
```

---

## Output Modes

argus supports both human-readable terminal output and several machine-readable export modes.

- **Human mode (default)**: prints a styled report to stdout.
- **JSON to stdout**: add `--json`.
- **File outputs**: set `--output <PATH>` and choose `--output-format`:
  - `single` (default): collect all findings and write one JSON file at the end.
  - `ndjson`: stream one JSON object per line while scanning (best for big repos/CI).
  - `per-file`: write one JSON file per scanned source into the output directory.
  - `story`: write a grouped markdown report (Story Mode) to the output path.

---

## Python / PyO3 FFI

argus exposes a PyO3-friendly FFI module behind the `python-ffi` feature.

```bash
PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1 cargo build --release --features python-ffi
```

This produces a Python extension shared library in target/release/ (e.g., libargus.so on Linux). You can rename it to argus_ffi.so for import.

### Maturin (recommended for easy import)

```bash
pip install maturin
maturin develop --release
```

Then:

```python
import argus_ffi
```

### Python tests

```bash
pip install -e ".[test]"
pytest python/tests
```

### Release to PyPI

Push a version tag (e.g., v1.1.0) to trigger the publish workflow:

```bash
git tag v1.1.0
git push origin v1.1.0
```

Example (maturin-style usage):

```python
from argus_ffi import ScanOptions, scan_json

opts = ScanOptions(
    targets=["./src"],
    keywords=["token"],
    entropy=False,
    deep_scan=True,
    flow_scan=True,
    request_trace=False,
    mode="scan",
)

print(scan_json(opts))
```

---

## WASM Support

Build a WASM module with in-memory scanning (no filesystem access) using the `wasm-ffi` feature.

```bash
cargo build --target wasm32-unknown-unknown --release --no-default-features --features wasm-ffi
```

The module exports `scan_bytes_json(bytes, options)` and `scan_bytes_count(bytes, options)`.

---

## Deep Analysis and Security Heuristics

argus moves beyond simple pattern matching by applying a suite of heuristics to every potential match. When using `--deep-scan`, the following specific analysis modules are activated:

### 🔍 Context & Provenance
- **Story Mode**: Generates a natural language explanation for *why* a match is considered risky.
- **Sink Provenance**: Determines where the data flows. Detects if a secret is passed to:
  - **Network Sinks**: `fetch`, `axios`, `send`, `open`
  - **Disk Sinks**: `fs.write`, `File::create`
  - **Log Sinks**: `console.log`, `println!`
- **Leak Velocity**: Estimates how quickly a secret might be exposed based on surrounding code (e.g., hardcoded in a public endpoint handler vs. buried in a config loader).

### 🧬 Structural Heuristics
- **Credential Shadowing**: Detects when a placeholder (e.g., `const KEY = "TODO"`) is "shadowed" or replaced by a real secret nearby, often indicating a committed production key.
- **Lateral Linkage**: Identifies identical high-entropy tokens across valid source files, linking disparate parts of the codebase that share credentials.
- **Secret Lineage**: Traces the "origin" of a repeated secret to its most likely definition point.
- **Surface Tension**: Measures the complexity of the code surrounding a secret. High tension often correlates with critical logic rather than test data.

### 🛡️ Protocol & Auth Logic
- **Protocol Drift**: Flags insecure protocol downgrades near sensitive data (e.g., switching from `https://` to `http://` in the same scope).
- **Auth Drift**: Detects HTTP requests that lack typical authentication headers (e.g., `Authorization`, `X-API-Key`) when surrounding requests use them.
- **API Capability Inference**: Infers the risk level of an endpoint based on the method and context (e.g., `DELETE` or `POST` implies **destructive** or **state-changing** capability).
- **Response Class Analysis**: Guesses the sensitivity of the data returned by an endpoint based on variable naming (e.g., `password`, `token` in response handlers).

### ⚠️ Review Hints
- **Comment Escalation**: Scans nearby comments for risk indicators (e.g., "TEMPORARY", "FIXME", "REMOVE THIS") that suggest technical debt or security shortcuts.
- **Endpoint Morphing**: Detects when a base URL is constructed dynamically in ways that obscure its destination (e.g., template literal injection).

---

## Traffic Analysis & Attack Surface

With `--request-trace`, argus becomes a targeted DAST tool for source code.

- **Request Tracing**: Parses HTTP client calls (`fetch`, `axios`, `requests`, `curl`) to reconstruct URLs and methods.
- **Attack Surface Mapping**: Aggregates found URLs and classifies them:
  - **Public**: Fully qualified domains (`https://api.stripe.com`)
  - **Localhost**: Local development servers (`http://127.0.0.1:8080`)
  - **Internal**: Private network IP ranges.
  - **Relative**: API paths (`/api/v1/user`)
- **Obfuscation Detection**: Flags signatures of minified or packed code (e.g., hex-encoded strings, massive one-liners) often used to hide malicious logic.

---

## Risk Visualization

When running in human-readable mode, argus provides high-level summaries to help prioritization.

### Risk Heatmap
A weighted ranking of the most critical files based on match count, entropy scores, and heuristic signals.

```text
🔥 Risk Heatmap (top files)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. src/config/secrets.ts — score 59.0 | hits 40 (entropy 38, keyword 2)
2. src/api/client.rs — score 44.5 | hits 30
```

### Flow Context Graph
With `--flow-scan`, argus prints a lightweight TUI tree showing the structural context of a finding.

```text
Flow: [scope function:init L40 d12] [ctrl if L41] [assign d2] [chain window.open]
Context:
├─ scope: function init @L40:C15
├─ call: window.open
└─ ctrl: if @L41:C13
```

---

## Smart Suppression

Reduce false positives without cluttering the output.

- **Load Rules**: `--suppress .argusignore`
- **Generate Rules**: `--suppress-out .argusignore` (Appends new suppression candidates from the current scan)
- **Audit Rules**: `--suppression-audit` (Reports stale rules that no longer match anything or are too broad)

**Rule Formats:**
- `id:<variable_name>` — Suppress by identifier (e.g., `id:example_key`).
- `<file>:<line>:<kind>` — Suppress a specific match location.

In Deep Scan mode, argus will suggest **Suppression Hints** for findings that look like test data or examples, complete with a confidence score and a recommended "decay" date.

---

## Advanced Configuration

### Control Flow Analysis (`--flow-scan`)
A lightweight, AST-free control flow analysis that works on most C-like languages. It provides:
- **Scope**: Current function/class/block.
- **Control**: Nearest `if`, `while`, `return`.
- **Distance**: How far the match is from assignments or returns.

> [!NOTE]
> For JavaScript/TypeScript, flow analysis is heuristic by default. Enable the `js-ast` feature for precise AST-based parsing.

### Optional Features
Compile argus with additional features for enhanced capabilities:

- **JavaScript AST**: `cargo build --features js-ast`
  - Enables tree-sitter based parsing for JS/TS files.
- **Syntax Highlighting**: `cargo build --features highlighting`
  - Enables true 24-bit syntax highlighting for code snippets in the terminal.

---

## Options Reference

| Category | Flag | Description |
|----------|------|-------------|
| **Core** | `-t, --target <PATH>` | Target file, directory, or URL (repeatable). |
| | `-k, --keyword <STR>` | Literal keyword to search for. |
| | `--entropy` | Enable Shannon entropy scanning. |
| | `--diff` | Scan only lines added in git diff. |
| **Output** | `--json` | Enable JSON output. |
| | `--output <PATH>` | Output path or directory. |
| | `--output-format` | `single` (default), `ndjson`, `per-file`, or `story`. |
| | `--no-color` | Disable ANSI colors. |
| **Tuning** | `--threshold <FLOAT>` | Entropy threshold (default: 4.5). |
| | `-c, --context <N>` | Context window size in bytes (default: 80). |
| | `-j, --threads <N>` | Scan threads (default: auto). |
| | `--exclude <GLOB>` | Patterns to ignore (e.g. `*.lock`). |
| **Analysis** | `--deep-scan` | Enable all heuristic analysis modules. |
| | `--flow-scan` | Enable control-flow context. |
| | `--request-trace` | Enable HTTP traffic analysis. |
| **Manage** | `--suppress <PATH>` | Load suppression rules. |
| | `--suppress-out` | Write new suppressions to file. |

---

## License

This project is licensed under the AGPL-3.0 License. See `LICENSE` for details.

---

<div align="center">

**Author:** Seuriin ([SSL-ACTX](https://github.com/SSL-ACTX))

*v1.1.0*

</div>