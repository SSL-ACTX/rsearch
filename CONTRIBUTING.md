# Contributing to argus

Thanks for taking the time to contribute.

This project is a Rust CLI that focuses on fast scanning + practical security heuristics. Contributions that improve correctness, reduce false positives, improve performance, or improve the UX/reporting are especially welcome.

## Quick start

### Prerequisites

- Rust toolchain via rustup

### Build

```bash
cargo build
```

### Test

```bash
cargo test
```

### Run locally

```bash
cargo run -- --help
```

## What to contribute

- Bug fixes (crashes, incorrect output, missed matches)
- False positive reductions (ideally with tests demonstrating the improvement)
- Performance improvements (hot paths, allocation reduction, parallelism)
- New heuristics/signals (keep them explainable)
- Documentation (README, examples, flags, suppression rules)

If you’re planning a larger feature, open an issue first to align on the approach.

## Coding standards

- Keep changes focused; avoid drive-by refactors.
- Prefer small, composable functions and minimal allocations in hot paths.
- Keep output deterministic where possible (stable ordering) for CI consumers.
- Preserve existing CLI flags and semantics unless there’s a strong reason.

### Formatting / lint

If you have them installed:

```bash
cargo fmt
cargo clippy --all-targets --all-features
```

Clippy warnings should be addressed for new/changed code.

## Tests (important)

Heuristic changes should come with tests.

- Add or update tests in `src/main.rs` under the `#[cfg(test)]` module.
- When possible, write tests as small, self-contained fixtures using byte strings.
- Prefer tests that show both:
  - a case that should be detected
  - a case that should *not* be detected

## Documentation expectations

If you add a flag, output field, or output format:

- Update README flag tables and examples.
- If applicable, update `src/cli.rs` docstrings.

## Commit messages

Use Conventional Commits:

- `feat(scope): ...`
- `fix(scope): ...`
- `docs: ...`
- `chore: ...`

Examples:

- `fix(scan): skip binary files earlier`
- `feat(output): add story output format`

## Pull request checklist

Before opening a PR:

- `cargo test` passes
- `cargo fmt` applied (if available)
- New behavior is covered by tests
- README/docs updated for user-visible changes
- No secrets/tokens included in examples, fixtures, screenshots, or logs

## Reporting security issues

Please do **not** file public issues for security vulnerabilities. See [SECURITY.md](SECURITY.md) for responsible disclosure.
