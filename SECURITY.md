# Security Policy

argus is a security tool, and we take security reports seriously. Thanks for helping keep the project and its users safe.

## Supported versions

We provide security fixes for:

- The latest `main` branch
- The most recent tagged release

If you’re using an older release, please upgrade and re-test before reporting.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for a vulnerability.

### Preferred: GitHub Security Advisories

If this repository has Security Advisories enabled:

- Go to the repository’s **Security** tab
- Click **Report a vulnerability**

This keeps the discussion private while we triage and coordinate a fix.

### Alternative: Private contact

If Security Advisories are not available, open a draft PR with a minimal reproduction (redacted), or contact the maintainer via a private channel listed on the project profile.

> [!IMPORTANT]
> Do not include real secrets, API keys, tokens, credentials, or private customer data in any report.

## What to include

A good report includes:

- A clear description of the issue and expected impact
- Steps to reproduce (preferably with a minimal sample)
- Affected versions / commit hash
- Environment details (OS, Rust version, invocation)
- Any suggested fix or mitigation (if you have one)

If the issue relates to false positives/false negatives rather than a vulnerability, please file a normal issue instead.

## Triage and response targets

Best-effort targets (not guarantees):

- Acknowledgement within **72 hours**
- Initial triage within **7 days**
- Fix or mitigation plan within **30 days** (severity dependent)

## Coordinated disclosure

We prefer coordinated disclosure:

- Please allow time for a fix before public disclosure.
- We will credit reporters in release notes unless you request anonymity.

## Scope

In scope:

- Memory safety issues, panics/DoS from untrusted input, path traversal, unsafe temp file handling
- Output injection issues that could mislead CI users
- Dependency supply-chain risks that meaningfully affect argus behavior

Out of scope:

- Issues requiring physical access
- Social engineering
- Vulnerabilities in unrelated third-party services

## Hard rules for reports

> [!WARNING]
> Never paste production secrets into issues, advisories, logs, or screenshots. Use synthetic test strings.
