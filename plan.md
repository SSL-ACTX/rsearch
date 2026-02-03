# argus Signature Features Plan

Status legend: done | in-progress | planned

- Adaptive Confidence Engine: per-finding confidence score with explainable signals and tunable risk profiles. **Status:** done
- Context Graph: lightweight flow graph around findings (call-chain + ownership + data-path hints) rendered as a compact TUI tree. **Status:** done
- Secret Lineage: track repeated tokens across files and show “origin → propagation” chains. **Status:** done
 -- stucked- Smart Suppression: auto-generated suppression rules with “why” and confidence-based decay. **Status:** done
	- Done: multi-signal suppression hints (rule + reasons + confidence) with decay window.
	- Done: load suppression rules (`--suppress`) and export hints (`--suppress-out`).
- Risk Heatmap: file-level heat scores, top hotspots, and “top 10 risky files” summary. **Status:** done
- Token Typing: classify likely token types (JWT, AWS key, GitHub PAT, Stripe, etc.) with non-regex heuristics. **Status:** done
- Secure Diff Mode: scan only newly added lines in git diffs with a high-signal summary. **Status:** done
- Entropy Clustering: group nearby high-entropy blocks into one finding with surrounding metadata. **Status:** done
- Attack Surface Hints: detect public endpoints + secrets in the same file and link them. **Status:** done
	- Done: endpoint classification (public/localhost/internal/relative) with base URL constant extraction.
	- Done: de-dup endpoints per file and attach endpoint list to attack surface records.
	- Done: link request-trace calls to nearby endpoint hints (context match + line proximity).
- “Story Mode” Export: a narrative report that explains why each finding matters. **Status:** planned
