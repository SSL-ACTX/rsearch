# argus Signature Features Plan

Status legend: done | in-progress | planned

## ✅ Completed (Done)
- Adaptive Confidence Engine: per-finding confidence score with explainable signals and tunable risk profiles. **Status:** done
- Context Graph: lightweight flow graph around findings (call-chain + ownership + data-path hints) rendered as a compact TUI tree. **Status:** done
- Secret Lineage: track repeated tokens across files and show “origin → propagation” chains. **Status:** done
- Smart Suppression: auto-generated suppression rules with “why” and confidence-based decay. **Status:** done
  - Done: multi-signal suppression hints (rule + reasons + confidence) with decay window.
  - Done: load suppression rules (`--suppress`) and export hints (`--suppress-out`).
- Inverse Suppression Audit: detect stale or overbroad suppression rules. **Status:** done
- Intent-Consistency Scoring: flag requests whose method/body conflict with nearby semantic intent. **Status:** done
- Token-Sink Provenance: trace secret-like values to their first sink (network, disk, logs). **Status:** done
- Ambient Credential Shadowing: detect when placeholder values are later replaced by real secrets. **Status:** done
- Protocol Drift Map: detect HTTP requests that silently migrate between protocols/classes. **Status:** done
- Entropy “Surface Tension”: detect layered obfuscation by entropy gradients. **Status:** done
- Lateral Linkage Graph: connect findings across files by shared fingerprints. **Status:** done
- Risk Heatmap: file-level heat scores, top hotspots, and “top 10 risky files” summary. **Status:** done
- Token Typing: classify likely token types (JWT, AWS key, GitHub PAT, Stripe, etc.) with non-regex heuristics. **Status:** done
- Secure Diff Mode: scan only newly added lines in git diffs with a high-signal summary. **Status:** done
- Entropy Clustering: group nearby high-entropy blocks into one finding with surrounding metadata. **Status:** done
- Attack Surface Hints: detect public endpoints + secrets in the same file and link them. **Status:** done
  - Done: endpoint classification (public/localhost/internal/relative) with base URL constant extraction.
  - Done: de-dup endpoints per file and attach endpoint list to attack surface records.
  - Done: link request-trace calls to nearby endpoint hints (context match + line proximity).

## 🧪 New Concepts (Planned, Unique)
- **API Capability Inference:** infer capability level by combining endpoints + verbs + auth context (read-only, destructive, privileged). **Status:** planned
- **Secrets-in-Comments Escalation:** treat secrets embedded in commented code as higher risk when adjacent to live endpoints. **Status:** planned
- **Obfuscation Signature Index:** fingerprint minifiers/packers and adjust request-trace extraction strategy per signature. **Status:** planned
- **Response Class Guessing:** infer expected response sensitivity based on request parameters (e.g., `token`, `password`, `refresh`). **Status:** planned
- **Path-Depth Shock:** elevate risk when a secret appears close to deployment paths (e.g., `infra/`, `k8s/`, `terraform/`). **Status:** planned
- **Contextual Auth Drift:** detect when a request loses auth headers within a call chain compared to nearby calls. **Status:** planned
- **Endpoint Shape Morphing:** detect templated endpoints that resolve to public domains at runtime through base URL overrides. **Status:** planned
- **Leak Velocity Score:** estimate how quickly a secret could leak based on proximity to logging, telemetry, or error paths. **Status:** planned
- **Story Mode Export:** a narrative report that explains why each finding matters. **Status:** planned
