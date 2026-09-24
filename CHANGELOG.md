# Changelog

Notable changes to Momus. Format loosely follows [Keep a Changelog](https://keepachangelog.com/);
versions follow [semantic versioning](https://semver.org/).

Until 1.0, the MAL attack format may gain fields but will not silently change
the meaning of existing ones. A change that would alter what an existing
detector matches goes through an RFC, never a point release.

## [Unreleased]

## [0.1.0] — 2026-09-24

First public release.

### Scanning

- `momus scan <url>` runs an attack pack against a target and reports, per
  attack, `vulnerable` / `safe` / `inconclusive`.
- **200 attacks** across 10 categories — prompt injection, jailbreak, data
  exfiltration, encoding/obfuscation, excessive agency, insecure output
  handling, sensitive-info disclosure, RAG injection, misinformation, and
  package hallucination. Mapped to OWASP LLM Top 10 and MITRE ATLAS.
- **MAL v1**, the attack language: attacks are YAML, so adding one needs no Go.
  Parser, strict validator, and a three-valued (Kleene) detector engine with
  `any_of` / `all_of` / `not`.
- **7 target adapters** — OpenAI-compatible (also Ollama, vLLM, Groq), Azure
  OpenAI, Anthropic Messages, Google Gemini, Google Vertex AI, AWS Bedrock
  (Converse API), and generic HTTP/JSON. The adapter is chosen from the URL.
- **`llm_judge` scorer** for semantic checks: nonce-fenced against injection
  from the text it grades, required to quote verifiable evidence, confidence
  thresholded, cached, with optional voting. Works with OpenAI-compatible,
  Anthropic, or local judges. Refuses to let a model grade its own answers.
- Cost controls for paid endpoints: `--dry-run`, `--category`, `--limit`.

### Output and CI

- Four formats: colourised terminal, JSON, a self-contained HTML report, and
  SARIF 2.1.0 for GitHub code scanning.
- `--fail-on <severity>` gates a build. Exit codes distinguish outcomes: `0`
  completed and passed, `1` operational failure, `2` gate tripped.
- **SQLite evidence store** (`--store`) with `momus history` and `momus diff`,
  plus `--fail-on-regression` to fail a build when an attack that used to be
  blocked starts succeeding.
- A **GitHub Action**, with `store` and `fail-on-regression` inputs.

### Integrity and distribution

- Single static binary, no cgo, for Linux, macOS and Windows on amd64/arm64.
- The core attack pack is **embedded in the binary**, so `go install` and
  `npx momus` work with nothing to download separately.
- `momus pack lock|verify|sign|keygen` — SHA-256 per-file hashes and Ed25519
  signing. Release checksums additionally carry a keyless cosign signature.
- `npx momus`, which fetches the release binary and verifies its SHA-256.

### The two contracts

These are the point of the project, so they are listed as features rather than
buried in the design docs:

- **No false positives.** A model that refuses is never reported vulnerable.
  Compliance is proven with unguessable canary tokens anchored to the whole
  reply, or confirmed by the judge. `momus validate` rejects detector shapes
  that can cry wolf — including an `any_of` that lets a loose pattern outvote
  the judge.
- **No false "safe".** A target that was not genuinely tested never comes back
  clean. `inconclusive` is the zero value, so anything unexpected lands there:
  non-2xx and non-3xx responses, redirects without a `Location`, SSE bodies,
  blank replies, unrecognised JSON shapes, HTML pages, binary or compressed
  bodies, sustained throttling. A liveness probe aborts a scan whose target
  answers two different benign prompts identically. A run where every attack
  was inconclusive exits non-zero, and an interrupted run says so on the face
  of its own HTML and SARIF reports.

### Known limitations

- Without a judge configured, roughly 170 of the 200 attacks resolve
  `inconclusive` rather than giving a verdict. That is the honest answer, not a
  pass — but it does mean a judge is worth configuring, and a local one is free.
- No MCP adapter yet, and no multi-turn attack chains. Both are Phase 2.
- Vertex AI takes an explicit `GOOGLE_ACCESS_TOKEN`; Application Default
  Credentials are not implemented.
- Momus tests behaviour over HTTP. It does not audit your agent's tool
  permissions or read your source.

[Unreleased]: https://github.com/momus-ai/momus/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/momus-ai/momus/releases/tag/v0.1.0
