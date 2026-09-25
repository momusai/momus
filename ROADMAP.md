# Momus Roadmap

This document is the public build plan for Momus. It is deliberately ambitious. The goal is a multi-year, standard-setting platform for AI security — not a weekend scanner. We ship in phases; each phase must be complete and polished before the next begins.

## Vision

By 2028, Momus should be to AI security what Metasploit was to network security in 2010: the default open framework that every serious researcher, red teamer, defender, and enterprise safety engineer builds on or benchmarks against.

## Guiding principles

1. **Free forever.** The core engine, the CLI, the attack packs, and the guardrail middleware are Apache-2.0 and will never be paywalled.
2. **Red team AND blue team.** Every attack ships with a corresponding defense.
3. **DSL over hardcode.** The Momus Attack Language (MAL) is the moat. If you have to write Go to add an attack, we have failed.
4. **Screenshot-able.** If a feature can't produce a compelling screenshot or GIF, it doesn't ship until it can.
5. **Community first.** Contributors are treated as owners. Governance is transparent from day one.

---

## Phase 0 — Foundation *(months 1–3)*

**Ship v0.1.** A single, credible release that proves the pattern.

- [x] Go monorepo scaffold (module + `internal/` packages)
- [x] Momus Attack Language v1 (MAL) — parser, validator, three-valued evaluator
- [x] Adapters: HTTP JSON + OpenAI-compatible API
- [x] Attack runner + scoring pipeline (regex/contains + Kleene tri-state + `llm_judge`)
- [x] Evidence store on disk (SQLite) — *`scan --store`, plus `momus history` and `momus diff` for regression gating in CI*
- [x] HTML report generator (single file, self-contained, theme-aware)
- [x] JSON output + SARIF 2.1.0 *(uploads to GitHub code scanning)*
- [x] 50 attacks in `packs/core/` across 8 categories — *shipped 200 across 10*
- [x] `momus` CLI binary + `npx momus` wrapper — *(core pack embedded in the binary; npm installer fetches + checksum-verifies the release binary)*
- [x] GitHub Actions dogfooding pipeline
- [x] Documentation site skeleton (Docusaurus) — *9 pages in `website/`, not yet deployed*
- [ ] Launch: HN, r/netsec, r/LocalLLaMA, Twitter/X

**Star target:** 500–1,000.

---

## Phase 1 — Depth *(months 3–6)*

**Prove Momus works against every model that matters.**

- [x] Adapter: Anthropic native (Messages API) *(target-side)*
- [x] Adapter: Google Gemini (generateContent API) *(target-side)*
- [x] Adapter: Azure OpenAI (api-key auth) *(target-side)*
- [x] Adapters: AWS Bedrock, Google Vertex *(target-side; Bedrock via the Converse API)*
- [x] Adapters: Ollama, vLLM, llama.cpp servers *(covered by the OpenAI-compatible adapter)*
- [x] LLM-as-judge scorer using pluggable judge models *(OpenAI/Ollama/Anthropic/Fake; nonce-fenced, evidence-verified)*
- [x] 200 attacks total
- [x] Attack pack versioning + signature verification *(momus pack lock/verify/sign/keygen; SHA-256 + Ed25519)*
- [ ] GitHub Action published to Marketplace
- [ ] First responsible-disclosure blog post against a well-known OSS agent
- [x] `momus init` scaffolding for new users

**Star target:** 2,000–3,000.

---

## Phase 2 — MCP + Agentic *(months 6–9)*

**Own the protocols nobody else is testing.**

- [x] Native MCP adapter (Model Context Protocol servers as first-class targets) — *`momus mcp audit` + `momus mcp scan`, stdio and streamable HTTP*
- [ ] LangChain / LangGraph adapter
- [ ] LlamaIndex adapter
- [ ] CrewAI / AutoGen / Semantic Kernel adapters
- [ ] Multi-turn attack chains in MAL
- [ ] Tool-abuse attack category (50+ attacks)
- [ ] RAG poisoning attack category (50+ attacks)
- [ ] 400 attacks total
- [ ] Second blog post: MCP server disclosure roundup

**Star target:** 4,000–6,000.

---

## Phase 3 — Blue team *(months 9–12)*

**Every attack now has a matching defense.**

- [ ] `@momus/guard-express` — Node/Express middleware
- [ ] `momus-guard-fastapi` — Python/FastAPI middleware (via Py bindings)
- [ ] `@momus/guard-next` — Next.js edge middleware
- [ ] `momus-guard-mcp` — server-side MCP guard
- [ ] Attack ↔ Guard mapping registry
- [ ] `momus guard-verify` command: prove your guard blocks the attacks
- [ ] First "guard-in-production" case study

**Star target:** 7,000–10,000.

---

## Phase 4 — Studio *(months 12–15)*

**The screenshot machine.**

- [ ] Browser-based Studio (WASM-powered, runs offline)
- [ ] Live attack builder with syntax highlighting for MAL
- [ ] Model comparison view (GPT-4 vs Claude vs Llama-3 vs Gemini on the same attack pack)
- [ ] Attack replay + diff viewer
- [ ] Public leaderboard of anonymized results
- [ ] Deep-link sharing of attack sessions

**Star target:** 12,000–18,000.

---

## Phase 5 — Sentinel *(months 15–18)*

**From CI-time scanner to production observability.**

- [ ] Momus Sentinel agent SDK (Node + Python)
- [ ] Collector daemon
- [ ] Real-time attack detection dashboard
- [ ] Integrations: Slack, PagerDuty, OpenTelemetry, Datadog
- [ ] "We caught an attack in prod" case-study series

**Star target:** 18,000–25,000.

---

## Phase 6 — Compliance *(months 18–24)*

**Make Momus indispensable to enterprises.**

- [ ] Evidence pack generator (PDF + machine-readable)
- [ ] Framework mappings: OWASP LLM Top 10, MITRE ATLAS, NIST AI RMF, EU AI Act Art. 15, ISO/IEC 42001
- [ ] Signed, tamper-evident scan artifacts
- [ ] Auditor-friendly export
- [ ] Reference implementations for common enterprise architectures

**Star target:** 25,000–40,000.

---

## Phase 7 — Ecosystem *(years 2–3)*

- [ ] **Forge** — LLM-driven adversarial agent that invents novel attacks
- [ ] **Atlas** — public benchmark & leaderboard of model/agent safety
- [ ] **Threat Feed** — daily feed of new jailbreaks & disclosures
- [ ] **Momus IDE** — VS Code + JetBrains extensions
- [ ] **Momus Fuzz** — coverage-guided prompt mutation
- [ ] Attack pack marketplace (community-authored, signed, distributed)
- [ ] 2,000+ curated attacks

**Star target:** 40,000–70,000.

---

## What we will *not* do

- We will not add a proprietary "enterprise-only" attack pack. All attacks are free.
- We will not add license restrictions that punish forks.
- We will not chase every new AI framework — adapters must earn their place.
- We will not fragment the DSL. MAL evolves via RFCs, never by silent breaking changes.

## How to contribute

See [CONTRIBUTING.md](CONTRIBUTING.md). The single most valuable contribution right now is authoring MAL attacks in [packs/](packs/).
