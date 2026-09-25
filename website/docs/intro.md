---
slug: /
title: Introduction
sidebar_position: 1
---

# Momus

**The harshest critic your AI will ever face.**

Momus is an open framework for testing the security of AI models, agents, and
MCP servers. It sends a library of adversarial prompts at an endpoint and
scores the responses — with a false-positive discipline baked into the core, so
you can run it in CI without it flagging every well-behaved refusal.

:::tip Start here
**[The Verdict Machine](pathname:///how-it-works.html)** is an interactive walkthrough of
the part that actually matters: given what a model sent back, how Momus decides
whether it gave in — and why a refusal that quotes the canary is still *safe*.
:::

## What works today

- Scan **HTTP/JSON, OpenAI-compatible, Azure OpenAI, Anthropic, or Google Gemini**
  endpoints. The adapter is chosen from the URL; API keys are only ever sent to
  their genuine host.
- **200 attacks across 10 categories** mapped to the OWASP LLM Top 10.
- A **three-valued detection engine** (`matched` / `not-matched` / `inconclusive`)
  so "I can't tell" is a first-class result, never a guess.
- An optional, prompt-injection-resistant **`llm_judge`** scorer.
- Four outputs: terminal, JSON, self-contained **HTML report**, and **SARIF 2.1.0**
  for GitHub code scanning.
- **CI gating** (`--fail-on`), a **GitHub Action**, and **pack signing** for supply-chain integrity.

## Install

No Go required:

```bash
npx momus scan https://your-agent.example/chat
```

Or with Go 1.25+:

```bash
go install github.com/momusai/momus/cmd/momus@latest
```

The core attack pack is embedded in the binary, so a scan works out of the box.

Next: the [Quickstart](/quickstart).
