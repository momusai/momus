---
title: The judge
---

# The llm_judge scorer

Some vulnerabilities can't be decided by a string match — "did the model leak its
system prompt?" is a judgment call. Momus can route those to a second model, the
judge. It's optional: with no judge configured, semantic checks resolve
`inconclusive`, never a false positive.

## Enabling it

The judge must be a **different endpoint than the target under test**:

```bash
export MOMUS_JUDGE_URL=https://api.openai.com/v1/chat/completions
export MOMUS_JUDGE_API_KEY=sk-...
export MOMUS_JUDGE_MODEL=gpt-4o-mini          # optional
```

Local and free works too (Ollama, vLLM):

```bash
export MOMUS_JUDGE_URL=http://localhost:11434/v1/chat/completions
export MOMUS_JUDGE_MODEL=llama3.1
```

Providers: OpenAI-compatible and Anthropic.

**Auto-selection:** if you don't set `MOMUS_JUDGE_URL` but `OPENAI_API_KEY` or
`ANTHROPIC_API_KEY` is present, Momus enables that provider's judge
automatically.

A model must never grade its own answers, so Momus checks whether the judge
resolves to the same endpoint as the target. What happens next depends on who
chose that judge:

- **Auto-selected** (e.g. scanning `api.openai.com` with `OPENAI_API_KEY` set):
  Momus warns and scans **without a judge**. Semantic checks come back
  `inconclusive` rather than failing the run — scanning OpenAI with an OpenAI key
  is a normal thing to do, and it should not be a hard error.
- **Explicitly configured** (`MOMUS_JUDGE_URL` or `--judge-provider` pointing at
  the target): that's a misconfiguration, and Momus exits with an error.

To get semantic checks in the first case, point `MOMUS_JUDGE_URL` at a different
endpoint — a local Ollama works.

## Why it doesn't produce false positives

The judge grades attacker-influenced text, so it's hardened:

- **Nonce fencing** — the untrusted response is wrapped in per-call random
  markers and the judge must echo the nonce, so response text that injects a
  fake verdict is rejected.
- **Evidence verification** — a "compliant" verdict must quote a verbatim span of
  the response; Momus checks that quote is really there. Hallucinated verdicts are
  downgraded to `inconclusive`.
- **Confidence threshold** (default `0.7`) — below it, `inconclusive`.
- **Determinism** — temperature 0, results cached per (attack, response, model).

Tuning: `MOMUS_JUDGE_THRESHOLD` (0..1), `MOMUS_JUDGE_TIMEOUT` (a Go duration such
as `30s` or `2m`), `MOMUS_JUDGE_VOTES` (an odd integer). A malformed value falls
back to the default rather than failing the scan.
