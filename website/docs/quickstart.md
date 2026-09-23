---
title: Quickstart
---

# Quickstart

## Try it against the example targets

Momus ships two demo targets — a deliberately vulnerable one and a well-behaved
one — so you can see it work with zero setup.

```bash
# Terminal 1: start the vulnerable example (listens on :8000)
go run ./examples/vulnerable-echo

# Terminal 2: scan it
momus scan http://localhost:8000
```

## Scan a real provider

The adapter is picked from the URL path/host:

```bash
export OPENAI_API_KEY=sk-...
momus scan https://api.openai.com/v1/chat/completions

export ANTHROPIC_API_KEY=sk-ant-...
momus scan https://api.anthropic.com/v1/messages
```

Set `MOMUS_MODEL` to choose the model. For a non-standard host, provide the key
explicitly with `MOMUS_TARGET_API_KEY` (the provider env keys are only sent to
their real host).

### Windows

Releases include Windows binaries, and `npx momus` works the same. Use your
shell's syntax for environment variables — in PowerShell:

```powershell
$env:OPENAI_API_KEY = "sk-..."
momus scan https://api.openai.com/v1/chat/completions
```

## Liveness probe

Before running the pack, Momus sends two benign prompts to confirm the endpoint
actually behaves like a model. If it returns the same reply to both (a health
check, a static page, a gateway that swallows the body), the scan aborts rather
than reporting a meaningless "everything safe". Override with `--skip-probe`.

## Reports and CI

```bash
momus scan http://localhost:8000 \
  --html report.html \
  --sarif momus.sarif \
  --json > findings.json

# fail the build on a high-severity vulnerability
momus scan https://your-agent.example/chat --fail-on high
```

## Enable the judge (optional)

Some checks are semantic. Point Momus at a judge — a *different* endpoint than
the target:

```bash
export MOMUS_JUDGE_URL=http://localhost:11434/v1/chat/completions   # local Ollama
export MOMUS_JUDGE_MODEL=llama3.1
momus scan http://localhost:8000
```

Without a judge, semantic attacks report `inconclusive` and a refusing model is
never marked vulnerable. See [The judge](/the-judge).
