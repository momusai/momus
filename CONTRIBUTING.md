# Contributing

Thanks for taking a look. The most useful thing you can contribute right now is
new attacks — and that doesn't require writing any Go.

## Adding an attack (no code)

Attacks are YAML files under `packs/core/<category>/`. Copy an existing one that
resembles what you want and edit it. The format is documented in
[ARCHITECTURE.md](ARCHITECTURE.md); a minimal one looks like:

```yaml
mal_version: "1"
id: pi-020-your-attack
name: Short human name
category: prompt-injection
severity: medium
owasp_llm: LLM01
references:
  - https://owasp.org/www-project-top-10-for-large-language-model-applications/
description: |
  What the attack does. End with a note on why it won't false-positive.
payload: |
  The text sent to the target.
detect:
  contains: "AB123_HIT"
```

Two rules that matter:

1. **No false positives.** A model that refuses must never be flagged
   vulnerable. Prove compliance with an unguessable canary (matching
   `^[A-Z]{2}[0-9]{3}_HIT$`), or use `llm_judge` for semantic checks. Never write
   a `contains`/`regex` that could match a polite refusal.
2. **Unique id and canary.** Don't reuse an id or a canary that already exists.

Before opening a PR:

```bash
go run ./cmd/momus validate packs/core   # must pass
go run ./cmd/momus pack lock packs/core --name momus-core --pack-version 0.1.0   # re-lock after editing attacks
go test ./...                            # must pass — the pack + its lock are covered by tests
```

If you add, edit, or remove an attack, regenerate the integrity lock with the
`pack lock` command above — a test verifies `packs/core` matches its lock.

The test suite scans a refusing target with the whole pack and fails if anything
comes back "vulnerable", so a false-positive-prone attack will be caught.

## Code changes

```bash
go build ./...
go test -race ./...
gofmt -w .
golangci-lint run ./...   # if you have it installed
```

Keep changes focused. If you're adding a target adapter or an output format,
there's a test for the existing ones — follow the same shape. New behavior needs
a test.

## PRs

Small, self-contained PRs get reviewed faster. Explain what and why in the
description. If it's a big change, open an issue first so we can talk about it
before you sink time into it.
