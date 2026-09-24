---
title: CLI reference
---

# CLI reference

```
momus scan <target-url> [flags]
momus validate <pack-dir>
momus init [dir]
momus pack lock|verify|sign|keygen ...
```

## momus scan

| Flag | Default | Description |
|---|---|---|
| `--pack` | `packs/core` | Attack pack directory (falls back to the embedded core pack if absent) |
| `--json` | off | Emit findings as JSON to stdout |
| `--html <path>` | — | Write a self-contained HTML report |
| `--sarif <path>` | — | Write a SARIF 2.1.0 report |
| `--fail-on <sev>` | — | Exit 2 if a vulnerable finding meets this floor: `any\|info\|low\|medium\|high\|critical` |
| `--concurrency <n>` | `8` | Attacks in flight at once |
| `--limit <n>` | `0` (all) | Run at most N attacks — scope a run against a paid endpoint |
| `--category <name>` | all | Only run one category (e.g. `jailbreak`) |
| `--dry-run` | off | Print the planned target/judge call counts without calling anything |
| `--skip-probe` | off | Skip the liveness probe that checks the target behaves like a model |
| `--judge-url` | `$MOMUS_JUDGE_URL` | Judge endpoint (enables `llm_judge`) |
| `--judge-model` | `$MOMUS_JUDGE_MODEL` | Judge model |
| `--judge-provider` | auto | `openai` \| `anthropic` |
| `--judge-threshold` | `0.7` | Minimum judge confidence |
| `--store <path>` | — | Record the run in a SQLite evidence file — see [Evidence store](/evidence-store) |

## Environment variables

| Var | Purpose |
|---|---|
| `MOMUS_MODEL` | Model for OpenAI/Anthropic targets |
| `MOMUS_TARGET_API_KEY` | Explicit key for a non-standard target host |
| `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / `AZURE_OPENAI_API_KEY` (or `AZURE_OPENAI_KEY`) / `GEMINI_API_KEY` (or `GOOGLE_API_KEY`) | Provider keys (sent only to their genuine host) |
| `GOOGLE_ACCESS_TOKEN` (or `VERTEX_ACCESS_TOKEN`) | Vertex AI bearer token — `gcloud auth print-access-token` |
| `AWS_REGION` / `AWS_PROFILE` / `AWS_ACCESS_KEY_ID` / … | AWS Bedrock, via the standard credential chain |
| `MOMUS_JUDGE_URL` / `MOMUS_JUDGE_MODEL` / `MOMUS_JUDGE_API_KEY` / `MOMUS_JUDGE_PROVIDER` | Judge configuration |
| `MOMUS_JUDGE_THRESHOLD` / `MOMUS_JUDGE_TIMEOUT` / `MOMUS_JUDGE_VOTES` | Judge tuning |

## momus validate

Strictly validates every attack in a pack (schema, detect tree, duplicate ids,
regex compilation). Exits non-zero on any problem — use it in CI for custom packs.

## momus init

Scaffolds a starter pack with commented templates you can edit.

## momus pack

Integrity tooling — see [Pack integrity](/pack-integrity). `momus pack verify`
with no argument (or on an installed binary with no `packs/core` on disk)
verifies the core pack **embedded in the binary**.

## momus history

Lists runs recorded by `scan --store`, newest first. Runs that covered only part
of the pack are marked `PARTIAL`.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--store <path>` | `momus.db` | Evidence database to read |
| `--target <url>` | all | Only runs against this target |
| `--limit <n>` | `20` | Show at most N runs (`0` = all) |

## momus diff

Compares two recorded runs and reports what moved. See
[Evidence store](/evidence-store) for what the categories mean — in particular
why `vulnerable → inconclusive` is reported as lost signal rather than as a fix.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--store <path>` | `momus.db` | Evidence database to read |
| `--target <url>` | — | Compare the two most recent runs for this target |
| `--base <id>` | — | Baseline run id (from `momus history`) |
| `--head <id>` | — | Newer run id; must be given with `--base` |
| `--fail-on-regression` | off | Exit 2 if any attack newly succeeds |
