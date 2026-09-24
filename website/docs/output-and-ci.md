---
title: Output & CI
---

# Output formats & CI

## Formats

```bash
momus scan <url>                       # colorized terminal summary
momus scan <url> --json > out.json     # machine-readable findings
momus scan <url> --html report.html    # self-contained, theme-aware HTML report
momus scan <url> --sarif momus.sarif   # SARIF 2.1.0 for GitHub code scanning
```

You can request several at once. Findings are emitted before report files are
written, so a report-write failure never discards results.

## Gating the build

```bash
momus scan <url> --fail-on high        # any|low|medium|high|critical
```

Exit codes let CI tell outcomes apart:

- `0` — the scan completed and the gate was not tripped
- `1` — operational failure: a bad flag, an unwritable report path, an
  **interrupted** scan, or a scan where **every attack was inconclusive**
  (a wrong model, expired key, or sustained throttling). An aborted or
  untested run never passes the gate open.
- `2` — the scan completed, but the `--fail-on` gate tripped on findings

Tune throughput with `--concurrency` (default 8 attacks in flight).

## Controlling cost

A full pack is 200 target calls plus up to ~147 judge calls. Against a paid
endpoint, preview and scope the run first:

```bash
momus scan <url> --dry-run                    # print call counts, send nothing
momus scan <url> --category prompt-injection  # one category only
momus scan <url> --limit 20                   # first 20 attacks
```

## GitHub Action

```yaml
- name: Momus AI security scan
  uses: momusai/momus@v0
  with:
    target: https://your-agent.example/chat
    sarif: momus.sarif
    fail-on: high
- uses: github/codeql-action/upload-sarif@v3
  if: always() # still upload when --fail-on trips the build
  with:
    sarif_file: momus.sarif
```

A complete workflow is in `.github/workflows/momus-scan.yml` in the repo.
