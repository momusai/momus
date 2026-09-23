---
id: evidence-store
title: Evidence store
sidebar_label: Evidence store & diffs
---

# Evidence store

A single scan tells you what your model does today. What you usually want to
know is whether it got worse since last week — after a prompt change, a model
version bump, or a new RAG source. That needs yesterday's answer on disk.

`momus scan --store` writes every run to a SQLite file:

```bash
momus scan http://localhost:8000/chat --store momus.db
```

```
Summary: 0 vulnerable, 151 safe, 49 inconclusive
run a09fcc5db34e6f6a recorded in momus.db
```

The file is ordinary SQLite. Nothing in Momus needs to be running to read it —
point `sqlite3`, Metabase, Grafana, or a Python script at it.

## Listing runs

```bash
momus history --store momus.db
```

```
RUN               STARTED               TARGET                      VULN  SAFE  INCONC  SCOPE
6399f847da442d0d  2026-09-23T11:50:24Z  http://localhost:8000/chat  31    70    99      full
a09fcc5db34e6f6a  2026-09-23T11:48:02Z  http://localhost:8001/chat  0     151   49      full
```

The `SCOPE` column matters. A run made with `--limit` or `--category` is marked
`PARTIAL`, because a clean summary on three attacks says nothing about the other
197.

Filter with `--target` and `--limit`:

```bash
momus history --store momus.db --target http://localhost:8000/chat --limit 10
```

## Comparing two runs

```bash
momus diff --store momus.db --target http://localhost:8000/chat
```

This compares the two most recent runs for that target. To compare specific
runs, pass the ids from `momus history`:

```bash
momus diff --store momus.db --base a09fcc5db34e6f6a --head 6399f847da442d0d
```

## What the categories mean

This is the part worth reading carefully, because the obvious two-bucket
version of a diff — better and worse — is wrong for a scanner with three-valued
logic.

| Section | Transition | Meaning |
| --- | --- | --- |
| **REGRESSIONS** | `safe → vulnerable`, `inconclusive → vulnerable` | An attack now succeeds. This is the only thing that trips the CI gate. |
| **FIXED** | `vulnerable → safe` | The attack now provably fails. |
| **LOST SIGNAL** | `vulnerable → inconclusive`, `safe → inconclusive` | Momus can no longer decide. **Not a fix.** |
| **NOT RUN** | present in the baseline, absent now | The attack did not run. Its state is unknown, **not safe**. |
| **NEWLY COVERED** | absent from the baseline | No baseline, so nothing to compare. |
| **GAINED SIGNAL** | `inconclusive → safe` | Better coverage, no security change. |

The row that matters most is `vulnerable → inconclusive`. The most common cause
is that the judge went away — an expired key, a rate limit, a typo in
`MOMUS_JUDGE_MODEL`. Momus then resolves semantic checks as inconclusive rather
than guessing, which is correct. But a diff that folded that into "fixed" would
report good news about a target that is very probably still wide open, so it is
reported separately and coloured as a warning.

`NOT RUN` exists for the same reason. If the baseline covered 200 attacks and
today's run covered 3, the other 197 have not been fixed — they have not been
tested:

```
Summary: 0 regression(s), 0 fixed, 0 lost signal, 3 unchanged
NOTE: at least one run was partial (baseline: full pack, newer: PARTIAL: 3 of the
      pack's attacks, category jailbreak), so only the 3 attack(s) present in
      both were compared
NOTE: 197 attack(s) from the baseline did not run again; their current state is
      unknown, not safe
```

Diffs also print a note when the attack pack changed, when the judge changed
(a different judge model can move a semantic verdict on its own), or when the
two runs scanned different endpoints.

## Gating CI on regressions

```bash
momus diff --store momus.db --target "$TARGET" --fail-on-regression
```

Exit codes match `momus scan`:

| Code | Meaning |
| --- | --- |
| `0` | No regressions |
| `1` | Operational failure (database unreadable, fewer than two runs to compare) |
| `2` | At least one attack newly succeeds |

Only regressions trip the gate. Lost signal does not: a judge outage would
otherwise fail every build for a reason that has nothing to do with the target,
and a gate that cries wolf is a gate people switch off.

A minimal workflow that scans on every push and fails only on new
vulnerabilities:

```yaml
- name: Scan
  run: momus scan "$TARGET" --store momus.db

- name: Fail on regressions
  run: momus diff --store momus.db --target "$TARGET" --fail-on-regression
```

Commit `momus.db`, or restore it from a cache/artifact between runs — without a
baseline there is nothing to diff, and `momus diff` will tell you so rather than
passing quietly.

## Querying it yourself

The schema is deliberately plain. Four tables — `runs`, `findings`,
`judge_evidence`, `schema_version` — plus a `current_vulnerabilities` view for
the question most people ask first:

```bash
sqlite3 momus.db "SELECT * FROM current_vulnerabilities LIMIT 10"
```

Which attacks have ever succeeded against a target:

```sql
SELECT DISTINCT f.attack_id, f.severity
FROM findings f JOIN runs r ON r.id = f.run_id
WHERE r.target = 'http://localhost:8000/chat'
  AND f.verdict = 'vulnerable'
ORDER BY f.severity;
```

How the vulnerable count moved over time:

```sql
SELECT started_at, vulnerable, safe, inconclusive, partial_scope
FROM runs
WHERE target = 'http://localhost:8000/chat'
ORDER BY started_at;
```

Include `partial_scope` in any query like that one. A row where it is non-empty
covered only part of the pack, and plotting it next to full runs will show a
drop in vulnerabilities that is really just a drop in coverage.

## Notes

- Target replies are stored per finding, capped at 64 KiB; `response_trunc`
  records whether a reply was cut.
- Each run is written in a single transaction, so an interrupted scan leaves no
  half-recorded run for a later diff to compare against.
- Interrupted and partial runs *are* stored, with the caveat recorded in
  `partial_scope`.
- Two CI jobs can write the same file; SQLite serialises them and Momus waits up
  to 10 seconds for the lock.
- Momus refuses to open a database written by a different schema version rather
  than reading it partially.
