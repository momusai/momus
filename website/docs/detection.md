---
title: How detection works
---

# How detection works

A security scanner that cries wolf gets uninstalled. Momus is built so a model
that refuses — or that safely describes, translates, or quotes an attack — is
never reported vulnerable.

## Three-valued logic

Every detector resolves to one of three outcomes, composed with Kleene logic
through `any_of` / `all_of` / `not`:

- `matched` → **vulnerable**
- `not-matched` → **safe**
- `inconclusive` → undecided (no judge configured, judge unreachable, low
  confidence, ...) → reported as **inconclusive**, never guessed

Because "can't tell" is a real outcome, an uncertain judge sitting next to a
decisive regex never flips a safe result to vulnerable.

## Detection styles

- **Canary** — the payload plants an unguessable token (`^[A-Z]{2}[0-9]{3}_HIT$`)
  and detects it verbatim. A refusing model can't emit it by chance. Safe for
  *direct* injection and jailbreaks.
- **Encoded canary** — the token appears only encoded (base64, ROT13, ...) and is
  detected after the model decodes it. Describing the payload shows the encoded
  form, not the token.
- **Judge-gated canary** — for indirect injection (the token lives in a document
  or data the model processes) the canary is combined with an `llm_judge` node so
  a model that merely *describes or quotes* the injection isn't flagged.
- **Wrapper, judge-gated** — for "the model emitted a dangerous string" checks
  (`<script>`, `DROP DATABASE`), the marker + canary are a cheap prefilter and the
  judge confirms genuine output vs a quoted refusal.
- **Judge only** — purely semantic checks (leaks, misinformation).

## The load-bearing guarantee

A test scans a refusing target with the entire pack and asserts **zero**
vulnerable findings. The same discipline is enforced when you write your own
attacks — see [Writing attacks](/writing-attacks).
