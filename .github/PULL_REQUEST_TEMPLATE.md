## What this changes

<!-- One or two sentences. If it fixes an issue, link it. -->

## Checks

- [ ] `go test ./...` passes
- [ ] `go vet ./...` and `gofmt -l .` are clean

**If you touched `packs/core/`:**

- [ ] `momus validate packs/core` passes
- [ ] `momus pack lock packs/core` re-run, and the updated lock is committed
- [ ] The attack's `description` explains how it avoids false-positives

**If you added or changed a detector**, the important one:

- [ ] A refusing model cannot satisfy it. Specifically: a refusal that *quotes*
      the payload, or that safely decodes an obfuscated payload and then warns
      about it, must not match.
- [ ] It is anchored (`^...$`) or judge-gated rather than a bare `contains`
      a polite refusal could satisfy.

**If you touched `internal/target/` or the scan pipeline:**

- [ ] Anything that is not a genuine model reply still errors rather than being
      scored — non-2xx *and* non-3xx, streaming bodies, blank replies,
      unrecognised JSON shapes, HTML.
- [ ] A credential is still only ever sent to its own provider's real host.

## Notes for the reviewer

<!-- Anything you are unsure about, or deliberately did not do. -->
