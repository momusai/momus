---
title: Pack integrity
---

# Pack integrity: lock & sign

Attack packs can be locked and signed so consumers can verify they haven't been
tampered with. The tooling uses only the Go standard library (SHA-256 + Ed25519).

```bash
momus pack lock packs/core                 # write per-file hashes + a digest
momus pack verify packs/core               # fail if any attack changed/added/removed
```

The lock lives at `<pack>/momus-pack.lock.json` and is ignored by the scanner and
validator. If you edit attacks, re-run `momus pack lock`.

Installed from npm or `go install`? There is no `packs/core` on disk — run
`momus pack verify` with no argument and it checks the pack **embedded in the
binary** against the lock embedded alongside it:

```bash
momus pack verify          # verifies the built-in core pack
```

Release artifacts also publish a keyless **cosign** signature over
`checksums.txt` (`checksums.txt.sig` + `.pem`). The npm installer verifies the
SHA-256 hashes but does **not** check that signature — cosign isn't available
during a postinstall. Verify it yourself for a supply-chain guarantee:

```bash
cosign verify-blob checksums.txt \
  --signature checksums.txt.sig --certificate checksums.txt.pem \
  --certificate-identity-regexp 'https://github.com/momus-ai/momus/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Signing

```bash
momus pack keygen --out mykey                       # Ed25519 keypair
momus pack sign packs/core --key mykey.key          # sign the pack digest
momus pack verify packs/core --pubkey @mykey.pub    # authenticate against a pinned key
```

`verify` always checks file integrity. When you pin a public key with
`--pubkey`, it additionally requires the signature to verify under **that** key —
so an attacker can't just re-sign a modified pack with their own key.
