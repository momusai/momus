# momus (npm)

Run [Momus](https://github.com/momusai/momus), the open AI/LLM security scanner,
without installing Go:

```bash
npx momus scan https://your-agent.example/chat --fail-on high
```

On install this package downloads the prebuilt `momus` binary for your platform
from the matching GitHub release and verifies its SHA-256. The core attack pack
(200 attacks across the OWASP LLM Top 10) is embedded in the binary, so a scan
works out of the box — no extra files to fetch.

## Common commands

```bash
npx momus scan <url>                 # scan an endpoint with the embedded core pack
npx momus scan <url> --sarif s.sarif # SARIF for GitHub code scanning
npx momus init my-pack               # scaffold your own attack pack
npx momus validate my-pack           # validate a pack
```

## Notes

- Supported platforms: linux, macOS, Windows on amd64 / arm64.
- **Install scripts disabled?** (`--ignore-scripts`, pnpm 10's default, Yarn
  Berry) — the binary is fetched on first run instead, so `npx momus` still
  works. To fetch it eagerly, run `npm rebuild momus`.
- Set `MOMUS_BINARY=/path/to/momus` before install to use a local binary instead
  of downloading.
- Prefer Go? `go install github.com/momusai/momus/cmd/momus@latest`.

License: Apache-2.0.
