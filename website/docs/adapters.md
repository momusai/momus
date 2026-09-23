---
title: Target adapters
---

# Target adapters

Momus picks an adapter from the target URL:

| Adapter | Matches | Auth |
|---|---|---|
| OpenAI-compatible | URL path contains `/chat/completions` | `OPENAI_API_KEY` (Bearer), for `api.openai.com` only |
| Azure OpenAI | host `*.openai.azure.com` | `AZURE_OPENAI_API_KEY` (`api-key` header) |
| Anthropic | path `/v1/messages` or host `api.anthropic.com` | `ANTHROPIC_API_KEY` (`x-api-key`) |
| Google Gemini | path `:generateContent` or the Gemini host | `GEMINI_API_KEY` / `GOOGLE_API_KEY` |
| Generic HTTP | anything else | `MOMUS_TARGET_API_KEY` (Bearer), if set |

The OpenAI-compatible adapter also covers Ollama, vLLM, and Groq.

## Key isolation

A provider's API key is only ever sent to that provider's genuine host — so
scanning an arbitrary URL can't leak your `OPENAI_API_KEY` to it. To send a key
to any other host (a proxy, a self-hosted gateway), set it explicitly:

```bash
export MOMUS_TARGET_API_KEY=...
momus scan https://my-gateway.internal/v1/chat/completions
```

## Robustness

Every adapter treats a non-2xx status, a streaming/SSE body, or a missing reply
field as an **error** (reported `inconclusive`) rather than scoring it as a
model reply — so a misconfigured endpoint can never come back "0 vulnerabilities".
Response bodies are size-capped and redirects on a POST are refused.

### Rate limits and transient failures

Real endpoints throttle. Momus retries transient failures automatically —
HTTP **408, 429, 500, 502, 503, 504 and 529** (Anthropic "overloaded") plus
network errors — up to 4 attempts with jittered exponential backoff.

Two deliberate limits:

- **A total retry budget of 20s per request.** Providers often answer 429 with
  `Retry-After: 60`; honouring that for every attack would stall a scan for
  close to an hour with no output. If the server asks for longer than the
  budget, Momus stops and reports the throttling instead of sleeping.
- **Client-side timeouts are not retried.** The provider has already generated
  (and billed) that completion, so re-sending would multiply cost without
  improving the result. Dial and DNS timeouts *are* retried — nothing was
  generated there.

Client errors (400, 401, 403, …) are never retried: they are real answers.

If throttling persists, the attack is reported `inconclusive` with the provider's
own message in the reason — never as "safe". Lower `--concurrency` (default 8) if
you are hitting limits on a small quota.
