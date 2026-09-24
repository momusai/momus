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
| Google Vertex AI | host `*-aiplatform.googleapis.com` | `GOOGLE_ACCESS_TOKEN` (Bearer) |
| AWS Bedrock | host `bedrock-runtime.*` | the standard AWS credential chain (SigV4) |
| Generic HTTP | anything else | `MOMUS_TARGET_API_KEY` (Bearer), if set |

The OpenAI-compatible adapter also covers Ollama, vLLM, and Groq.

Vertex is matched **before** Gemini: the two serve the same `generateContent`
API and differ only in auth, so a Vertex URL routed to the Gemini adapter would
send an API-key header and get a 401 on every attack.

## AWS Bedrock

The model and region come from the URL, so there is nothing else to configure:

```bash
momus scan https://bedrock-runtime.us-east-1.amazonaws.com/model/anthropic.claude-3-5-sonnet-20240620-v1:0/converse
```

Momus uses Bedrock's **Converse** API rather than `InvokeModel`. `InvokeModel`
has a different request and response shape for every model family (Anthropic,
Titan, Llama, Mistral, Cohere), so an adapter built on it has to guess at the
reply format for any family it does not recognise — and guessing is how a
scanner ends up scoring a non-reply as "safe". Converse normalises all of them.

Credentials come from the standard AWS chain: environment variables, a shared
profile (`AWS_PROFILE`), SSO, EC2/ECS instance roles, or EKS IRSA. Production
Bedrock is usually reached with an IAM role rather than a static key pair, which
is why the official SDK is used here instead of a hand-rolled signature.

The role needs `bedrock:InvokeModel` on the model, and **model access must be
enabled** for that model in that region — an access-denied error names both
possibilities rather than leaving you to guess.

## Google Vertex AI

```bash
export GOOGLE_ACCESS_TOKEN=$(gcloud auth print-access-token)
momus scan "https://us-central1-aiplatform.googleapis.com/v1/projects/PROJECT/locations/us-central1/publishers/google/models/gemini-1.5-pro:generateContent"
```

Momus does not implement Application Default Credentials — the token is supplied
explicitly, as above. These tokens last about an hour, which is comfortably
longer than a scan; if one does expire mid-run the remaining attacks report
`inconclusive` (HTTP 401), never "safe".

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
