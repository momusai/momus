// Package target defines the Target abstraction: anything a Momus attack can
// be sent to. Concrete adapters (HTTP, OpenAI, Anthropic, MCP, …) live in
// sibling files in this package.
package target

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"strings"
	"time"

	"github.com/momus-ai/momus/internal/httpx"
)

// parseChatCompletionText extracts choices[0].message.content from an
// OpenAI-style chat-completion response body. Shared by the OpenAI and Azure
// OpenAI adapters. A non-JSON body (e.g. SSE) or a body with no "choices" is an
// error (-> the scanner marks it inconclusive, never a false "safe").
func parseChatCompletionText(data []byte, provider string) (string, map[string]any, error) {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return "", nil, fmt.Errorf("%s target: unparseable response (streaming not supported?): %s", provider, snippet(data))
	}
	choices, ok := raw["choices"].([]any)
	if !ok {
		return "", nil, fmt.Errorf("%s target: response has no 'choices' field: %s", provider, snippet(data))
	}
	text := ""
	if len(choices) > 0 {
		if choice, ok := choices[0].(map[string]any); ok {
			if msg, ok := choice["message"].(map[string]any); ok {
				if c, ok := msg["content"].(string); ok {
					text = c
				}
			}
		}
	}
	if err := requireReply(text, provider, data); err != nil {
		return "", nil, err
	}
	return text, raw, nil
}

// requireNotStream rejects a Server-Sent Events body. The adapters all send
// "stream": false, but a gateway or a self-hosted server can ignore it and
// stream anyway. The generic HTTP adapter's last resort is to score the body as
// plain text, so an SSE response used to be scored as the reply — raw "data: {…}"
// frames, in which no canary ever appears, giving a full pack of "safe" verdicts
// and exit 0 for a target whose actual answer was never assembled.
func requireNotStream(resp *http.Response, provider string, body []byte) error {
	streaming := strings.Contains(strings.ToLower(resp.Header.Get("content-type")), "text/event-stream")
	if !streaming {
		// Some servers stream while labelling the body text/plain or JSON, so
		// fall back to the wire format: repeated "data:" frames, optionally
		// terminated by the [DONE] sentinel.
		frames := 0
		for _, line := range strings.Split(string(body), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "data:") {
				frames++
			}
		}
		streaming = frames >= 2
	}
	if streaming {
		return fmt.Errorf("%s target: the response is a Server-Sent Events stream, which Momus "+
			"cannot score (it needs the assembled reply). Momus sends \"stream\": false; configure "+
			"the endpoint to honour it, or put a non-streaming route in front of it. body: %s",
			provider, snippet(body))
	}
	return nil
}

// requireOK rejects any status outside 2xx. Checking only >= 400 left the 3xx
// range scored as a model reply: Go's redirect refusal in newHTTPClient only
// fires when there is a parseable Location header, so a gateway answering
// "302 Found — sign in at the portal" with no Location reached the detectors as
// if the model had said it. Every attack then misses and the target is reported
// SAFE, which is the false-clean-bill-of-health this package exists to prevent.
func requireOK(resp *http.Response, provider string, body []byte) error {
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s target returned HTTP %d: %s", provider, resp.StatusCode, snippet(body))
	}
	return nil
}

// requireReply rejects an empty/blank model reply. Scoring "" would make every
// detector miss and report the target SAFE — so a content-filtered, truncated, or
// malformed response would look like a clean bill of health. An unscoreable reply
// must be an error (-> inconclusive) instead.
func requireReply(text, provider string, body []byte) error {
	if strings.TrimSpace(text) == "" {
		return fmt.Errorf("%s target: the response contained no reply text to score "+
			"(content filtered, truncated, or an unexpected shape); body: %s", provider, snippet(body))
	}
	return nil
}

// The adapters share their HTTP behaviour (redirect refusal, capped reads, and
// retries for throttling/transient failures) with the judge providers via
// internal/httpx, so the two can't drift apart.

func newHTTPClient() *http.Client { return httpx.NewClient(60 * time.Second) }

func readCappedBody(r io.Reader) ([]byte, error) { return httpx.ReadCapped(r) }

// sendWithRetry issues the request built by newReq, retrying transient transport
// errors and retryable statuses with backoff. newReq must build a FRESH request
// each call (an attempt consumes the body).
func sendWithRetry(ctx context.Context, client *http.Client, newReq func() (*http.Request, error)) (*http.Response, error) {
	return httpx.Do(ctx, client, newReq)
}

// Request is a normalized attack payload dispatched to a Target.
type Request struct {
	Payload string `json:"payload"`
}

// Response is a Target's normalized reply.
type Response struct {
	Text      string `json:"text"`
	Raw       any    `json:"raw,omitempty"`
	LatencyMs int64  `json:"latency_ms"`
	Status    int    `json:"status,omitempty"`
}

// Target is any endpoint Momus can attack.
type Target interface {
	Name() string
	Send(ctx context.Context, req Request) (*Response, error)
}

// snippet returns a short single-line preview of a response body for use in
// error messages (never the full body, which could be large or noisy).
func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}

// Build picks the right adapter for a target URL. The heuristic is deliberate:
// an actual chat-completions PATH gets the OpenAI adapter; everything else falls
// back to the generic HTTP adapter. We match on the path (not a bare "openai"
// substring anywhere in the URL) so a proxy named "openai-gateway" isn't sent
// the wrong request shape — and, critically, isn't handed the OpenAI API key.
func Build(url string) (Target, error) {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return nil, fmt.Errorf("unsupported target url: %q (want http:// or https://)", url)
	}
	switch {
	// Azure OpenAI URLs also contain "/chat/completions", so match the Azure host
	// FIRST — it needs a different auth header (api-key) and key than OpenAI.
	case isAzureOpenAIHost(url):
		return NewAzureOpenAI(url), nil
	case strings.Contains(url, "/chat/completions"):
		return NewOpenAI(url), nil
	case strings.Contains(url, "/v1/messages") || isAnthropicHost(url):
		return NewAnthropic(url), nil
	// Vertex serves the same generateContent API as public Gemini but
	// authenticates with a bearer token, so it must be matched FIRST — the
	// shared ":generateContent" marker would otherwise send it down the
	// API-key path and every request would come back 401.
	case isVertexHost(url):
		return NewVertex(url), nil
	case strings.Contains(url, ":generateContent") || isGeminiHost(url):
		return NewGemini(url), nil
	case isBedrockHost(url):
		return NewBedrock(url), nil
	default:
		return NewHTTP(url), nil
	}
}

// isGeminiHost reports whether the URL's host is Google's generative-language API.
func isGeminiHost(rawURL string) bool {
	u, err := neturl.Parse(rawURL)
	if err != nil {
		return false
	}
	return strings.ToLower(u.Hostname()) == "generativelanguage.googleapis.com"
}

// isAnthropicHost reports whether the URL's host is api.anthropic.com.
func isAnthropicHost(rawURL string) bool {
	u, err := neturl.Parse(rawURL)
	if err != nil {
		return false
	}
	return strings.ToLower(u.Hostname()) == "api.anthropic.com"
}
