package target

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	neturl "net/url"
	"os"
	"strings"
	"time"

	"github.com/momus-ai/momus/internal/buildinfo"
)

// OpenAITarget speaks the OpenAI /v1/chat/completions API. It also works with
// any provider that mimics that surface (Groq, Together, Ollama, vLLM, ...).
type OpenAITarget struct {
	URL    string
	Model  string
	APIKey string
	Client *http.Client
}

// NewOpenAI constructs an OpenAITarget. Model is read from MOMUS_MODEL
// (default: gpt-4o-mini). Auth is resolved by targetAPIKey, which never sends
// OPENAI_API_KEY to an arbitrary host.
func NewOpenAI(url string) *OpenAITarget {
	model := os.Getenv("MOMUS_MODEL")
	if model == "" {
		model = "gpt-4o-mini"
	}
	return &OpenAITarget{
		URL:    url,
		Model:  model,
		APIKey: targetAPIKey(url),
		// Must be newHTTPClient(): it refuses redirects. A 3xx from a gateway or
		// load balancer would turn our POST into a GET, drop the attack payload,
		// and let the gateway's banner be scored as the model's reply — i.e. a
		// whole scan reporting "safe" against a target that was never tested.
		Client: newHTTPClient(),
	}
}

// targetAPIKey returns an auth token to send to the TARGET, but only when it is
// safe to do so. OPENAI_API_KEY is attached solely for genuine OpenAI hosts —
// otherwise scanning an arbitrary URL that merely looks OpenAI-compatible would
// leak the key to that host. For any other endpoint the user must opt in
// explicitly via MOMUS_TARGET_API_KEY.
func targetAPIKey(rawURL string) string {
	if k := os.Getenv("MOMUS_TARGET_API_KEY"); k != "" {
		return k // explicit opt-in for this specific target
	}
	u, err := neturl.Parse(rawURL)
	if err != nil {
		return ""
	}
	// Azure OpenAI hosts route to their own adapter (api-key header), so only a
	// genuine OpenAI host gets OPENAI_API_KEY here.
	if strings.ToLower(u.Hostname()) == "api.openai.com" {
		return os.Getenv("OPENAI_API_KEY")
	}
	return ""
}

// Name identifies this adapter.
func (t *OpenAITarget) Name() string { return "openai" }

// Send calls the chat completions API and pulls the assistant reply.
func (t *OpenAITarget) Send(ctx context.Context, req Request) (*Response, error) {
	start := time.Now()
	body, _ := json.Marshal(map[string]any{
		"model":  t.Model,
		"stream": false, // we don't parse SSE; force a single JSON response
		"messages": []map[string]string{
			{"role": "user", "content": req.Payload},
		},
	})
	resp, err := sendWithRetry(ctx, t.Client, func() (*http.Request, error) {
		r, err := http.NewRequestWithContext(ctx, http.MethodPost, t.URL, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		r.Header.Set("content-type", "application/json")
		r.Header.Set("user-agent", buildinfo.UserAgent("momus"))
		if t.APIKey != "" {
			r.Header.Set("authorization", "Bearer "+t.APIKey)
		}
		return r, nil
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := readCappedBody(resp.Body)
	if err != nil {
		return nil, err
	}
	// A non-2xx status (auth failure, rate limit, server error) must NOT be
	// scored as a model reply — otherwise a misconfigured endpoint reports every
	// attack as "safe". Surface it as an error so the scanner marks it
	// inconclusive.
	if err := requireOK(resp, "openai", data); err != nil {
		return nil, err
	}
	if err := requireNotStream(resp, "openai", data); err != nil {
		return nil, err
	}
	// An unparseable body (e.g. an SSE stream) or a response with no "choices"
	// is surfaced as an error (-> inconclusive) rather than a false "safe".
	text, raw, err := parseChatCompletionText(data, "openai")
	if err != nil {
		return nil, err
	}
	return &Response{
		Text:      text,
		Raw:       raw,
		LatencyMs: time.Since(start).Milliseconds(),
		Status:    resp.StatusCode,
	}, nil
}
