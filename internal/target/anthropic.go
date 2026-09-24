package target

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	neturl "net/url"
	"os"
	"strings"
	"time"

	"github.com/momus-ai/momus/internal/buildinfo"
)

// AnthropicTarget speaks the Anthropic Messages API (/v1/messages). It is the
// native adapter for scanning Claude-backed endpoints, whose request/response
// shape differs from the OpenAI chat-completions API.
type AnthropicTarget struct {
	URL    string
	Model  string
	APIKey string
	Client *http.Client
}

// NewAnthropic constructs an AnthropicTarget. Model comes from MOMUS_MODEL
// (default: claude-3-5-haiku-latest). Auth is resolved by anthropicAPIKey, which
// never sends ANTHROPIC_API_KEY to a non-Anthropic host.
func NewAnthropic(url string) *AnthropicTarget {
	model := os.Getenv("MOMUS_MODEL")
	if model == "" {
		model = "claude-3-5-haiku-latest"
	}
	return &AnthropicTarget{
		URL:    url,
		Model:  model,
		APIKey: anthropicAPIKey(url),
		Client: newHTTPClient(),
	}
}

// Name identifies this adapter.
func (t *AnthropicTarget) Name() string { return "anthropic" }

// Send posts a single user message and concatenates the text content blocks.
func (t *AnthropicTarget) Send(ctx context.Context, req Request) (*Response, error) {
	start := time.Now()
	body, _ := json.Marshal(map[string]any{
		"model":      t.Model,
		"max_tokens": 1024,
		"stream":     false,
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
		r.Header.Set("anthropic-version", "2023-06-01")
		if t.APIKey != "" {
			r.Header.Set("x-api-key", t.APIKey)
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
	// Non-2xx (auth/rate-limit/server error) must not be scored as a reply.
	if err := requireOK(resp, "anthropic", data); err != nil {
		return nil, err
	}
	if err := requireNotStream(resp, "anthropic", data); err != nil {
		return nil, err
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("anthropic target: unparseable response (streaming not supported?): %s", snippet(data))
	}
	content, ok := raw["content"].([]any)
	if !ok {
		return nil, fmt.Errorf("anthropic target: response has no 'content' field: %s", snippet(data))
	}
	var text strings.Builder
	for _, b := range content {
		m, ok := b.(map[string]any)
		if !ok {
			continue
		}
		if m["type"] == "text" {
			if s, ok := m["text"].(string); ok {
				text.WriteString(s)
			}
		}
	}
	if err := requireReply(text.String(), "anthropic", data); err != nil {
		return nil, err
	}
	return &Response{
		Text:      text.String(),
		Raw:       raw,
		LatencyMs: time.Since(start).Milliseconds(),
		Status:    resp.StatusCode,
	}, nil
}

// anthropicAPIKey returns the auth key to send to an Anthropic target, but only
// for a genuine Anthropic host — otherwise scanning an arbitrary URL would leak
// ANTHROPIC_API_KEY. Any other host requires explicit MOMUS_TARGET_API_KEY.
func anthropicAPIKey(rawURL string) string {
	if k := os.Getenv("MOMUS_TARGET_API_KEY"); k != "" {
		return k
	}
	u, err := neturl.Parse(rawURL)
	if err != nil {
		return ""
	}
	if strings.ToLower(u.Hostname()) == "api.anthropic.com" {
		return os.Getenv("ANTHROPIC_API_KEY")
	}
	return ""
}
