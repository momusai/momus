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
)

// GeminiTarget speaks the Google Gemini generateContent API. The model is part
// of the URL (…/models/<model>:generateContent), so the user supplies the full
// endpoint and no model env is needed.
type GeminiTarget struct {
	URL    string
	APIKey string
	Client *http.Client
}

// NewGemini constructs a GeminiTarget. Auth is resolved by geminiAPIKey, which
// never sends the key to a non-Google host.
func NewGemini(url string) *GeminiTarget {
	return &GeminiTarget{
		URL:    url,
		APIKey: geminiAPIKey(url),
		Client: newHTTPClient(),
	}
}

// Name identifies this adapter.
func (t *GeminiTarget) Name() string { return "gemini" }

// Send posts a single user turn and concatenates the candidate's text parts.
func (t *GeminiTarget) Send(ctx context.Context, req Request) (*Response, error) {
	start := time.Now()
	body, _ := json.Marshal(map[string]any{
		"contents": []map[string]any{
			{"parts": []map[string]string{{"text": req.Payload}}},
		},
	})
	resp, err := sendWithRetry(ctx, t.Client, func() (*http.Request, error) {
		r, err := http.NewRequestWithContext(ctx, http.MethodPost, t.URL, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		r.Header.Set("content-type", "application/json")
		r.Header.Set("user-agent", "momus/0.0.1")
		if t.APIKey != "" {
			// Header auth keeps the key out of the URL / logs.
			r.Header.Set("x-goog-api-key", t.APIKey)
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
	if err := requireOK(resp, "gemini", data); err != nil {
		return nil, err
	}
	if err := requireNotStream(resp, "gemini", data); err != nil {
		return nil, err
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("gemini target: unparseable response (streaming not supported?): %s", snippet(data))
	}
	candidates, ok := raw["candidates"].([]any)
	if !ok {
		return nil, fmt.Errorf("gemini target: response has no 'candidates' field: %s", snippet(data))
	}
	var text strings.Builder
	for _, c := range candidates {
		cm, ok := c.(map[string]any)
		if !ok {
			continue
		}
		content, ok := cm["content"].(map[string]any)
		if !ok {
			continue
		}
		parts, ok := content["parts"].([]any)
		if !ok {
			continue
		}
		for _, p := range parts {
			if pm, ok := p.(map[string]any); ok {
				if s, ok := pm["text"].(string); ok {
					text.WriteString(s)
				}
			}
		}
	}
	if err := requireReply(text.String(), "gemini", data); err != nil {
		return nil, err
	}
	return &Response{
		Text:      text.String(),
		Raw:       raw,
		LatencyMs: time.Since(start).Milliseconds(),
		Status:    resp.StatusCode,
	}, nil
}

// geminiAPIKey returns the auth key for a Gemini target, only for a genuine
// Google host. Any other host requires explicit MOMUS_TARGET_API_KEY.
func geminiAPIKey(rawURL string) string {
	if k := os.Getenv("MOMUS_TARGET_API_KEY"); k != "" {
		return k
	}
	u, err := neturl.Parse(rawURL)
	if err != nil {
		return ""
	}
	// Exact host only — matches the router's isGeminiHost so the key-isolation
	// and routing checks cannot drift. A broader ".googleapis.com" suffix would
	// send the generative key to unrelated Google services (e.g. storage).
	if strings.ToLower(u.Hostname()) == "generativelanguage.googleapis.com" {
		return firstNonEmptyEnv("GEMINI_API_KEY", "GOOGLE_API_KEY")
	}
	return ""
}

func firstNonEmptyEnv(names ...string) string {
	for _, n := range names {
		if v := os.Getenv(n); v != "" {
			return v
		}
	}
	return ""
}
