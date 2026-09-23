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
)

// AzureOpenAITarget speaks the Azure OpenAI chat-completions API. It shares the
// OpenAI request/response shape but authenticates with the "api-key" header (not
// Authorization: Bearer), and the deployment is encoded in the URL, so no model
// field is sent in the body.
type AzureOpenAITarget struct {
	URL    string
	APIKey string
	Client *http.Client
}

// NewAzureOpenAI constructs an AzureOpenAITarget. Auth is resolved by
// azureAPIKey, which never sends the key to a non-Azure host.
func NewAzureOpenAI(url string) *AzureOpenAITarget {
	return &AzureOpenAITarget{
		URL:    url,
		APIKey: azureAPIKey(url),
		Client: newHTTPClient(),
	}
}

// Name identifies this adapter.
func (t *AzureOpenAITarget) Name() string { return "azure-openai" }

// Send posts a single user turn and extracts the assistant reply.
func (t *AzureOpenAITarget) Send(ctx context.Context, req Request) (*Response, error) {
	start := time.Now()
	body, _ := json.Marshal(map[string]any{
		"stream": false, // we don't parse SSE
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
		r.Header.Set("user-agent", "momus/0.0.1")
		if t.APIKey != "" {
			r.Header.Set("api-key", t.APIKey) // Azure uses api-key, not Bearer
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
	if err := requireOK(resp, "azure openai", data); err != nil {
		return nil, err
	}
	if err := requireNotStream(resp, "azure openai", data); err != nil {
		return nil, err
	}

	text, raw, err := parseChatCompletionText(data, "azure openai")
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

// azureAPIKey returns the auth key for an Azure OpenAI target, only for a
// genuine Azure host. Any other host requires explicit MOMUS_TARGET_API_KEY.
func azureAPIKey(rawURL string) string {
	if k := os.Getenv("MOMUS_TARGET_API_KEY"); k != "" {
		return k
	}
	if isAzureOpenAIHost(rawURL) {
		return firstNonEmptyEnv("AZURE_OPENAI_API_KEY", "AZURE_OPENAI_KEY")
	}
	return ""
}

// isAzureOpenAIHost reports whether the URL's host is an Azure OpenAI endpoint.
func isAzureOpenAIHost(rawURL string) bool {
	u, err := neturl.Parse(rawURL)
	if err != nil {
		return false
	}
	return strings.HasSuffix(strings.ToLower(u.Hostname()), ".openai.azure.com")
}
