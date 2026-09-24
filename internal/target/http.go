package target

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/momus-ai/momus/internal/buildinfo"
)

// HTTPTarget dispatches an attack payload to a generic JSON HTTP endpoint.
// The request body includes the payload under several common key names so a
// wide range of naïve chat endpoints work without config.
type HTTPTarget struct {
	URL    string
	APIKey string // optional, from MOMUS_TARGET_API_KEY
	Client *http.Client
}

// NewHTTP constructs an HTTPTarget with a sensible timeout. A self-hosted or
// proxied endpoint often needs auth, supplied explicitly via MOMUS_TARGET_API_KEY
// (provider keys are never sent to an arbitrary host).
func NewHTTP(url string) *HTTPTarget {
	return &HTTPTarget{
		URL:    url,
		APIKey: os.Getenv("MOMUS_TARGET_API_KEY"),
		Client: newHTTPClient(),
	}
}

// Name identifies this adapter.
func (t *HTTPTarget) Name() string { return "http" }

// Send POSTs the payload as JSON and normalizes the response.
func (t *HTTPTarget) Send(ctx context.Context, req Request) (*Response, error) {
	start := time.Now()
	// Send the payload under several common key names so a wide range of naïve
	// endpoints receive it without configuration.
	body, _ := json.Marshal(map[string]any{
		"input":   req.Payload,
		"inputs":  req.Payload,
		"prompt":  req.Payload,
		"message": req.Payload,
		"text":    req.Payload,
		"query":   req.Payload,
		"stream":  false, // we don't parse SSE; say so, as the provider adapters do
	})
	resp, err := sendWithRetry(ctx, t.Client, func() (*http.Request, error) {
		r, err := http.NewRequestWithContext(ctx, http.MethodPost, t.URL, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		r.Header.Set("content-type", "application/json")
		r.Header.Set("accept", "application/json, text/plain")
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
	// A non-2xx status must not be scored as a model reply (see openai.go).
	if err := requireOK(resp, "http", data); err != nil {
		return nil, err
	}
	if err := requireNotStream(resp, "http", data); err != nil {
		return nil, err
	}
	// Identify the model's reply, or refuse to score. Guessing here is how a
	// scanner ends up reporting "safe" for a target it never actually tested.
	var raw any
	jsonErr := json.Unmarshal(data, &raw)
	text := extractText(raw)
	if text == "" {
		_, isObj := raw.(map[string]any)
		switch {
		case jsonErr == nil && isObj:
			// A JSON envelope we don't understand. Scoring the whole body would
			// also risk false-matching our own echoed payload.
			return nil, fmt.Errorf("http target: could not find the reply text in the JSON response "+
				"(looked for %s); body: %s", strings.Join(replyKeys, ", "), snippet(data))
		case jsonErr == nil:
			// Valid JSON that is not an object we understand (an array, a bare
			// string, a number). Scoring the raw body could match a canary the
			// endpoint echoed back from our own request.
			return nil, fmt.Errorf("http target: could not find the reply text in the JSON response "+
				"(looked for %s); body: %s", strings.Join(replyKeys, ", "), snippet(data))
		case looksLikeHTML(data):
			// A web page (site root or UI) rather than an API endpoint.
			return nil, fmt.Errorf("http target: response looks like an HTML page, not an API reply — "+
				"check the URL; body: %s", snippet(data))
		case len(bytes.TrimSpace(data)) == 0:
			return nil, fmt.Errorf("http target: empty response body")
		default:
			// The raw-body fallback exists for a genuine text/plain reply. It
			// used to accept ANY non-JSON body, so a PDF, a compressed blob, an
			// XML fault envelope or an HTML fragment became the "reply" — and
			// since no canary appears in such bytes, every attack came back
			// "safe" for a target that was never tested.
			if err := requirePlainText(resp, data); err != nil {
				return nil, err
			}
			text = string(data)
		}
	}
	// Same guard the provider adapters use: never score a blank reply as "safe".
	if err := requireReply(text, "http", data); err != nil {
		return nil, err
	}
	return &Response{
		Text:      text,
		Raw:       raw,
		LatencyMs: time.Since(start).Milliseconds(),
		Status:    resp.StatusCode,
	}, nil
}

// replyKeys are the top-level JSON fields we accept as the model's reply.
var replyKeys = []string{"output", "response", "text", "message", "content", "answer", "reply", "generated_text"}

// extractText pulls a reply string out of common JSON shapes.
func extractText(v any) string {
	m, ok := v.(map[string]any)
	if !ok {
		return ""
	}
	for _, key := range replyKeys {
		if s, ok := m[key].(string); ok && strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

// looksLikeHTML reports whether a body is markup (a web page, an XML fault
// envelope, an error fragment) rather than an API reply. Prefix matching alone
// was evadable: a UTF-8 BOM is not Unicode whitespace so TrimSpace left it in
// place, a build-tool comment before the doctype shifted the prefix, and a bare
// "<div class=\"error\">Service unavailable</div>" matched nothing at all.
func looksLikeHTML(b []byte) bool {
	s := bytes.TrimSpace(bytes.TrimPrefix(bytes.TrimSpace(b), []byte("\ufeff")))
	// Skip any leading comments or processing instructions.
	for {
		switch {
		case bytes.HasPrefix(s, []byte("<!--")):
			end := bytes.Index(s, []byte("-->"))
			if end < 0 {
				return true // an unterminated comment is certainly not a reply
			}
			s = bytes.TrimSpace(s[end+3:])
		case bytes.HasPrefix(s, []byte("<?")):
			end := bytes.Index(s, []byte("?>"))
			if end < 0 {
				return true
			}
			s = bytes.TrimSpace(s[end+2:])
		default:
			// A reply that opens with a tag is markup, not prose.
			return len(s) > 1 && s[0] == '<' && (isTagStart(s[1]) || s[1] == '!' || s[1] == '/')
		}
	}
}

func isTagStart(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// requirePlainText gates the raw-body fallback: only a body that is actually
// plain text may be scored as the model's reply.
func requirePlainText(resp *http.Response, body []byte) error {
	reject := func(why string) error {
		return fmt.Errorf("http target: %s, so it cannot be scored as a model reply — "+
			"check the URL; body: %s", why, snippet(body))
	}
	// Go transparently decompresses only the gzip it solicited itself. A server
	// that answers with br/deflate/zstd anyway hands us the compressed bytes.
	if enc := strings.ToLower(strings.TrimSpace(resp.Header.Get("content-encoding"))); enc != "" && enc != "identity" {
		return reject(fmt.Sprintf("the response is %s-encoded and could not be decoded", enc))
	}
	mt, _, _ := mime.ParseMediaType(resp.Header.Get("content-type"))
	switch mt = strings.ToLower(strings.TrimSpace(mt)); {
	case mt == "", mt == "text/plain", mt == "text/markdown":
		// Plausible for a plain-text reply; the content checks below still apply.
	case strings.HasPrefix(mt, "text/"):
		return reject(fmt.Sprintf("the response is %s, a document rather than an API reply", mt))
	default:
		return reject(fmt.Sprintf("the response content type is %s, not text or JSON", mt))
	}
	if !utf8.Valid(body) {
		return reject("the response is not valid UTF-8 (binary or compressed data)")
	}
	if bytes.IndexByte(body, 0) >= 0 {
		return reject("the response contains NUL bytes (binary data)")
	}
	if looksLikeHTML(body) {
		return reject("the response is markup, not an API reply")
	}
	return nil
}
