package judge

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/momus-ai/momus/internal/httpx"
)

// AnthropicJudge speaks the Anthropic Messages API. Anthropic has no
// response_format, so structured output is forced via a single tool
// (record_judgment) with tool_choice. A missing tool_use block degrades to
// Inconclusive.
type AnthropicJudge struct {
	URL       string
	Model     string
	APIKey    string
	Client    *http.Client
	Timeout   time.Duration
	Threshold float64
}

// Name identifies this judge.
func (j *AnthropicJudge) Name() string { return "anthropic-judge" }

// Judge forces a structured tool call, reconstructs the JSON verdict from the
// tool input, and interprets it. Never returns a Go error.
func (j *AnthropicJudge) Judge(ctx context.Context, req Request) (*Result, error) {
	to := j.Timeout
	if to <= 0 {
		to = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()

	nonce, err := newNonce()
	if err != nil {
		return inconclusive("nonce: " + err.Error()), nil
	}
	model := resolveModel(req.Model, j.Model)
	system, user := buildMessages(req.Prompt, req.Response, nonce)

	tool := map[string]any{
		"name":        "record_judgment",
		"description": "Record the yes/no security judgment.",
		"input_schema": map[string]any{
			"type":     "object",
			"required": []string{"nonce", "compliant", "confidence", "evidence"},
			"properties": map[string]any{
				"nonce":      map[string]any{"type": "string"},
				"compliant":  map[string]any{"type": "boolean"},
				"confidence": map[string]any{"type": "number"},
				"evidence":   map[string]any{"type": "string"},
				"rationale":  map[string]any{"type": "string"},
			},
		},
	}
	body, _ := json.Marshal(map[string]any{
		"model":       model,
		"max_tokens":  512,
		"temperature": 0,
		"top_p":       0,
		"system":      system,
		"tools":       []any{tool},
		"tool_choice": map[string]any{"type": "tool", "name": "record_judgment"},
		"messages":    []map[string]string{{"role": "user", "content": user}},
	})

	// Retry throttling/transient failures (see openai.go).
	resp, err := httpx.Do(ctx, j.Client, func() (*http.Request, error) {
		r, err := http.NewRequestWithContext(ctx, http.MethodPost, j.URL, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		r.Header.Set("content-type", "application/json")
		r.Header.Set("user-agent", "momus-judge/0.0.1")
		r.Header.Set("x-api-key", j.APIKey)
		r.Header.Set("anthropic-version", "2023-06-01")
		return r, nil
	})
	if err != nil {
		return inconclusive("transport: " + err.Error()), nil
	}
	defer resp.Body.Close()
	data, _ := httpx.ReadCapped(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return inconclusive("status " + resp.Status), nil
	}

	var env struct {
		Content []struct {
			Type  string          `json:"type"`
			Name  string          `json:"name"`
			Input json.RawMessage `json:"input"`
		} `json:"content"`
	}
	if err := json.Unmarshal(data, &env); err != nil {
		return inconclusive("unparseable messages response"), nil
	}
	var toolInput string
	for _, c := range env.Content {
		if c.Type == "tool_use" && c.Name == "record_judgment" {
			toolInput = string(c.Input)
			break
		}
	}
	if toolInput == "" {
		return inconclusive("no tool_use block in reply"), nil
	}

	res := interpret(toolInput, nonce, req.Response, defaultThreshold(j.Threshold))
	res.Model = req.Model
	res.ResolvedModel = model
	return res, nil
}
