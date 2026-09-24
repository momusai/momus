package judge

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/momusai/momus/internal/buildinfo"
	"github.com/momusai/momus/internal/httpx"
)

// OpenAIJudge speaks the OpenAI /v1/chat/completions API and any provider that
// mimics it (Ollama, vLLM, Groq). It sends temperature 0 and top_p 0 for
// determinism, requests a JSON object, and degrades every transport/HTTP/parse
// failure to Inconclusive.
type OpenAIJudge struct {
	URL       string
	Model     string // concrete default model resolving "judge/default"
	APIKey    string
	Client    *http.Client
	Timeout   time.Duration
	Threshold float64
}

// Name identifies this judge.
func (j *OpenAIJudge) Name() string { return "openai-judge" }

// Judge builds a nonce-fenced prompt, calls the provider, and interprets the
// reply. It never returns a Go error: failures become Inconclusive results.
func (j *OpenAIJudge) Judge(ctx context.Context, req Request) (*Result, error) {
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

	body, _ := json.Marshal(map[string]any{
		"model":       model,
		"temperature": 0,
		"top_p":       0,
		// json_object is the widely-supported floor (OpenAI, Groq, vLLM, recent
		// Ollama). We deliberately do not require json_schema so local providers
		// keep working; a provider that ignores this still yields parseable text.
		"response_format": map[string]string{"type": "json_object"},
		"messages": []map[string]string{
			{"role": "system", "content": system},
			{"role": "user", "content": user},
		},
	})

	// Retry throttling/transient failures: a rate-limited judge would otherwise
	// turn every semantic check into "inconclusive".
	resp, err := httpx.Do(ctx, j.Client, func() (*http.Request, error) {
		r, err := http.NewRequestWithContext(ctx, http.MethodPost, j.URL, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		r.Header.Set("content-type", "application/json")
		r.Header.Set("user-agent", buildinfo.UserAgent("momus-judge"))
		if j.APIKey != "" {
			r.Header.Set("authorization", "Bearer "+j.APIKey)
		}
		return r, nil
	})
	if err != nil { // connection refused, timeout, DNS, persistent 429 -> degrade
		return inconclusive("transport: " + err.Error()), nil
	}
	defer resp.Body.Close()
	data, _ := httpx.ReadCapped(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return inconclusive("status " + resp.Status), nil
	}

	var env struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(data, &env); err != nil || len(env.Choices) == 0 {
		return inconclusive("unparseable completion"), nil
	}

	res := interpret(env.Choices[0].Message.Content, nonce, req.Response, defaultThreshold(j.Threshold))
	res.Model = req.Model
	res.ResolvedModel = model
	return res, nil
}
