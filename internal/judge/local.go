package judge

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Without a judge, 170 of the core pack's 200 attacks resolve inconclusive:
// they need something to read a reply and say whether the model complied or
// refused. That is the honest answer, but it is a poor first run — a newcomer
// scans an endpoint, sees a wall of "???", and concludes the tool does not
// work.
//
// A local model solves it completely and costs nothing, and a great many
// developers already have one running. So rather than telling people to
// configure it, Momus looks.
//
// Deliberate limits: only loopback addresses are probed, so this can never
// reach out to the network or hand a reply to a third party; the probe is
// bounded to well under a second so a missing server costs nothing; and it is
// announced loudly when used, because "which model graded my scan" must never
// be a surprise.

// localEndpoints are the addresses local inference servers conventionally use.
// Loopback only — discovery must never leave the machine.
var localEndpoints = []struct {
	name    string
	tags    string // model-listing endpoint
	chat    string // OpenAI-compatible chat endpoint
	extract func([]byte) []candidate
}{
	{
		name: "Ollama",
		tags: "http://127.0.0.1:11434/api/tags",
		chat: "http://127.0.0.1:11434/v1/chat/completions",
		extract: func(b []byte) []candidate {
			var r struct {
				Models []struct {
					Name string `json:"name"`
					Size int64  `json:"size"`
				} `json:"models"`
			}
			if json.Unmarshal(b, &r) != nil {
				return nil
			}
			out := make([]candidate, 0, len(r.Models))
			for _, m := range r.Models {
				out = append(out, candidate{name: m.Name, size: m.Size})
			}
			return out
		},
	},
	{
		name:    "a local OpenAI-compatible server",
		tags:    "http://127.0.0.1:8000/v1/models", // vLLM, llama.cpp, LM Studio
		chat:    "http://127.0.0.1:8000/v1/chat/completions",
		extract: openAIModelList,
	},
	{
		name:    "LM Studio",
		tags:    "http://127.0.0.1:1234/v1/models",
		chat:    "http://127.0.0.1:1234/v1/chat/completions",
		extract: openAIModelList,
	},
}

// openAIModelList reads the OpenAI /v1/models shape, which carries no size.
// Those candidates keep size 0 and so stay in the server's own order.
func openAIModelList(b []byte) []candidate {
	var r struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if json.Unmarshal(b, &r) != nil {
		return nil
	}
	out := make([]candidate, 0, len(r.Data))
	for _, m := range r.Data {
		out = append(out, candidate{name: m.ID})
	}
	return out
}

// candidate is a model that could act as judge. size is bytes on disk, 0 when
// the server does not report it.
type candidate struct {
	name string
	size int64
}

// LocalJudge describes a discovered local inference server.
type LocalJudge struct {
	Server string // human name, for the message
	URL    string // chat endpoint
	Model  string
}

// DiscoverLocal looks for a local model that can act as judge, avoiding the
// model under test so the judge is never grading its own answers.
//
// It returns nil when nothing is found, which is not an error: no judge is a
// supported mode, it just means semantic checks stay inconclusive.
func DiscoverLocal(ctx context.Context, avoidModel string) *LocalJudge {
	if os.Getenv("MOMUS_NO_AUTO_JUDGE") != "" {
		return nil
	}
	client := &http.Client{Timeout: 700 * time.Millisecond}

	for _, ep := range localEndpoints {
		models := probe(ctx, client, ep.tags, ep.extract)
		if len(models) == 0 {
			continue
		}
		pick := pickJudge(models, avoidModel)
		if pick == "" {
			continue
		}
		return &LocalJudge{Server: ep.name, URL: ep.chat, Model: pick}
	}
	return nil
}

func probe(ctx context.Context, c *http.Client, url string, extract func([]byte) []candidate) []candidate {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	// Read it all (bounded): a single Read can return a partial body, and a
	// truncated JSON document parses as "no models" — which would silently
	// disable the judge on a server that is working fine.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil
	}
	return extract(body)
}

// Describe is the line shown when an auto-detected judge is used. Who graded a
// scan is never allowed to be a surprise.
func (l *LocalJudge) Describe() string {
	return fmt.Sprintf("auto-detected %s (%s) — local, nothing leaves this machine",
		l.Server, l.Model)
}

// pickJudge chooses which discovered model should grade the scan, or "" when
// none can.
//
// The model under test is always skipped: grading its own answers is
// self-grading, which New() refuses outright.
//
// Among the rest it takes the LARGEST. Judging is harder than answering — the
// judge reads an adversarial reply, rules compliance vs refusal, and has to
// quote evidence for the call — and taking whatever the server listed first can
// hand that job to a 0.5B model while a 7B sits right beside it. Size on disk
// is a crude proxy for capability, but it is the only signal the listing
// carries and it beats list order. Servers that report no size (the OpenAI
// /v1/models shape) leave every candidate at 0, so they keep their own order.
func pickJudge(models []candidate, avoidModel string) string {
	best := candidate{}
	for _, m := range models {
		if m.name == "" || strings.EqualFold(m.name, avoidModel) {
			continue
		}
		if best.name == "" || m.size > best.size {
			best = m
		}
	}
	return best.name
}
