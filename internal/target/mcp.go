package target

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/momusai/momus/internal/mcp"
)

// MCPTarget drives one tool on a Model Context Protocol server, so the whole
// attack pack can be fired at it exactly as at a chat endpoint.
//
// The interesting property of an MCP tool as a target is that its output is fed
// straight back into a host model's context. A tool that will echo attacker text
// verbatim is therefore an injection vector into whatever assistant is wired to
// it, which is why the normal canary detectors are meaningful here.
type MCPTarget struct {
	Client *mcp.Client
	Tool   string

	// Arg is the tool argument the payload is placed in. Empty means infer it
	// from the tool's input schema.
	Arg string

	// Extra are additional arguments sent with every call, for tools that
	// require more than one parameter.
	Extra map[string]any
}

// NewMCPTarget builds a target for a named tool. The client must already be
// initialized.
func NewMCPTarget(c *mcp.Client, tool, arg string) *MCPTarget {
	return &MCPTarget{Client: c, Tool: tool, Arg: arg}
}

// Name identifies this adapter.
func (t *MCPTarget) Name() string { return "mcp" }

// Send calls the tool with the payload and returns its text output.
func (t *MCPTarget) Send(ctx context.Context, req Request) (*Response, error) {
	start := time.Now()
	if t.Tool == "" {
		return nil, fmt.Errorf("mcp target: no tool selected — pass --tool, or run " +
			"`momus mcp audit` to see what the server exposes")
	}
	if t.Arg == "" {
		return nil, fmt.Errorf("mcp target: no argument chosen for tool %q — pass --arg", t.Tool)
	}

	args := make(map[string]any, len(t.Extra)+1)
	for k, v := range t.Extra {
		args[k] = v
	}
	args[t.Arg] = req.Payload

	res, err := t.Client.CallTool(ctx, t.Tool, args)
	if err != nil {
		return nil, fmt.Errorf("mcp target: calling %s: %w", t.Tool, err)
	}

	text := res.Text()

	// A tool error is a real answer from the server, but it is not the tool
	// doing what the attack asked. Surfacing it as an error keeps it out of the
	// "safe" column: the attack did not get a fair run.
	if res.IsError {
		return nil, fmt.Errorf("mcp target: tool %s reported an error: %s", t.Tool, snippet([]byte(text)))
	}

	// Same guard as every other adapter. A tool that returns only an image, or
	// nothing at all, leaves no text to score, and scoring "" would make every
	// detector miss and call the target safe.
	if err := requireReply(text, "mcp", []byte(text)); err != nil {
		return nil, err
	}

	return &Response{
		Text:      text,
		Raw:       map[string]any{"tool": t.Tool, "blocks": len(res.Content)},
		LatencyMs: time.Since(start).Milliseconds(),
		Status:    http.StatusOK,
	}, nil
}

// InferArg picks which argument a payload should go in, from a tool's input
// schema. It returns "" when the choice is not obvious, because guessing wrong
// means every attack is delivered to a parameter the tool ignores — and a tool
// that never saw the payload will look perfectly safe.
//
// The order is deliberate: a required string beats an optional one, and among
// equals the conventional prompt-ish names win before falling back to the only
// candidate.
func InferArg(schema json.RawMessage) string {
	if len(schema) == 0 {
		return ""
	}
	var s struct {
		Properties map[string]struct {
			Type any `json:"type"`
		} `json:"properties"`
		Required []string `json:"required"`
	}
	if json.Unmarshal(schema, &s) != nil || len(s.Properties) == 0 {
		return ""
	}

	isString := func(v any) bool {
		switch t := v.(type) {
		case string:
			return t == "string"
		case []any: // e.g. ["string","null"]
			for _, x := range t {
				if x == "string" {
					return true
				}
			}
		}
		return false
	}

	required := map[string]bool{}
	for _, r := range s.Required {
		required[r] = true
	}

	var strs, reqStrs []string
	for name, p := range s.Properties {
		if !isString(p.Type) {
			continue
		}
		strs = append(strs, name)
		if required[name] {
			reqStrs = append(reqStrs, name)
		}
	}
	sort.Strings(strs)
	sort.Strings(reqStrs)

	// Names that conventionally carry free text.
	preferred := []string{"query", "prompt", "message", "text", "input", "content", "question", "q"}
	pick := func(from []string) string {
		for _, want := range preferred {
			for _, have := range from {
				if strings.EqualFold(have, want) {
					return have
				}
			}
		}
		if len(from) == 1 {
			return from[0]
		}
		return ""
	}

	if v := pick(reqStrs); v != "" {
		return v
	}
	return pick(strs)
}
