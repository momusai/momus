package target

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/momusai/momus/internal/mcp"
)

// stubTransport answers MCP frames from a canned handler, so these tests need
// no server and no network.
type stubTransport struct {
	reply func(method string, args map[string]any) (any, *stubErr)
	calls []map[string]any
}

type stubErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (s *stubTransport) RoundTrip(_ context.Context, frame []byte, notification bool) ([]byte, error) {
	var req struct {
		ID     *int64 `json:"id"`
		Method string `json:"method"`
		Params struct {
			Arguments map[string]any `json:"arguments"`
		} `json:"params"`
	}
	if err := json.Unmarshal(frame, &req); err != nil {
		return nil, err
	}
	if notification || req.ID == nil {
		return nil, nil
	}
	if req.Method == "tools/call" {
		s.calls = append(s.calls, req.Params.Arguments)
	}
	result, rpcErr := s.reply(req.Method, req.Params.Arguments)
	msg := map[string]any{"jsonrpc": "2.0", "id": req.ID}
	if rpcErr != nil {
		msg["error"] = rpcErr
	} else {
		msg["result"] = result
	}
	return json.Marshal(msg)
}

func (s *stubTransport) Close() error { return nil }

func mcpTargetWith(t *testing.T, reply func(string, map[string]any) (any, *stubErr)) (*MCPTarget, *stubTransport) {
	t.Helper()
	st := &stubTransport{reply: reply}
	c := mcp.New(st)
	if err := c.Initialize(context.Background()); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	return NewMCPTarget(c, "search", "query"), st
}

func okInit(method string, _ map[string]any) (any, *stubErr) {
	if method == "initialize" {
		return map[string]any{"protocolVersion": mcp.ProtocolVersion,
			"serverInfo": map[string]any{"name": "stub", "version": "0"}}, nil
	}
	return nil, &stubErr{Code: -32601, Message: "Method not found"}
}

func TestMCPTargetSendsPayloadAndReadsText(t *testing.T) {
	tgt, st := mcpTargetWith(t, func(method string, args map[string]any) (any, *stubErr) {
		if method != "tools/call" {
			return okInit(method, args)
		}
		return map[string]any{"content": []any{
			map[string]any{"type": "text", "text": "found: "},
			map[string]any{"type": "image", "data": "AAA"},
			map[string]any{"type": "text", "text": args["query"]},
		}}, nil
	})

	resp, err := tgt.Send(context.Background(), Request{Payload: "AB123_HIT"})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if resp.Text != "found: AB123_HIT" {
		t.Errorf("Text = %q; image blocks must be skipped and text joined", resp.Text)
	}
	if len(st.calls) != 1 || st.calls[0]["query"] != "AB123_HIT" {
		t.Errorf("payload did not reach the chosen argument: %+v", st.calls)
	}
}

// Contract (B): anything that leaves no scoreable text must be an error, never
// an empty string that every detector misses and the scanner calls safe.
func TestMCPTargetUnscoreableRepliesError(t *testing.T) {
	cases := map[string]any{
		"tool reported an error": map[string]any{
			"content": []any{map[string]any{"type": "text", "text": "permission denied"}},
			"isError": true,
		},
		"no content at all": map[string]any{"content": []any{}},
		"only a non-text blob": map[string]any{"content": []any{
			map[string]any{"type": "image", "data": "AAAA"},
		}},
		"whitespace only": map[string]any{"content": []any{
			map[string]any{"type": "text", "text": "  \n\t "},
		}},
	}
	for name, result := range cases {
		t.Run(name, func(t *testing.T) {
			tgt, _ := mcpTargetWith(t, func(method string, args map[string]any) (any, *stubErr) {
				if method != "tools/call" {
					return okInit(method, args)
				}
				return result, nil
			})
			resp, err := tgt.Send(context.Background(), Request{Payload: "attack"})
			if err == nil {
				t.Errorf("scored %q instead of erroring", resp.Text)
			}
		})
	}
}

func TestMCPTargetRequiresToolAndArg(t *testing.T) {
	st := &stubTransport{reply: okInit}
	c := mcp.New(st)
	if err := c.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := NewMCPTarget(c, "", "query").Send(context.Background(), Request{Payload: "x"}); err == nil {
		t.Error("a target with no tool must error rather than call the server")
	}
	if _, err := NewMCPTarget(c, "search", "").Send(context.Background(), Request{Payload: "x"}); err == nil {
		t.Error("a target with no argument must error rather than guess")
	}
}

// Picking the wrong argument delivers every attack to a parameter the tool
// ignores, and a tool that never saw the payload looks perfectly safe. So
// InferArg has to return "" whenever the choice is not obvious.
func TestInferArg(t *testing.T) {
	cases := []struct {
		name, schema, want string
	}{
		{"single required string", `{"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}`, "query"},
		{"single optional string", `{"type":"object","properties":{"text":{"type":"string"}}}`, "text"},
		{"prefers the conventional name", `{"type":"object","properties":{"limit":{"type":"string"},"prompt":{"type":"string"}}}`, "prompt"},
		{"required beats optional", `{"type":"object","properties":{"note":{"type":"string"},"message":{"type":"string"}},"required":["message"]}`, "message"},
		{"nullable string still counts", `{"type":"object","properties":{"input":{"type":["string","null"]}}}`, "input"},
		{"ignores non-strings", `{"type":"object","properties":{"count":{"type":"integer"},"q":{"type":"string"}}}`, "q"},

		// Ambiguous or unusable: must refuse rather than guess.
		{"two unconventional strings", `{"type":"object","properties":{"alpha":{"type":"string"},"beta":{"type":"string"}}}`, ""},
		{"no string properties", `{"type":"object","properties":{"count":{"type":"integer"}}}`, ""},
		{"no properties", `{"type":"object"}`, ""},
		{"empty schema", ``, ""},
		{"not json", `nonsense`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := InferArg(json.RawMessage(tc.schema)); got != tc.want {
				t.Errorf("InferArg = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestMCPTargetSurfacesServerErrors(t *testing.T) {
	tgt, _ := mcpTargetWith(t, func(method string, args map[string]any) (any, *stubErr) {
		if method != "tools/call" {
			return okInit(method, args)
		}
		return nil, &stubErr{Code: -32602, Message: "invalid arguments"}
	})
	_, err := tgt.Send(context.Background(), Request{Payload: "attack"})
	if err == nil {
		t.Fatal("a JSON-RPC error must surface")
	}
	if !strings.Contains(err.Error(), "invalid arguments") {
		t.Errorf("the server's own message was dropped: %v", err)
	}
}
