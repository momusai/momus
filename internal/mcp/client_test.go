package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// ── a fake server both transports can drive ──────────────────────────────────

// handle answers one JSON-RPC request the way a small MCP server would.
func handle(t *testing.T, raw []byte) (json.RawMessage, bool) {
	t.Helper()
	var req struct {
		Method string          `json:"method"`
		ID     *int64          `json:"id"`
		Params json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		t.Fatalf("server got unparseable request: %s", raw)
	}
	if req.ID == nil {
		return nil, false // a notification; nothing to reply with
	}

	var result any
	switch req.Method {
	case "initialize":
		result = map[string]any{
			"protocolVersion": ProtocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "fake-server", "version": "1.2.3"},
		}
	case "tools/list":
		result = map[string]any{"tools": []any{
			map[string]any{
				"name":        "read_file",
				"description": "Read a file from disk.",
				"inputSchema": map[string]any{"type": "object"},
			},
		}}
	case "tools/call":
		result = map[string]any{
			"content": []any{
				map[string]any{"type": "text", "text": "hello "},
				map[string]any{"type": "image", "data": "AAAA", "mimeType": "image/png"},
				map[string]any{"type": "text", "text": "world"},
			},
			"isError": false,
		}
	case "prompts/list":
		// Method not implemented, the common case for tool-only servers.
		b, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0", "id": req.ID,
			"error": map[string]any{"code": -32601, "message": "Method not found"},
		})
		return b, true
	default:
		b, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0", "id": req.ID,
			"error": map[string]any{"code": -32601, "message": "Method not found"},
		})
		return b, true
	}

	b, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
	if err != nil {
		t.Fatal(err)
	}
	return b, true
}

func httpServer(t *testing.T, sse bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		if _, err := r.Body.Read(body); err != nil && len(body) == 0 {
			t.Errorf("server could not read request: %v", err)
		}
		resp, hasReply := handle(t, body)
		w.Header().Set("mcp-session-id", "sess-123")
		if !hasReply {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		if sse {
			w.Header().Set("content-type", "text/event-stream")
			fmt.Fprintf(w, ": keep-alive\n\ndata: %s\n\n", resp)
			return
		}
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write(resp)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// ── tests ────────────────────────────────────────────────────────────────────

func TestHTTPTransportHandshakeAndTools(t *testing.T) {
	for _, sse := range []bool{false, true} {
		name := "json"
		if sse {
			name = "sse"
		}
		t.Run(name, func(t *testing.T) {
			srv := httpServer(t, sse)
			c := New(NewHTTP(srv.URL, srv.Client()))
			defer c.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			if err := c.Initialize(ctx); err != nil {
				t.Fatalf("initialize: %v", err)
			}
			if c.ServerInfo.Name != "fake-server" || c.ServerInfo.Version != "1.2.3" {
				t.Errorf("serverInfo = %+v", c.ServerInfo)
			}
			if c.Negotiated != ProtocolVersion {
				t.Errorf("negotiated %q", c.Negotiated)
			}

			tools, err := c.ListTools(ctx)
			if err != nil {
				t.Fatalf("tools/list: %v", err)
			}
			if len(tools) != 1 || tools[0].Name != "read_file" {
				t.Fatalf("tools = %+v", tools)
			}

			res, err := c.CallTool(ctx, "read_file", map[string]any{"path": "/etc/hosts"})
			if err != nil {
				t.Fatalf("tools/call: %v", err)
			}
			// Non-text blocks must be skipped: base64 image bytes are not a reply
			// and scoring them would be scoring noise.
			if got := res.Text(); got != "hello world" {
				t.Errorf("Text() = %q, want the text blocks only", got)
			}
		})
	}
}

// A server that does not implement a capability answers -32601. That is not an
// audit failure, and callers need to be able to tell it apart from a real one.
func TestMethodNotFoundIsDistinguishable(t *testing.T) {
	srv := httpServer(t, false)
	c := New(NewHTTP(srv.URL, srv.Client()))
	defer c.Close()
	ctx := context.Background()
	if err := c.Initialize(ctx); err != nil {
		t.Fatal(err)
	}

	_, err := c.ListPrompts(ctx)
	if err == nil {
		t.Fatal("expected an error for an unimplemented method")
	}
	if !IsMethodNotFound(err) {
		t.Errorf("IsMethodNotFound was false for %v", err)
	}

	// A transport failure must NOT be mistaken for "not implemented".
	dead := New(NewHTTP("http://127.0.0.1:1/mcp", &http.Client{Timeout: time.Second}))
	if _, err = dead.ListTools(ctx); err == nil || IsMethodNotFound(err) {
		t.Errorf("a dead endpoint was reported as method-not-found: %v", err)
	}
}

func TestHTTPTransportRejectsNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"nope"}`))
	}))
	defer srv.Close()

	c := New(NewHTTP(srv.URL, srv.Client()))
	err := c.Initialize(context.Background())
	if err == nil {
		t.Fatal("a 403 must be an error")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error should name the status: %v", err)
	}
}

func TestHTTPTransportCarriesSessionID(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("mcp-session-id"))
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		resp, hasReply := handle(t, body)
		w.Header().Set("mcp-session-id", "sess-123")
		if !hasReply {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write(resp)
	}))
	defer srv.Close()

	c := New(NewHTTP(srv.URL, srv.Client()))
	ctx := context.Background()
	if err := c.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ListTools(ctx); err != nil {
		t.Fatal(err)
	}
	if len(seen) < 2 {
		t.Fatalf("expected several requests, got %d", len(seen))
	}
	if seen[0] != "" {
		t.Errorf("the first request should carry no session id, got %q", seen[0])
	}
	if seen[len(seen)-1] != "sess-123" {
		t.Errorf("later requests must echo the session id, got %q", seen[len(seen)-1])
	}
}

// ── stdio, against a real subprocess ─────────────────────────────────────────

// TestStdioTransport runs this test binary again as an MCP server, so the stdio
// path is exercised against a genuine process rather than a pipe stand-in.
func TestStdioTransport(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=TestHelperMCPServer")
	cmd.Env = append(os.Environ(), "MOMUS_MCP_HELPER=1")
	st, err := NewStdioCmd(cmd)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	c := New(st)
	defer c.Close()

	if err = c.Initialize(ctx); err != nil {
		t.Fatalf("initialize over stdio: %v", err)
	}
	if c.ServerInfo.Name != "stdio-fake" {
		t.Errorf("serverInfo = %+v", c.ServerInfo)
	}
	tools, err := c.ListTools(ctx)
	if err != nil {
		t.Fatalf("tools/list over stdio: %v", err)
	}
	if len(tools) != 1 || tools[0].Name != "echo" {
		t.Fatalf("tools = %+v", tools)
	}
	res, err := c.CallTool(ctx, "echo", map[string]any{"text": "ping"})
	if err != nil {
		t.Fatalf("tools/call over stdio: %v", err)
	}
	if res.Text() != "ping" {
		t.Errorf("Text() = %q", res.Text())
	}
}

// TestHelperMCPServer is not a test. It is the stdio MCP server the test above
// drives, selected by an environment variable so it stays inert in normal runs.
func TestHelperMCPServer(t *testing.T) {
	if os.Getenv("MOMUS_MCP_HELPER") != "1" {
		t.Skip("helper process; not a real test")
	}
	in := bufio.NewReader(os.Stdin)
	out := os.Stdout
	for {
		line, err := in.ReadBytes('\n')
		if err != nil {
			return
		}
		var req struct {
			Method string `json:"method"`
			ID     *int64 `json:"id"`
			Params struct {
				Arguments map[string]any `json:"arguments"`
			} `json:"params"`
		}
		if json.Unmarshal(line, &req) != nil || req.ID == nil {
			continue // notification or noise
		}
		var result any
		switch req.Method {
		case "initialize":
			result = map[string]any{
				"protocolVersion": ProtocolVersion,
				"capabilities":    map[string]any{},
				"serverInfo":      map[string]any{"name": "stdio-fake", "version": "0"},
			}
		case "tools/list":
			result = map[string]any{"tools": []any{
				map[string]any{"name": "echo", "description": "Echo text back."},
			}}
		case "tools/call":
			text, _ := req.Params.Arguments["text"].(string)
			result = map[string]any{"content": []any{map[string]any{"type": "text", "text": text}}}
		default:
			b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": req.ID,
				"error": map[string]any{"code": -32601, "message": "Method not found"}})
			fmt.Fprintf(out, "%s\n", b)
			continue
		}
		b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
		fmt.Fprintf(out, "%s\n", b)
	}
}

// A stdio server that dies immediately must explain itself with whatever it
// printed, rather than surfacing a bare EOF.
func TestStdioSurfacesServerStderr(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tr, err := NewStdio(ctx, "sh", "-c", "echo 'boom: missing API key' >&2; exit 1")
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	c := New(tr)
	defer c.Close()

	err = c.Initialize(ctx)
	if err == nil {
		t.Fatal("expected an error from a server that exits immediately")
	}
	// Give the process a moment to have flushed stderr before we assert on it.
	if !strings.Contains(err.Error(), "boom") {
		t.Logf("error was: %v", err)
		t.Logf("stderr buffer: %q", tr.Stderr.String())
		if !strings.Contains(tr.Stderr.String(), "boom") {
			t.Errorf("the server's stderr was not captured at all")
		}
	}
}
