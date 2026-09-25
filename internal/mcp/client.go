// Package mcp is a minimal client for the Model Context Protocol, enough to
// audit a server and to drive its tools as a scan target.
//
// MCP is a JSON-RPC 2.0 protocol over one of two transports: stdio, where the
// server is a subprocess exchanging newline-delimited JSON, and streamable
// HTTP, where each request is a POST whose response is either JSON or an SSE
// stream. Only the handful of methods a scanner needs are implemented —
// initialize, tools/list, tools/call, prompts/list, resources/list — because
// every method added is another shape whose failure modes have to be reasoned
// about, and a scanner that guesses is a scanner that lies.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// ProtocolVersion is the MCP revision this client speaks. Servers echo back the
// version they chose; a mismatch is surfaced rather than ignored, because
// silently talking past a server produces empty results that look like a clean
// audit.
const ProtocolVersion = "2024-11-05"

// Transport carries one JSON-RPC message and returns the reply. Implementations
// must be safe for sequential use; the client serialises calls itself.
type Transport interface {
	// RoundTrip sends a request frame and returns the response frame. A
	// notification (no id) returns nil with no error.
	RoundTrip(ctx context.Context, frame []byte, notification bool) ([]byte, error)
	Close() error
}

// Client speaks MCP to a single server.
type Client struct {
	transport Transport

	mu     sync.Mutex
	nextID int64

	// ServerInfo and Capabilities are filled by Initialize.
	ServerInfo   Implementation `json:"serverInfo"`
	Capabilities map[string]any `json:"capabilities"`
	Negotiated   string         `json:"protocolVersion"`
}

// Implementation identifies a peer.
type Implementation struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Tool is an MCP tool as advertised by the server.
//
// Description is the interesting field for security work: the host model reads
// it verbatim, so it is an injection vector that the user never sees.
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

// Prompt is a server-provided prompt template.
type Prompt struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Arguments   []struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Required    bool   `json:"required"`
	} `json:"arguments"`
}

// Resource is a server-provided resource listing.
type Resource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description"`
	MimeType    string `json:"mimeType"`
}

// ToolResult is the outcome of tools/call.
type ToolResult struct {
	Content []ContentBlock `json:"content"`
	IsError bool           `json:"isError"`
}

// ContentBlock is one piece of a tool result.
type ContentBlock struct {
	Type     string `json:"type"`
	Text     string `json:"text"`
	MimeType string `json:"mimeType"`
	Data     string `json:"data"`
}

// Text concatenates the textual blocks of a result. Non-text blocks are skipped
// deliberately: an image or an audio blob has no text to score, and rendering
// its base64 payload as "the reply" would be scored as a model answer.
func (r *ToolResult) Text() string {
	var b strings.Builder
	for _, c := range r.Content {
		if c.Type == "text" {
			b.WriteString(c.Text)
		}
	}
	return b.String()
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      *int64 `json:"id,omitempty"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      *int64          `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *rpcError       `json:"error"`
}

type rpcError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *rpcError) Error() string {
	if len(e.Data) > 0 {
		return fmt.Sprintf("%s (code %d): %s", e.Message, e.Code, string(e.Data))
	}
	return fmt.Sprintf("%s (code %d)", e.Message, e.Code)
}

// New wraps a transport. Call Initialize before anything else.
func New(t Transport) *Client { return &Client{transport: t} }

// Close releases the transport, stopping a stdio server's process.
func (c *Client) Close() error { return c.transport.Close() }

// call performs one request/response exchange.
func (c *Client) call(ctx context.Context, method string, params any, out any) error {
	c.mu.Lock()
	c.nextID++
	id := c.nextID
	c.mu.Unlock()

	frame, err := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: &id, Method: method, Params: params})
	if err != nil {
		return fmt.Errorf("mcp: encode %s: %w", method, err)
	}
	raw, err := c.transport.RoundTrip(ctx, frame, false)
	if err != nil {
		return fmt.Errorf("mcp %s: %w", method, err)
	}
	var resp rpcResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return fmt.Errorf("mcp %s: unparseable response: %s", method, snippet(raw))
	}
	if resp.Error != nil {
		return fmt.Errorf("mcp %s: %w", method, resp.Error)
	}
	if out == nil {
		return nil
	}
	if len(resp.Result) == 0 {
		return fmt.Errorf("mcp %s: response had no result", method)
	}
	if err := json.Unmarshal(resp.Result, out); err != nil {
		return fmt.Errorf("mcp %s: unexpected result shape: %s", method, snippet(resp.Result))
	}
	return nil
}

// notify sends a notification, which has no reply.
func (c *Client) notify(ctx context.Context, method string, params any) error {
	frame, err := json.Marshal(rpcRequest{JSONRPC: "2.0", Method: method, Params: params})
	if err != nil {
		return err
	}
	_, err = c.transport.RoundTrip(ctx, frame, true)
	return err
}

// Initialize performs the MCP handshake and records what the server said it is.
func (c *Client) Initialize(ctx context.Context) error {
	var res struct {
		ProtocolVersion string         `json:"protocolVersion"`
		Capabilities    map[string]any `json:"capabilities"`
		ServerInfo      Implementation `json:"serverInfo"`
	}
	err := c.call(ctx, "initialize", map[string]any{
		"protocolVersion": ProtocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      Implementation{Name: "momus", Version: "dev"},
	}, &res)
	if err != nil {
		return err
	}
	c.ServerInfo = res.ServerInfo
	c.Capabilities = res.Capabilities
	c.Negotiated = res.ProtocolVersion

	// The spec requires this notification before normal operation; several
	// servers refuse every subsequent call without it.
	if err := c.notify(ctx, "notifications/initialized", map[string]any{}); err != nil {
		return fmt.Errorf("mcp: initialized notification: %w", err)
	}
	return nil
}

// ListTools returns the server's advertised tools.
func (c *Client) ListTools(ctx context.Context) ([]Tool, error) {
	var res struct {
		Tools []Tool `json:"tools"`
	}
	if err := c.call(ctx, "tools/list", map[string]any{}, &res); err != nil {
		return nil, err
	}
	return res.Tools, nil
}

// ListPrompts returns the server's prompt templates. A server that does not
// implement prompts answers with a "method not found" error, which is not a
// failure of the audit — the caller decides.
func (c *Client) ListPrompts(ctx context.Context) ([]Prompt, error) {
	var res struct {
		Prompts []Prompt `json:"prompts"`
	}
	if err := c.call(ctx, "prompts/list", map[string]any{}, &res); err != nil {
		return nil, err
	}
	return res.Prompts, nil
}

// ListResources returns the server's resources.
func (c *Client) ListResources(ctx context.Context) ([]Resource, error) {
	var res struct {
		Resources []Resource `json:"resources"`
	}
	if err := c.call(ctx, "resources/list", map[string]any{}, &res); err != nil {
		return nil, err
	}
	return res.Resources, nil
}

// CallTool invokes a tool and returns its result.
func (c *Client) CallTool(ctx context.Context, name string, args map[string]any) (*ToolResult, error) {
	if args == nil {
		args = map[string]any{}
	}
	var res ToolResult
	err := c.call(ctx, "tools/call", map[string]any{"name": name, "arguments": args}, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

// IsMethodNotFound reports whether an error is JSON-RPC -32601, which means the
// server simply does not implement that capability.
func IsMethodNotFound(err error) bool {
	var e *rpcError
	return errors.As(err, &e) && e.Code == -32601
}

// readFrame reads one newline-delimited JSON message.
//
// The size cap matters: a hostile or broken server can otherwise stream without
// end and exhaust memory before any timeout fires.
func readFrame(r *bufio.Reader, max int64) ([]byte, error) {
	lim := io.LimitedReader{R: r, N: max + 1}
	br := bufio.NewReader(&lim)
	line, err := br.ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return nil, err
	}
	if int64(len(line)) > max {
		return nil, fmt.Errorf("message exceeded %d bytes", max)
	}
	return line, nil
}

func snippet(b []byte) string {
	const max = 240
	s := strings.TrimSpace(string(b))
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}

// defaultTimeout bounds a single exchange. An MCP server that hangs would
// otherwise hang the scan.
const defaultTimeout = 30 * time.Second
