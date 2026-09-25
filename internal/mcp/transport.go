package mcp

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// maxFrame caps a single JSON-RPC message. Servers under audit are, by
// definition, not trusted to be well behaved.
const maxFrame = 8 << 20 // 8 MiB

// ── stdio ────────────────────────────────────────────────────────────────────

// StdioTransport runs an MCP server as a subprocess and exchanges
// newline-delimited JSON over its stdin and stdout.
//
// This spawns a process the caller names. That is inherent to auditing a stdio
// MCP server — there is no other way to talk to one — but it is worth being
// explicit that scanning a server means executing it.
type StdioTransport struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader

	mu     sync.Mutex
	closed bool

	// Stderr captures the server's diagnostics so a failure can be explained.
	// Servers routinely log to stderr, and discarding it leaves "no response"
	// as the only thing we could report.
	Stderr *bytes.Buffer
}

// NewStdio starts the given command as an MCP server, inheriting the current
// environment.
func NewStdio(ctx context.Context, name string, args ...string) (*StdioTransport, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = os.Environ()
	return NewStdioCmd(cmd)
}

// NewStdioCmd starts an already-configured command as an MCP server. Use this
// when the server needs a particular environment or working directory — many
// MCP servers are configured entirely through environment variables.
func NewStdioCmd(cmd *exec.Cmd) (*StdioTransport, error) {
	if cmd.Env == nil {
		cmd.Env = os.Environ()
	}
	name := cmd.Path
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("mcp stdio: stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("mcp stdio: stdout: %w", err)
	}
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("mcp stdio: start %s: %w", name, err)
	}
	return &StdioTransport{
		cmd:    cmd,
		stdin:  stdin,
		stdout: bufio.NewReaderSize(stdout, 64<<10),
		Stderr: &errBuf,
	}, nil
}

// RoundTrip writes a frame and reads the matching reply.
func (t *StdioTransport) RoundTrip(ctx context.Context, frame []byte, notification bool) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil, errors.New("mcp stdio: transport closed")
	}

	if _, err := t.stdin.Write(append(frame, '\n')); err != nil {
		return nil, fmt.Errorf("mcp stdio: write: %w%s", err, t.stderrHint())
	}
	if notification {
		return nil, nil
	}

	type result struct {
		b   []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		for {
			line, err := readFrame(t.stdout, maxFrame)
			if err != nil {
				done <- result{nil, err}
				return
			}
			trimmed := bytes.TrimSpace(line)
			// Servers sometimes emit blank lines or log noise on stdout. Skip
			// anything that is not a JSON object rather than failing the audit
			// on a stray line.
			if len(trimmed) == 0 || trimmed[0] != '{' {
				continue
			}
			done <- result{trimmed, nil}
			return
		}
	}()

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("mcp stdio: %w%s", ctx.Err(), t.stderrHint())
	case r := <-done:
		if r.err != nil {
			return nil, fmt.Errorf("mcp stdio: read: %w%s", r.err, t.stderrHint())
		}
		return r.b, nil
	}
}

// stderrHint appends what the server printed, when it printed anything. A
// stdio server that dies on start otherwise produces an unexplainable EOF.
func (t *StdioTransport) stderrHint() string {
	if t.Stderr == nil || t.Stderr.Len() == 0 {
		return ""
	}
	return "; server stderr: " + snippet(t.Stderr.Bytes())
}

// Close shuts the server down, first politely and then firmly.
func (t *StdioTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true

	_ = t.stdin.Close() // EOF on stdin is how an MCP server is asked to exit

	done := make(chan error, 1)
	go func() { done <- t.cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		if t.cmd.Process != nil {
			_ = t.cmd.Process.Kill()
		}
		<-done
	}
	return nil
}

// ── streamable HTTP ──────────────────────────────────────────────────────────

// HTTPTransport speaks MCP over streamable HTTP: each request is a POST whose
// response is either a JSON object or an SSE stream carrying one.
type HTTPTransport struct {
	URL    string
	Client *http.Client
	Header http.Header

	mu        sync.Mutex
	sessionID string
}

// NewHTTP builds an HTTP transport for an MCP endpoint.
func NewHTTP(url string, client *http.Client) *HTTPTransport {
	if client == nil {
		client = &http.Client{Timeout: defaultTimeout}
	}
	return &HTTPTransport{URL: url, Client: client, Header: http.Header{}}
}

// RoundTrip posts a frame and returns the JSON-RPC response.
func (t *HTTPTransport) RoundTrip(ctx context.Context, frame []byte, notification bool) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.URL, bytes.NewReader(frame))
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/json")
	// Both are required by the streamable-HTTP transport: a server may answer
	// either with JSON or by opening an SSE stream.
	req.Header.Set("accept", "application/json, text/event-stream")
	for k, v := range t.Header {
		req.Header[k] = v
	}
	t.mu.Lock()
	if t.sessionID != "" {
		req.Header.Set("mcp-session-id", t.sessionID)
	}
	t.mu.Unlock()

	resp, err := t.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if sid := resp.Header.Get("mcp-session-id"); sid != "" {
		t.mu.Lock()
		t.sessionID = sid
		t.mu.Unlock()
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFrame+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxFrame {
		return nil, fmt.Errorf("response exceeded %d bytes", maxFrame)
	}

	// A notification is answered with 202 and no body.
	if notification {
		if resp.StatusCode >= 400 {
			return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, snippet(body))
		}
		return nil, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, snippet(body))
	}

	if strings.Contains(strings.ToLower(resp.Header.Get("content-type")), "text/event-stream") {
		msg := firstSSEData(body)
		if msg == nil {
			return nil, fmt.Errorf("event stream carried no JSON-RPC message: %s", snippet(body))
		}
		return msg, nil
	}
	return body, nil
}

// Close is a no-op; HTTP holds nothing open between requests.
func (t *HTTPTransport) Close() error { return nil }

// firstSSEData pulls the first JSON object out of an SSE body. Only one
// response per request is expected, so later events are ignored rather than
// buffered.
func firstSSEData(body []byte) []byte {
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimRight(line, "\r")
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" || payload == "[DONE]" {
			continue
		}
		if payload[0] == '{' {
			return []byte(payload)
		}
	}
	return nil
}
