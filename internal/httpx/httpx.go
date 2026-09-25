// Package httpx holds the shared HTTP behaviour Momus needs when talking to
// somebody else's model endpoint: a client that refuses redirects, size-capped
// body reads, and retries for the transient failures real providers return
// (429 throttling, 502/503/504 blips, network errors).
//
// Used by both scan targets (internal/target) and the llm_judge providers
// (internal/judge) so their behaviour can't drift apart.
package httpx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// MaxResponseBytes caps how much of a response we read, so a hostile or broken
// endpoint can't exhaust our memory.
const MaxResponseBytes = 10 << 20 // 10 MiB

// Retry policy. Vars (not consts) so tests can shrink the waits.
var (
	MaxAttempts = 4                      // 1 try + 3 retries
	BaseBackoff = 500 * time.Millisecond // doubled per attempt
	MaxBackoff  = 8 * time.Second

	// MaxRetryElapsed bounds the TOTAL time spent sleeping between retries for a
	// single request. Providers commonly answer 429 with "Retry-After: 60"; without
	// a budget, 200 attacks would stall a scan for over an hour with no output.
	// When a wait doesn't fit the budget we stop and report the throttling.
	MaxRetryElapsed = 20 * time.Second
)

// NewClient returns the client used for outbound calls. It refuses redirects: a
// 3xx would silently turn our POST into a GET and drop the payload, so we
// surface it as an error instead.
func NewClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return fmt.Errorf("refusing redirect to %s (endpoint should not redirect a POST)", req.URL)
		},
	}
}

// ReadCapped reads at most MaxResponseBytes from r.
func ReadCapped(r io.Reader) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, MaxResponseBytes))
}

// Retryable reports whether an HTTP status is worth retrying. Client errors
// (400/401/403/...) are real answers — retrying them only burns quota.
func Retryable(code int) bool {
	switch code {
	case http.StatusRequestTimeout, // 408
		http.StatusTooManyRequests,     // 429
		http.StatusInternalServerError, // 500 (providers use it for transient faults)
		http.StatusBadGateway,          // 502
		http.StatusServiceUnavailable,  // 503
		http.StatusGatewayTimeout,      // 504
		529:                            // Anthropic "overloaded"
		return true
	}
	return false
}

// retryAfter returns the server's requested delay, or -1 when absent/unparseable.
func retryAfter(resp *http.Response) time.Duration {
	if resp == nil {
		return -1
	}
	v := strings.TrimSpace(resp.Header.Get("Retry-After"))
	if v == "" {
		return -1
	}
	if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
		return 0
	}
	return -1
}

// BackoffFor returns how long to wait before the next attempt: the server's
// Retry-After when it sent one, otherwise exponential backoff with jitter.
// Jitter matters because every concurrent worker hits the same rate limit at
// once; without it they'd all retry in lockstep and be throttled again.
func BackoffFor(attempt int, resp *http.Response) time.Duration {
	if d := retryAfter(resp); d >= 0 {
		return d
	}
	// Shift with a cap: a large attempt count would overflow into a negative.
	d := MaxBackoff
	if attempt < 24 {
		if shifted := BaseBackoff << attempt; shifted > 0 && shifted < MaxBackoff {
			d = shifted
		}
	}
	// +/- 20% jitter.
	jitter := time.Duration(rand.Int63n(int64(d/5)+1)) - d/10
	if d+jitter < 0 {
		return 0
	}
	return d + jitter
}

// notWorthRetrying reports errors that a retry cannot fix and that cost money to
// repeat. A client-side timeout is the important one: the provider already
// generated (and billed) the completion, so re-POSTing the same attack multiplies
// cost without improving the result.
func notWorthRetrying(err error) bool {
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		return false
	}
	// A DNS or dial timeout happened before the request reached the model, so
	// nothing was generated or billed — those are worth retrying. Only a timeout
	// while awaiting the response is suppressed.
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return false
	}
	if strings.Contains(err.Error(), "dial tcp") {
		return false
	}
	return true
}

// Do issues the request built by newReq, retrying transient transport errors and
// retryable statuses with backoff. newReq must build a FRESH request each call
// (an attempt consumes the body). A non-retryable error status is returned to the
// caller as a normal response, so callers keep their own status handling.
func Do(ctx context.Context, client *http.Client, newReq func() (*http.Request, error)) (*http.Response, error) {
	if client == nil {
		client = NewClient(0)
	}
	var lastErr error
	var slept time.Duration
	for attempt := 0; attempt < MaxAttempts; attempt++ {
		req, err := newReq()
		if err != nil {
			return nil, err // a build error will not fix itself
		}
		resp, err := client.Do(req)

		// Decide whether to retry and how long to wait; the default branch returns.
		var wait time.Duration
		switch {
		case err != nil:
			if ctx.Err() != nil {
				return nil, err // cancelled/expired: don't retry
			}
			if notWorthRetrying(err) {
				return nil, fmt.Errorf("%w (not retried: a timed-out request may still have been billed; "+
					"raise MOMUS_TIMEOUT for slow models, e.g. MOMUS_TIMEOUT=180s)", err)
			}
			lastErr = err
			wait = BackoffFor(attempt, nil)
		case Retryable(resp.StatusCode):
			// Keep the provider's explanation (quota message, model error): it is the
			// only actionable detail the operator gets.
			body, _ := ReadCapped(io.LimitReader(resp.Body, 4<<10))
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("HTTP %d after %d attempt(s): %s",
				resp.StatusCode, attempt+1, oneLine(body))
			wait = BackoffFor(attempt, resp)
		default:
			return resp, nil
		}
		if attempt == MaxAttempts-1 {
			break // out of attempts
		}
		// Bound the TOTAL sleeping so a big Retry-After can't stall the scan.
		if slept+wait > MaxRetryElapsed {
			lastErr = fmt.Errorf("%w (giving up: retry delay %v exceeds the %v budget)",
				lastErr, wait.Round(time.Second), MaxRetryElapsed)
			break
		}
		slog.Debug("retrying request", "wait", wait, "attempt", attempt+1, "error", lastErr)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
		slept += wait
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("request failed after %d attempts", MaxAttempts)
	}
	return nil, lastErr
}

// oneLine collapses a response body into a short single-line snippet.
func oneLine(b []byte) string {
	s := strings.Join(strings.Fields(string(b)), " ")
	if len(s) > 200 {
		return s[:200] + "…"
	}
	if s == "" {
		return "(empty body)"
	}
	return s
}
