package target

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/momus-ai/momus/internal/httpx"
)

// fastBackoff shrinks the retry waits for tests and restores them after.
func fastBackoff(t *testing.T) {
	t.Helper()
	oldBase, oldMax, oldElapsed := httpx.BaseBackoff, httpx.MaxBackoff, httpx.MaxRetryElapsed
	httpx.BaseBackoff, httpx.MaxBackoff, httpx.MaxRetryElapsed = time.Millisecond, 5*time.Millisecond, 200*time.Millisecond
	t.Cleanup(func() {
		httpx.BaseBackoff, httpx.MaxBackoff, httpx.MaxRetryElapsed = oldBase, oldMax, oldElapsed
	})
}

// TestRetryOn429ThenSuccess: a rate-limited target must be retried, not reported
// inconclusive on the first 429.
func TestRetryOn429ThenSuccess(t *testing.T) {
	fastBackoff(t)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"output": "recovered"})
	}))
	defer srv.Close()

	resp, err := NewHTTP(srv.URL).Send(context.Background(), Request{Payload: "hi"})
	if err != nil {
		t.Fatalf("expected the retry to succeed, got %v", err)
	}
	if resp.Text != "recovered" {
		t.Errorf("text = %q, want 'recovered'", resp.Text)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("want 2 requests (429 then 200), got %d", got)
	}
}

// TestRetryExhaustedOn429 : persistent throttling must surface as an ERROR
// (-> inconclusive), never as a scored/"safe" response.
func TestRetryExhaustedOn429(t *testing.T) {
	fastBackoff(t)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	if _, err := NewHTTP(srv.URL).Send(context.Background(), Request{Payload: "hi"}); err == nil {
		t.Fatal("persistent 429 must return an error")
	}
	if got := calls.Load(); int(got) != httpx.MaxAttempts {
		t.Errorf("want %d attempts, got %d", httpx.MaxAttempts, got)
	}
}

// TestRetryBudgetStopsLongRetryAfter is the guard against a silent hour-long
// stall: providers answer 429 with "Retry-After: 60", and 200 attacks waiting
// 3x60s each would hang a scan. A wait that doesn't fit the budget gives up now.
func TestRetryBudgetStopsLongRetryAfter(t *testing.T) {
	oldElapsed := httpx.MaxRetryElapsed
	httpx.MaxRetryElapsed = 100 * time.Millisecond
	t.Cleanup(func() { httpx.MaxRetryElapsed = oldElapsed })

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "60") // far beyond the budget
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	start := time.Now()
	_, err := NewHTTP(srv.URL).Send(context.Background(), Request{Payload: "hi"})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error for sustained throttling")
	}
	if elapsed > 2*time.Second {
		t.Errorf("must not sleep a 60s Retry-After; took %v", elapsed)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("an un-affordable Retry-After should stop after the first try, got %d", got)
	}
}

// TestRetryErrorKeepsProviderMessage: the quota/error text from the provider is
// the only actionable detail the operator gets, so it must survive into the error.
func TestRetryErrorKeepsProviderMessage(t *testing.T) {
	fastBackoff(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"message":"exceeded token rate limit of your current quota"}}`))
	}))
	defer srv.Close()

	_, err := NewHTTP(srv.URL).Send(context.Background(), Request{Payload: "hi"})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !contains(err.Error(), "token rate limit") {
		t.Errorf("provider explanation lost; got %q", err.Error())
	}
}

// TestRetryOn503 covers transient server blips.
func TestRetryOn503(t *testing.T) {
	fastBackoff(t)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"output": "ok now"})
	}))
	defer srv.Close()

	resp, err := NewHTTP(srv.URL).Send(context.Background(), Request{Payload: "hi"})
	if err != nil {
		t.Fatalf("expected recovery after 503s, got %v", err)
	}
	if resp.Text != "ok now" {
		t.Errorf("text = %q", resp.Text)
	}
}

// TestRetryableStatuses pins the transient set, including the ones providers
// actually return (Anthropic 529 overloaded, 500, 408).
func TestRetryableStatuses(t *testing.T) {
	for _, code := range []int{408, 429, 500, 502, 503, 504, 529} {
		if !httpx.Retryable(code) {
			t.Errorf("HTTP %d should be retryable", code)
		}
	}
	for _, code := range []int{400, 401, 403, 404, 422} {
		if httpx.Retryable(code) {
			t.Errorf("HTTP %d must NOT be retried (it is a real answer)", code)
		}
	}
}

// TestNoRetryOnClientError: a 401 is a real answer — retrying burns quota.
func TestNoRetryOnClientError(t *testing.T) {
	fastBackoff(t)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	if _, err := NewHTTP(srv.URL).Send(context.Background(), Request{Payload: "hi"}); err == nil {
		t.Fatal("401 must error")
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("401 must not be retried; got %d attempts", got)
	}
}

// TestNoRetryOnTimeout: a client-side timeout means the provider likely already
// generated (and billed) the completion — retrying multiplies cost 4x.
func TestNoRetryOnTimeout(t *testing.T) {
	fastBackoff(t)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		time.Sleep(300 * time.Millisecond) // outlive the client timeout below
	}))
	defer srv.Close()

	tgt := NewHTTP(srv.URL)
	tgt.Client.Timeout = 50 * time.Millisecond
	if _, err := tgt.Send(context.Background(), Request{Payload: "hi"}); err == nil {
		t.Fatal("expected a timeout error")
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("a timed-out request must not be retried (billing); got %d attempts", got)
	}
}

// TestRetryRespectsCancellation: a cancelled scan must not keep waiting.
func TestRetryRespectsCancellation(t *testing.T) {
	oldBase, oldElapsed := httpx.BaseBackoff, httpx.MaxRetryElapsed
	httpx.BaseBackoff, httpx.MaxRetryElapsed = 2*time.Second, time.Minute
	t.Cleanup(func() { httpx.BaseBackoff, httpx.MaxRetryElapsed = oldBase, oldElapsed })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()

	start := time.Now()
	if _, err := NewHTTP(srv.URL).Send(ctx, Request{Payload: "hi"}); err == nil {
		t.Fatal("expected an error after cancellation")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("cancellation should abort the backoff quickly, took %v", elapsed)
	}
}

// TestBackoffUsesRetryAfterAndJitter: Retry-After is honoured verbatim (the
// caller enforces the budget); without it, backoff grows with jitter.
func TestBackoffUsesRetryAfterAndJitter(t *testing.T) {
	mk := func(v string) *http.Response {
		return &http.Response{Header: http.Header{"Retry-After": []string{v}}}
	}
	if d := httpx.BackoffFor(0, mk("0")); d != 0 {
		t.Errorf("Retry-After: 0 -> %v, want 0", d)
	}
	if d := httpx.BackoffFor(0, mk("7")); d != 7*time.Second {
		t.Errorf("Retry-After: 7 -> %v, want 7s", d)
	}
	// Garbage falls back to jittered exponential backoff (within +/-20%).
	lo := time.Duration(float64(httpx.BaseBackoff) * 0.75)
	hi := time.Duration(float64(httpx.BaseBackoff) * 1.25)
	for i := 0; i < 20; i++ {
		d := httpx.BackoffFor(0, mk("not-a-number"))
		if d < lo || d > hi {
			t.Fatalf("jittered backoff %v outside [%v,%v]", d, lo, hi)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
