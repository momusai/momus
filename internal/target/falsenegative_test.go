package target

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// These guard the worst failure mode for a security scanner: reporting "safe"
// for a target it never actually tested. Each case previously produced a
// scorable (empty or wrong) response text instead of an error.

// TestOpenAIRefusesRedirect: a gateway 302 would turn the POST into a GET and
// drop the attack payload, then let the gateway banner be scored as the reply.
func TestOpenAIRefusesRedirect(t *testing.T) {
	var gotGET bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			gotGET = true
			_ = json.NewEncoder(w).Encode(map[string]any{
				"choices": []any{map[string]any{"message": map[string]any{"content": "Welcome to the API gateway."}}},
			})
			return
		}
		http.Redirect(w, r, "/v2/chat/completions", http.StatusFound)
	}))
	defer srv.Close()

	_, err := NewOpenAI(srv.URL+"/v1/chat/completions").Send(context.Background(), Request{Payload: "attack"})
	if err == nil {
		t.Fatal("a redirect must error (-> inconclusive), never be scored as a model reply")
	}
	if gotGET {
		t.Error("the redirect was followed; the attack payload was dropped")
	}
}

// TestHTTPUnknownJSONShapeErrors: a JSON envelope with no recognizable reply key
// must not be scored as an empty reply (which reads as "safe").
func TestHTTPUnknownJSONShapeErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"completion": "I refuse"}})
	}))
	defer srv.Close()

	if _, err := NewHTTP(srv.URL).Send(context.Background(), Request{Payload: "hi"}); err == nil {
		t.Fatal("an unrecognized JSON shape must error, not score as an empty (safe) reply")
	}
}

// TestHTTPHTMLPageErrors: pointing Momus at a web UI or site root must fail
// loudly rather than score the page markup as the model's answer.
func TestHTTPHTMLPageErrors(t *testing.T) {
	for _, body := range []string{
		"<!doctype html><html><body><h1>My App</h1></body></html>",
		"<html><head><title>Login</title></head></html>",
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("content-type", "text/html")
			_, _ = w.Write([]byte(body))
		}))
		if _, err := NewHTTP(srv.URL).Send(context.Background(), Request{Payload: "hi"}); err == nil {
			t.Errorf("an HTML page must error, not be scored as a reply (body %.30q)", body)
		}
		srv.Close()
	}
}

// TestHTTPEmptyBodyErrors: a 200 with no body tells us nothing.
func TestHTTPEmptyBodyErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	if _, err := NewHTTP(srv.URL).Send(context.Background(), Request{Payload: "hi"}); err == nil {
		t.Fatal("an empty 200 body must error, not score as a safe reply")
	}
}

// TestHTTPPlainTextStillWorks: a legitimate plain-text endpoint must keep working.
func TestHTTPPlainTextStillWorks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "text/plain")
		_, _ = w.Write([]byte("I can't help with that."))
	}))
	defer srv.Close()
	resp, err := NewHTTP(srv.URL).Send(context.Background(), Request{Payload: "hi"})
	if err != nil {
		t.Fatalf("plain-text replies must still be accepted: %v", err)
	}
	if resp.Text != "I can't help with that." {
		t.Errorf("text = %q", resp.Text)
	}
}

// A 3xx WITHOUT a Location header never reaches the redirect refusal in
// newHTTPClient — Go only consults CheckRedirect when it is about to follow a
// redirect, which needs a parseable Location. Such a response used to pass the
// old `>= 400` guard and be scored as the model's reply, so a gateway answering
// "302 Found — sign in at the portal" produced a full pack of "safe" verdicts
// and exit 0 against a target that never saw the payload.
func TestLocationlessRedirectIsNotScored(t *testing.T) {
	for _, code := range []int{300, 301, 302, 303, 307, 308} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("content-type", "text/plain")
				w.WriteHeader(code) // deliberately no Location
				fmt.Fprint(w, "Found. This endpoint has moved; sign in at the portal.")
			}))
			defer srv.Close()

			if _, err := NewHTTP(srv.URL).Send(context.Background(), Request{Payload: "attack"}); err == nil {
				t.Errorf("HTTP %d was scored as a model reply; it must error (-> inconclusive)", code)
			}
		})
	}
}

// The same hole in the provider adapters: a 3xx carrying a provider-shaped JSON
// envelope parsed cleanly and its text was scored.
func TestLocationlessRedirectIsNotScoredByProviders(t *testing.T) {
	body := map[string]any{
		"choices": []any{map[string]any{"message": map[string]any{"content": "sure, here is how"}}},
		"content": []any{map[string]any{"type": "text", "text": "sure, here is how"}},
		"candidates": []any{map[string]any{
			"content": map[string]any{"parts": []any{map[string]any{"text": "sure, here is how"}}},
		}},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusFound) // no Location
		_ = json.NewEncoder(w).Encode(body)
	}))
	defer srv.Close()

	for name, tgt := range map[string]Target{
		"openai":    NewOpenAI(srv.URL),
		"anthropic": NewAnthropic(srv.URL),
		"gemini":    NewGemini(srv.URL),
		"azure":     NewAzureOpenAI(srv.URL),
	} {
		if _, err := tgt.Send(context.Background(), Request{Payload: "attack"}); err == nil {
			t.Errorf("%s: a 302 body was scored as a model reply", name)
		}
	}
}

// 1xx and other non-2xx statuses are equally unscoreable.
func TestNon2xxIsNotScored(t *testing.T) {
	for _, code := range []int{204, 205, 226, 402, 418, 451, 599} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("content-type", "application/json")
			w.WriteHeader(code)
			fmt.Fprint(w, `{"output":"anything at all"}`)
		}))
		_, err := NewHTTP(srv.URL).Send(context.Background(), Request{Payload: "attack"})
		srv.Close()
		if code >= 200 && code < 300 {
			continue // 2xx is legitimately scoreable; only asserting the rest
		}
		if err == nil {
			t.Errorf("HTTP %d was scored as a model reply", code)
		}
	}
}

// A streaming endpoint must be refused, not scored. The generic adapter's last
// resort is to treat an unrecognised body as plain text, so raw SSE frames used
// to become the "reply" — no canary ever appears in "data: {...}" envelopes, so
// the whole pack came back safe with exit 0. The liveness probe only catches
// this when the stream is byte-identical between prompts; a real stream varies.
func TestSSEBodyIsNotScored(t *testing.T) {
	frames := "data: {\"choices\":[{\"delta\":{\"content\":\"Sure\"}}]}\n\n" +
		"data: {\"choices\":[{\"delta\":{\"content\":\", here you go\"}}]}\n\n" +
		"data: [DONE]\n\n"

	t.Run("declared as text/event-stream", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("content-type", "text/event-stream")
			fmt.Fprint(w, frames)
		}))
		defer srv.Close()
		if _, err := NewHTTP(srv.URL).Send(context.Background(), Request{Payload: "attack"}); err == nil {
			t.Error("an SSE stream was scored as a model reply")
		}
	})

	// Servers that stream while mislabelling the content type are common enough
	// that the wire shape has to be checked too.
	t.Run("mislabelled as text/plain", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("content-type", "text/plain")
			fmt.Fprint(w, frames)
		}))
		defer srv.Close()
		if _, err := NewHTTP(srv.URL).Send(context.Background(), Request{Payload: "attack"}); err == nil {
			t.Error("a mislabelled SSE stream was scored as a model reply")
		}
	})

	t.Run("provider adapters", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("content-type", "text/event-stream")
			fmt.Fprint(w, frames)
		}))
		defer srv.Close()
		for name, tgt := range map[string]Target{
			"openai":    NewOpenAI(srv.URL),
			"anthropic": NewAnthropic(srv.URL),
			"gemini":    NewGemini(srv.URL),
			"azure":     NewAzureOpenAI(srv.URL),
		} {
			if _, err := tgt.Send(context.Background(), Request{Payload: "attack"}); err == nil {
				t.Errorf("%s: an SSE stream was scored as a model reply", name)
			}
		}
	})
}

// The SSE guard must not fire on an ordinary reply that merely mentions "data:".
func TestSSEGuardDoesNotOverTrigger(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"output": "Here's the schema:\ndata: the payload field\nIt has one data: entry per row.",
		})
	}))
	defer srv.Close()

	resp, err := NewHTTP(srv.URL).Send(context.Background(), Request{Payload: "attack"})
	if err != nil {
		t.Fatalf("a normal JSON reply mentioning \"data:\" was rejected: %v", err)
	}
	if !strings.Contains(resp.Text, "schema") {
		t.Errorf("unexpected reply text: %q", resp.Text)
	}
}

// The generic adapter's raw-body fallback used to accept ANY non-JSON 2xx body
// as the model's reply. None of these shapes is a reply, and none can contain a
// canary, so each produced a full pack of "safe" verdicts for an untested
// target. Every case below was observed being SCORED before the content-type
// gate was added.
func TestNonReplyBodiesAreNotScored(t *testing.T) {
	cases := []struct {
		name        string
		contentType string
		encoding    string
		body        []byte
	}{
		{"pdf", "application/pdf", "", []byte("%PDF-1.4\n\x00\x01\x02binarygarbage")},
		{"octet-stream", "application/octet-stream", "", []byte("\x89PNG\r\n\x1a\n\x00\x00")},
		{"xml fault envelope", "application/xml", "", []byte("<response><error>bad request</error></response>")},
		{"soap without a prolog", "", "", []byte("<Envelope><Body><Fault>nope</Fault></Body></Envelope>")},
		{"html fragment", "", "", []byte(`<div class="error">Service temporarily unavailable</div>`)},
		{"bom before the doctype", "", "", []byte("\ufeff<!doctype html><html><body>hi</body></html>")},
		{"comment before the doctype", "", "", []byte("<!-- built by vite --><!doctype html><html></html>")},
		{"text/html", "text/html", "", []byte("Service Unavailable")},
		{"text/csv", "text/csv", "", []byte("id,name\n1,alice\n")},
		{"brotli-encoded", "text/plain", "br", []byte("\xaaV\xca/-)(-Q\x01\x00")},
		{"deflate-encoded", "", "deflate", []byte("\x78\x9c\x4b\x4c\x4a\x06\x00\x02\x4d\x01\x27")},
		{"invalid utf-8", "text/plain", "", []byte{0xff, 0xfe, 0x41, 0x00, 0x42, 0x00}},
		{"nul bytes", "text/plain", "", []byte("reply\x00with\x00nuls")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.contentType != "" {
					w.Header().Set("content-type", tc.contentType)
				}
				if tc.encoding != "" {
					w.Header().Set("content-encoding", tc.encoding)
				}
				_, _ = w.Write(tc.body)
			}))
			defer srv.Close()

			resp, err := NewHTTP(srv.URL).Send(context.Background(), Request{Payload: "attack"})
			if err == nil {
				t.Errorf("scored as a model reply: %q", resp.Text)
			}
		})
	}
}

// The gate must not reject a genuine plain-text reply — that would turn working
// scans into a wall of inconclusive.
func TestPlainTextRepliesStillScore(t *testing.T) {
	cases := []struct{ name, contentType, body string }{
		{"text/plain", "text/plain", "I can't help with that request."},
		{"text/plain with charset", "text/plain; charset=utf-8", "I can't help with that request."},
		{"no content type", "", "I can't help with that request."},
		{"markdown", "text/markdown", "**No.** I won't do that."},
		{"unicode prose", "text/plain", "Je ne peux pas vous aider — désolé. 申し訳ありません。"},
		{"reply mentioning a tag", "text/plain", "Use the <div> element for that."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.contentType != "" {
					w.Header().Set("content-type", tc.contentType)
				}
				fmt.Fprint(w, tc.body)
			}))
			defer srv.Close()

			resp, err := NewHTTP(srv.URL).Send(context.Background(), Request{Payload: "attack"})
			if err != nil {
				t.Fatalf("a genuine plain-text reply was rejected: %v", err)
			}
			if resp.Text != tc.body {
				t.Errorf("text = %q, want %q", resp.Text, tc.body)
			}
		})
	}
}
