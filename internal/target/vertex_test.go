package target

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const vertexURL = "https://us-central1-aiplatform.googleapis.com/v1/projects/p/locations/us-central1/" +
	"publishers/google/models/gemini-1.5-pro:generateContent"

// Vertex and public Gemini share the ":generateContent" marker, so without an
// explicit case Vertex would route to the API-key path and 401 on every attack.
func TestVertexRoutesAheadOfGemini(t *testing.T) {
	tgt, err := Build(vertexURL)
	if err != nil {
		t.Fatal(err)
	}
	if tgt.Name() != "vertex" {
		t.Fatalf("routed to %q, want vertex", tgt.Name())
	}

	gem, err := Build("https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent")
	if err != nil {
		t.Fatal(err)
	}
	if gem.Name() != "gemini" {
		t.Errorf("public Gemini routed to %q, want gemini", gem.Name())
	}
}

func TestIsVertexHost(t *testing.T) {
	yes := []string{
		"https://us-central1-aiplatform.googleapis.com/v1/x",
		"https://europe-west4-aiplatform.googleapis.com/v1/x",
		"https://aiplatform.googleapis.com/v1/x",
	}
	no := []string{
		"https://generativelanguage.googleapis.com/v1/x",
		"https://storage.googleapis.com/x",
		// Must not be fooled by a lookalike host an attacker could register.
		"https://us-central1-aiplatform.googleapis.com.evil.tld/v1/x",
		"https://notaiplatform.googleapis.com/v1/x",
	}
	for _, u := range yes {
		if !isVertexHost(u) {
			t.Errorf("isVertexHost missed %q", u)
		}
	}
	for _, u := range no {
		if isVertexHost(u) {
			t.Errorf("isVertexHost wrongly claimed %q", u)
		}
	}
}

// The Cloud access token must go out as a bearer, and must never be sent to a
// host that is not Vertex.
func TestVertexAuthHeaderAndKeyIsolation(t *testing.T) {
	t.Setenv("GOOGLE_ACCESS_TOKEN", "ya29.test-token")
	t.Setenv("MOMUS_TARGET_API_KEY", "")

	var gotAuth, gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("authorization")
		gotKey = r.Header.Get("x-goog-api-key")
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"candidates": []any{map[string]any{
				"content": map[string]any{"parts": []any{map[string]any{"text": "I can't help with that."}}},
			}},
		})
	}))
	defer srv.Close()

	// A real Vertex host resolves the token...
	if tok := vertexAccessToken(vertexURL); tok != "ya29.test-token" {
		t.Errorf("token for a Vertex host = %q, want the env token", tok)
	}
	// ...but an arbitrary scan target must not receive it.
	if tok := vertexAccessToken("https://scanme.example.com/v1/models/x:generateContent"); tok != "" {
		t.Errorf("Google access token leaked to a non-Vertex host: %q", tok)
	}

	// Sending with a bearer set must use Authorization, not the API-key header.
	tgt := &GeminiTarget{URL: srv.URL, Bearer: "ya29.test-token", Client: newHTTPClient(), adapter: "vertex"}
	resp, err := tgt.Send(context.Background(), Request{Payload: "attack"})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if gotAuth != "Bearer ya29.test-token" {
		t.Errorf("authorization = %q, want a bearer token", gotAuth)
	}
	if gotKey != "" {
		t.Errorf("x-goog-api-key was also sent (%q); Vertex must use only the bearer", gotKey)
	}
	if resp.Text != "I can't help with that." {
		t.Errorf("text = %q", resp.Text)
	}
}

// Errors must name the service actually being scanned, or a Vertex failure
// reads as a problem with the public Gemini endpoint.
func TestVertexErrorsSayVertex(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"message":"Request had invalid authentication credentials."}}`))
	}))
	defer srv.Close()

	tgt := &GeminiTarget{URL: srv.URL, Bearer: "expired", Client: newHTTPClient(), adapter: "vertex"}
	_, err := tgt.Send(context.Background(), Request{Payload: "attack"})
	if err == nil {
		t.Fatal("a 401 must be an error, never a scoreable reply")
	}
	if got := err.Error(); !strings.Contains(got, "vertex") {
		t.Errorf("error does not name the vertex adapter: %q", got)
	}
}
