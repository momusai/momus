package target

import (
	neturl "net/url"
	"os"
	"strings"
)

// Google Vertex AI serves the same generateContent API as the public Gemini
// endpoint — identical request body, identical response shape. Only the auth
// differs: Vertex takes an OAuth2 bearer token scoped to a Google Cloud project,
// where the public endpoint takes an API key header.
//
// So there is no separate Vertex adapter. Duplicating the request builder and
// the candidates/parts parser would mean two places to fix every time a reply
// shape surprises us, and this package's whole discipline rests on there being
// exactly one answer to "what counts as a reply". NewVertex returns a
// GeminiTarget wired for bearer auth and labelled "vertex" so reports and error
// messages name the right service.
//
// Credentials: Momus does not implement Application Default Credentials. That
// would pull in an OAuth2 stack whose current release requires a newer Go
// toolchain than the rest of this project asks of contributors, for one adapter.
// Instead the token is supplied explicitly, which is a single command:
//
//	export GOOGLE_ACCESS_TOKEN=$(gcloud auth print-access-token)
//
// Such tokens are short-lived (about an hour), which is ample for a scan but
// worth knowing if one expires mid-run — that surfaces as HTTP 401, reported
// inconclusive, never as "safe".
func NewVertex(url string) *GeminiTarget {
	return &GeminiTarget{
		URL:     url,
		Bearer:  vertexAccessToken(url),
		Client:  newHTTPClient(),
		adapter: "vertex",
	}
}

// vertexAccessToken resolves the bearer token for a Vertex endpoint, and only
// for a genuine Google host. Every other adapter in this package scopes its
// credential to the provider's real hostname; a scan URL is attacker-adjacent
// input, so pointing Momus at an arbitrary host must never hand it your Google
// Cloud token.
func vertexAccessToken(rawURL string) string {
	if !isVertexHost(rawURL) {
		// An explicit per-target key is still honoured, because the user set it
		// for this specific target on purpose.
		return os.Getenv("MOMUS_TARGET_API_KEY")
	}
	return firstNonEmptyEnv(
		"MOMUS_TARGET_API_KEY",
		"GOOGLE_ACCESS_TOKEN",
		"VERTEX_ACCESS_TOKEN",
		"GOOGLE_OAUTH_ACCESS_TOKEN",
	)
}

// isVertexHost reports whether the URL is a Vertex AI aiplatform endpoint.
// Vertex hosts are regional — us-central1-aiplatform.googleapis.com — with a
// global aiplatform.googleapis.com as well.
func isVertexHost(rawURL string) bool {
	u, err := neturl.Parse(rawURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	return host == "aiplatform.googleapis.com" || strings.HasSuffix(host, "-aiplatform.googleapis.com")
}
