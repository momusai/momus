package judge

import (
	"fmt"
	"log/slog"
	"net/http"
	neturl "net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the resolved judge configuration (env-derived, overridable by CLI).
type Config struct {
	Provider    string        // "openai" | "anthropic" | "fake" | "" (auto)
	BaseURL     string        // judge endpoint
	Model       string        // default model / resolves "judge/default"
	APIKey      string        // optional (local Ollama/vLLM need none)
	Threshold   float64       // min confidence; default 0.7
	Timeout     time.Duration // per-call; default 30s
	Votes       int           // self-consistency samples; default 1 (off)
	TargetURL   string        // the target under test, to reject self-grading
	TargetModel string        // the model under test, so one endpoint serving many
	//                         models is not mistaken for self-grading
}

// ConfigFromEnv reads MOMUS_JUDGE_* (with OPENAI/ANTHROPIC key fallbacks).
func ConfigFromEnv() Config {
	return Config{
		Provider: strings.ToLower(os.Getenv("MOMUS_JUDGE_PROVIDER")),
		BaseURL:  os.Getenv("MOMUS_JUDGE_URL"),
		Model:    os.Getenv("MOMUS_JUDGE_MODEL"),
		// Only the EXPLICIT judge key is resolved here. A provider key depends
		// on which provider we end up calling, and the CLI can still override
		// --judge-url/--judge-provider after this returns, so that resolution
		// happens in New() once the endpoint is final.
		APIKey:    os.Getenv("MOMUS_JUDGE_API_KEY"),
		Threshold: parseFloat(os.Getenv("MOMUS_JUDGE_THRESHOLD"), 0.7),
		Timeout:   parseTimeout(os.Getenv("MOMUS_JUDGE_TIMEOUT"), 30*time.Second),
		Votes:     int(parseFloat(os.Getenv("MOMUS_JUDGE_VOTES"), 1)),
	}
}

// FromEnv resolves a Judge from the environment for a given target URL. It never
// returns nil; it returns an error only on actively-invalid config.
func FromEnv(targetURL string) (Judge, error) {
	c := ConfigFromEnv()
	c.TargetURL = targetURL
	return New(c)
}

// New builds a Judge from an explicit Config. It never returns nil and errors
// only when config is actively invalid: a non-http judge URL, or a judge URL
// equal to the target under test (which would let the model grade itself). A
// missing API key is not an error — it degrades to NoOp with a warning.
func New(c Config) (Judge, error) {
	if c.BaseURL != "" {
		if !strings.HasPrefix(c.BaseURL, "http://") && !strings.HasPrefix(c.BaseURL, "https://") {
			return nil, fmt.Errorf("invalid MOMUS_JUDGE_URL %q (want http:// or https://)", c.BaseURL)
		}
		// Only reject when the same MODEL is also implied. One endpoint serving
		// several models is the normal local setup, and the resolved-endpoint
		// check further down catches the rest once the model is known.
		if c.TargetURL != "" && c.BaseURL == c.TargetURL &&
			(c.Model == "" || c.TargetModel == "" || strings.EqualFold(c.Model, c.TargetModel)) {
			return nil, fmt.Errorf("the judge would be the same model at the same endpoint as the "+
				"target under test (%q), so it would grade its own answers; set MOMUS_JUDGE_MODEL "+
				"to a different model, or MOMUS_JUDGE_URL to a different endpoint", c.TargetURL)
		}
	}
	if c.APIKey == "" {
		c.APIKey = providerAPIKey(c.Provider, c.BaseURL)
	}
	hc := &http.Client{Timeout: orDurationDefault(c.Timeout, 30*time.Second)}

	base, err := selectProvider(c, hc)
	if err != nil {
		return nil, err
	}
	// Nothing to cache or vote on for the no-op degradation path.
	if _, ok := base.(NoOp); ok {
		return base, nil
	}
	// Re-check self-grading against the RESOLVED endpoint. The check above only
	// sees an explicit MOMUS_JUDGE_URL; when the judge is AUTO-selected from
	// OPENAI_API_KEY/ANTHROPIC_API_KEY it defaults to that provider's endpoint,
	// which is exactly the URL being scanned when the target IS that provider.
	// The model must never grade its own answers.
	//
	// How we react depends on whether the user asked for this judge. Scanning
	// OpenAI with OPENAI_API_KEY set is the documented happy path, so a collision
	// there must NOT hard-fail the scan — we just don't use a judge. Only an
	// explicit judge URL/provider colliding with the target is an error the user
	// should fix.
	//
	// Matching URLs alone is not self-grading. Ollama, vLLM and OpenRouter each
	// serve many models from one endpoint, so judging llama3.2 with qwen2.5 is a
	// genuinely different grader at the same address — and a local judge is the
	// whole answer to "most attacks are inconclusive without one". Only the same
	// model at the same endpoint is the model grading itself.
	if c.TargetURL != "" && resolvedJudgeURL(base) == c.TargetURL && sameModel(c, base) {
		if c.BaseURL != "" || c.Provider != "" {
			return nil, fmt.Errorf("the judge is the same model at the same endpoint as the target "+
				"under test (%s at %s), so it would be grading its own answers; point "+
				"MOMUS_JUDGE_MODEL at a different model, or MOMUS_JUDGE_URL elsewhere",
				orDefault(c.TargetModel, "the same model"), c.TargetURL)
		}
		slog.Warn("judge: the auto-selected judge is the target itself; scanning without a judge " +
			"(set MOMUS_JUDGE_URL or MOMUS_JUDGE_MODEL to enable semantic checks)")
		return NoOp{}, nil
	}
	// Decorate: cache always; voting only when explicitly requested.
	inner := base
	if c.Votes > 1 {
		inner = NewVotingJudge(base, c.Votes)
	}
	return NewCachingJudge(inner), nil
}

// sameModel reports whether the judge would run the very model under test.
// An unknown model on either side counts as "same", because guessing they
// differ is the answer that lets a model grade itself.
func sameModel(c Config, j Judge) bool {
	judgeModel := resolvedJudgeModel(j)
	if judgeModel == "" || c.TargetModel == "" {
		return true
	}
	return strings.EqualFold(judgeModel, c.TargetModel)
}

// resolvedJudgeModel reports the model a concrete judge will actually use.
func resolvedJudgeModel(j Judge) string {
	switch t := j.(type) {
	case *OpenAIJudge:
		return t.Model
	case *AnthropicJudge:
		return t.Model
	}
	return ""
}

// resolvedJudgeURL reports the endpoint a concrete judge will actually call.
func resolvedJudgeURL(j Judge) string {
	switch t := j.(type) {
	case *OpenAIJudge:
		return t.URL
	case *AnthropicJudge:
		return t.URL
	}
	return ""
}

func selectProvider(c Config, hc *http.Client) (Judge, error) {
	switch {
	case c.Provider == "fake":
		return &FakeJudge{Default: DecisionInconclusive}, nil

	// An explicit --judge-provider must win over key/URL sniffing; otherwise
	// "openai" could silently select the Anthropic judge when only that key is set.
	case c.Provider == "openai":
		if c.APIKey == "" && c.BaseURL == "" {
			slog.Warn("judge: openai selected but no API key or URL; llm_judge nodes will be inconclusive")
			return NoOp{}, nil
		}
		return &OpenAIJudge{
			URL:    orDefault(c.BaseURL, "https://api.openai.com/v1/chat/completions"),
			Model:  orDefault(c.Model, "gpt-4o-mini"),
			APIKey: c.APIKey, Client: hc, Timeout: c.Timeout, Threshold: c.Threshold,
		}, nil

	case c.Provider == "anthropic" || strings.Contains(c.BaseURL, "anthropic"):
		if c.APIKey == "" {
			slog.Warn("judge: anthropic selected but no API key; llm_judge nodes will be inconclusive")
			return NoOp{}, nil
		}
		return &AnthropicJudge{
			URL:    orDefault(c.BaseURL, "https://api.anthropic.com/v1/messages"),
			Model:  orDefault(c.Model, "claude-3-5-haiku-latest"),
			APIKey: c.APIKey, Client: hc, Timeout: c.Timeout, Threshold: c.Threshold,
		}, nil

	case c.BaseURL != "": // openai-compatible: openai, ollama, vllm, groq
		return &OpenAIJudge{
			URL:    c.BaseURL,
			Model:  orDefault(c.Model, "gpt-4o-mini"),
			APIKey: c.APIKey, Client: hc, Timeout: c.Timeout, Threshold: c.Threshold,
		}, nil

	case os.Getenv("MOMUS_JUDGE_API_KEY") != "" || os.Getenv("OPENAI_API_KEY") != "":
		// An explicit judge key (or an OpenAI key) with no URL/provider defaults
		// to the OpenAI endpoint. c.APIKey already resolves MOMUS_JUDGE_API_KEY
		// first, so a configured judge key is honored instead of degrading to NoOp.
		return &OpenAIJudge{
			URL:    "https://api.openai.com/v1/chat/completions",
			Model:  orDefault(c.Model, "gpt-4o-mini"),
			APIKey: c.APIKey, Client: hc, Timeout: c.Timeout, Threshold: c.Threshold,
		}, nil

	case os.Getenv("ANTHROPIC_API_KEY") != "":
		return &AnthropicJudge{
			URL:    "https://api.anthropic.com/v1/messages",
			Model:  orDefault(c.Model, "claude-3-5-haiku-latest"),
			APIKey: os.Getenv("ANTHROPIC_API_KEY"), Client: hc, Timeout: c.Timeout, Threshold: c.Threshold,
		}, nil

	default:
		slog.Info("judge: none configured; llm_judge nodes will resolve inconclusive")
		return NoOp{}, nil
	}
}

// providerAPIKey resolves which provider credential may be sent to the judge
// endpoint. A key is only ever handed to its own provider: the old resolver fell
// back to firstNonEmpty(OPENAI_API_KEY, ANTHROPIC_API_KEY) for the OpenAI host,
// so a user with only an Anthropic key had "Authorization: Bearer sk-ant-..."
// sent to api.openai.com — a secret handed to the wrong company.
//
// MOMUS_JUDGE_API_KEY is handled by the caller and always wins; a third-party or
// self-hosted judge must use it, since no provider key belongs to that host.
func providerAPIKey(provider, judgeURL string) string {
	host := ""
	if judgeURL != "" {
		if u, err := neturl.Parse(judgeURL); err == nil {
			host = strings.ToLower(u.Hostname())
		}
	}
	switch {
	case host == "api.openai.com":
		return os.Getenv("OPENAI_API_KEY")
	case host == "api.anthropic.com":
		return os.Getenv("ANTHROPIC_API_KEY")
	case host != "":
		// Self-hosted or third-party: local servers need no key, and anything
		// else must be given MOMUS_JUDGE_API_KEY explicitly.
		return ""
	// No URL: we will default to the provider's own endpoint.
	case provider == "openai":
		return os.Getenv("OPENAI_API_KEY")
	case provider == "anthropic":
		return os.Getenv("ANTHROPIC_API_KEY")
	default:
		// Nothing specified: auto-select, matching selectProvider's own order.
		return firstNonEmpty(os.Getenv("OPENAI_API_KEY"), os.Getenv("ANTHROPIC_API_KEY"))
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func orDurationDefault(v, def time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	return v
}

func parseFloat(s string, def float64) float64 {
	if s == "" {
		return def
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return def
	}
	return f
}

func parseTimeout(s string, def time.Duration) time.Duration {
	if s == "" {
		return def
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return def
	}
	return d
}
