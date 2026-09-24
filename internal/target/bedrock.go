package target

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	neturl "net/url"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	brtypes "github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
	"github.com/aws/smithy-go"
)

// BedrockTarget speaks Amazon Bedrock's Converse API.
//
// Converse is used rather than InvokeModel deliberately: InvokeModel takes a
// different request and response shape for every model family (Anthropic, Titan,
// Llama, Mistral, Cohere each differ), so an adapter built on it would need a
// per-family parser and would silently mis-read any family it did not know.
// Converse normalises all of them behind one schema, which means one code path
// and no guessing at what a reply looks like — and guessing is exactly how a
// scanner ends up scoring a non-reply as "safe".
//
// Auth goes through the standard AWS credential chain (environment, shared
// profile, SSO, IMDS, IRSA). That matters here: production Bedrock is reached
// with an IAM role far more often than with a static key pair, so an env-only
// implementation would serve almost nobody.
type BedrockTarget struct {
	Client  bedrockConverser
	ModelID string
	Region  string
}

// bedrockConverser is the slice of the Bedrock client this adapter uses, so
// tests can substitute a stub without standing up AWS.
type bedrockConverser interface {
	Converse(ctx context.Context, in *bedrockruntime.ConverseInput, optFns ...func(*bedrockruntime.Options)) (*bedrockruntime.ConverseOutput, error)
}

// NewBedrock builds a BedrockTarget from a bedrock-runtime URL of the form
//
//	https://bedrock-runtime.<region>.amazonaws.com/model/<model-id>/converse
//
// The region and model id are read from the URL, so no extra env var is needed.
// Credentials are resolved lazily on the first Send: constructing a target must
// not fail merely because this machine has no AWS configuration, since `momus
// scan --dry-run` and `--help` have to work anywhere.
func NewBedrock(url string) *BedrockTarget {
	region, model := parseBedrockURL(url)
	return &BedrockTarget{ModelID: model, Region: region}
}

// Name identifies this adapter.
func (t *BedrockTarget) Name() string { return "bedrock" }

// Send posts one user turn and returns the assistant's text.
func (t *BedrockTarget) Send(ctx context.Context, req Request) (*Response, error) {
	start := time.Now()

	if t.ModelID == "" {
		return nil, errors.New("bedrock target: no model id in the URL — expected " +
			"https://bedrock-runtime.<region>.amazonaws.com/model/<model-id>/converse")
	}
	client, err := t.converser(ctx)
	if err != nil {
		return nil, err
	}

	out, err := client.Converse(ctx, &bedrockruntime.ConverseInput{
		ModelId: aws.String(t.ModelID),
		Messages: []brtypes.Message{{
			Role:    brtypes.ConversationRoleUser,
			Content: []brtypes.ContentBlock{&brtypes.ContentBlockMemberText{Value: req.Payload}},
		}},
	})
	if err != nil {
		return nil, bedrockError(err)
	}

	// The SDK models the output as a union; anything other than a message means
	// we have no reply to score, which must be an error rather than an empty
	// string scored as "safe".
	msgOut, ok := out.Output.(*brtypes.ConverseOutputMemberMessage)
	if !ok {
		return nil, fmt.Errorf("bedrock target: response carried no assistant message "+
			"(stop reason %q), so there is nothing to score", out.StopReason)
	}

	var text strings.Builder
	for _, block := range msgOut.Value.Content {
		if tb, ok := block.(*brtypes.ContentBlockMemberText); ok {
			text.WriteString(tb.Value)
		}
	}

	// A reply that is only tool-use or reasoning blocks, or that Bedrock's
	// guardrails blanked, has no text to score. Same guard as every other
	// adapter: never let an empty reply read as a clean pass.
	if strings.TrimSpace(text.String()) == "" {
		return nil, fmt.Errorf("bedrock target: the response contained no reply text to score "+
			"(stop reason %q — a guardrail intervention, a tool-use-only turn, or an empty "+
			"completion); model %s", out.StopReason, t.ModelID)
	}

	return &Response{
		Text:      text.String(),
		Raw:       map[string]any{"stop_reason": string(out.StopReason), "model_id": t.ModelID},
		LatencyMs: time.Since(start).Milliseconds(),
		Status:    http.StatusOK,
	}, nil
}

// converser returns the Bedrock client, building it on first use.
func (t *BedrockTarget) converser(ctx context.Context) (bedrockConverser, error) {
	if t.Client != nil {
		return t.Client, nil
	}
	opts := []func(*awsconfig.LoadOptions) error{}
	if t.Region != "" {
		opts = append(opts, awsconfig.WithRegion(t.Region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("bedrock target: could not load AWS configuration: %w", err)
	}
	if cfg.Region == "" {
		return nil, errors.New("bedrock target: no AWS region — put it in the URL " +
			"(bedrock-runtime.<region>.amazonaws.com) or set AWS_REGION")
	}
	t.Client = bedrockruntime.NewFromConfig(cfg)
	return t.Client, nil
}

// bedrockError turns an SDK error into a message that says what to fix. A bare
// SDK error is opaque enough that a user can mistake an auth problem for the
// model behaving well, which is the failure this package exists to prevent.
func bedrockError(err error) error {
	var missing *awsconfig.CredentialRequiresARNError
	if errors.As(err, &missing) {
		return fmt.Errorf("bedrock target: incomplete AWS credentials: %w", err)
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "AccessDeniedException":
			return fmt.Errorf("bedrock target: access denied — the credentials are valid but lack "+
				"bedrock:InvokeModel on this model, or model access is not enabled in this region: %s",
				apiErr.ErrorMessage())
		case "ResourceNotFoundException":
			return fmt.Errorf("bedrock target: no such model in this region — check the model id "+
				"and that it is available where you are calling: %s", apiErr.ErrorMessage())
		case "ValidationException":
			return fmt.Errorf("bedrock target: Bedrock rejected the request: %s", apiErr.ErrorMessage())
		case "ThrottlingException":
			return fmt.Errorf("bedrock target: throttled by Bedrock (lower --concurrency): %s",
				apiErr.ErrorMessage())
		}
		return fmt.Errorf("bedrock target: %s: %s", apiErr.ErrorCode(), apiErr.ErrorMessage())
	}
	return fmt.Errorf("bedrock target: %w", err)
}

// parseBedrockURL pulls the region and model id out of a bedrock-runtime URL.
// Both may come back empty; Send reports that as an error rather than guessing.
func parseBedrockURL(rawURL string) (region, model string) {
	u, err := neturl.Parse(rawURL)
	if err != nil {
		return "", ""
	}
	host := strings.ToLower(u.Hostname())
	// bedrock-runtime.<region>.amazonaws.com (also -fips. and .api.aws variants)
	if parts := strings.Split(host, "."); len(parts) >= 3 && strings.HasPrefix(parts[0], "bedrock-runtime") {
		region = parts[1]
	}
	if region == "" {
		region = os.Getenv("AWS_REGION")
	}
	// /model/<model-id>/converse — the id itself contains dots and a colon
	// (e.g. anthropic.claude-3-5-sonnet-20240620-v1:0), so take the whole
	// segment rather than splitting on those.
	path := u.EscapedPath()
	if unescaped, err := neturl.PathUnescape(path); err == nil {
		path = unescaped
	}
	const marker = "/model/"
	if i := strings.Index(path, marker); i >= 0 {
		rest := path[i+len(marker):]
		rest = strings.TrimSuffix(rest, "/converse")
		rest = strings.TrimSuffix(rest, "/invoke")
		model = strings.Trim(rest, "/")
	}
	return region, model
}

// isBedrockHost reports whether the URL points at Amazon Bedrock's runtime API.
func isBedrockHost(rawURL string) bool {
	u, err := neturl.Parse(rawURL)
	if err != nil {
		return false
	}
	return strings.HasPrefix(strings.ToLower(u.Hostname()), "bedrock-runtime.")
}
