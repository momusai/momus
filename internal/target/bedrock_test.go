package target

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	brtypes "github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
	"github.com/aws/smithy-go"
)

// stubConverse stands in for the Bedrock client so these tests need no AWS
// account, no credentials, and no network.
type stubConverse struct {
	out *bedrockruntime.ConverseOutput
	err error
	got *bedrockruntime.ConverseInput
}

func (s *stubConverse) Converse(_ context.Context, in *bedrockruntime.ConverseInput, _ ...func(*bedrockruntime.Options)) (*bedrockruntime.ConverseOutput, error) {
	s.got = in
	return s.out, s.err
}

func textOutput(parts ...string) *bedrockruntime.ConverseOutput {
	blocks := make([]brtypes.ContentBlock, 0, len(parts))
	for _, p := range parts {
		blocks = append(blocks, &brtypes.ContentBlockMemberText{Value: p})
	}
	return &bedrockruntime.ConverseOutput{
		StopReason: brtypes.StopReasonEndTurn,
		Output: &brtypes.ConverseOutputMemberMessage{
			Value: brtypes.Message{Role: brtypes.ConversationRoleAssistant, Content: blocks},
		},
	}
}

func TestBedrockURLParsing(t *testing.T) {
	cases := []struct {
		url, wantRegion, wantModel string
	}{
		{
			"https://bedrock-runtime.us-east-1.amazonaws.com/model/anthropic.claude-3-5-sonnet-20240620-v1:0/converse",
			"us-east-1", "anthropic.claude-3-5-sonnet-20240620-v1:0",
		},
		{
			// The colon is often percent-encoded by whatever produced the URL.
			"https://bedrock-runtime.eu-west-2.amazonaws.com/model/anthropic.claude-3-haiku-20240307-v1%3A0/converse",
			"eu-west-2", "anthropic.claude-3-haiku-20240307-v1:0",
		},
		{
			"https://bedrock-runtime.ap-southeast-2.amazonaws.com/model/meta.llama3-70b-instruct-v1:0/invoke",
			"ap-southeast-2", "meta.llama3-70b-instruct-v1:0",
		},
		{
			// No trailing verb at all.
			"https://bedrock-runtime.us-west-2.amazonaws.com/model/amazon.titan-text-express-v1",
			"us-west-2", "amazon.titan-text-express-v1",
		},
		{
			"https://bedrock-runtime-fips.us-gov-west-1.amazonaws.com/model/cohere.command-r-v1:0/converse",
			"us-gov-west-1", "cohere.command-r-v1:0",
		},
	}
	for _, tc := range cases {
		t.Run(tc.wantModel, func(t *testing.T) {
			region, model := parseBedrockURL(tc.url)
			if region != tc.wantRegion {
				t.Errorf("region = %q, want %q", region, tc.wantRegion)
			}
			if model != tc.wantModel {
				t.Errorf("model = %q, want %q", model, tc.wantModel)
			}
		})
	}
}

// A bedrock-runtime URL must route to the Bedrock adapter. It contains none of
// the other adapters' markers, so without an explicit case it would fall
// through to the generic HTTP adapter and POST an unsigned request.
func TestBedrockRouting(t *testing.T) {
	tgt, err := Build("https://bedrock-runtime.us-east-1.amazonaws.com/model/anthropic.claude-3-haiku-20240307-v1:0/converse")
	if err != nil {
		t.Fatal(err)
	}
	if tgt.Name() != "bedrock" {
		t.Fatalf("routed to %q, want the bedrock adapter", tgt.Name())
	}
	if !isBedrockHost("https://bedrock-runtime.us-east-1.amazonaws.com/x") {
		t.Error("isBedrockHost missed a bedrock-runtime host")
	}
	// Must not capture unrelated AWS hosts.
	for _, u := range []string{
		"https://bedrock.us-east-1.amazonaws.com/foundation-models",
		"https://example.com/bedrock-runtime/chat",
	} {
		if isBedrockHost(u) {
			t.Errorf("isBedrockHost wrongly claimed %q", u)
		}
	}
}

func TestBedrockHappyPath(t *testing.T) {
	stub := &stubConverse{out: textOutput("sure, ", "here it is")}
	tgt := &BedrockTarget{Client: stub, ModelID: "anthropic.claude-3-haiku-20240307-v1:0", Region: "us-east-1"}

	resp, err := tgt.Send(context.Background(), Request{Payload: "attack"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Text != "sure, here it is" {
		t.Errorf("text = %q, want the concatenated blocks", resp.Text)
	}
	if stub.got == nil || len(stub.got.Messages) != 1 {
		t.Fatal("the payload was not sent as a single user message")
	}
	block, ok := stub.got.Messages[0].Content[0].(*brtypes.ContentBlockMemberText)
	if !ok || block.Value != "attack" {
		t.Error("the attack payload did not reach the request unchanged")
	}
	if stub.got.Messages[0].Role != brtypes.ConversationRoleUser {
		t.Error("the payload must be sent with the user role")
	}
}

// Contract (B): anything that leaves us without reply text must be an error, not
// an empty string that every detector misses and the scanner calls "safe".
func TestBedrockUnscoreableRepliesError(t *testing.T) {
	cases := map[string]*bedrockruntime.ConverseOutput{
		"no text blocks": {
			StopReason: brtypes.StopReasonGuardrailIntervened,
			Output: &brtypes.ConverseOutputMemberMessage{
				Value: brtypes.Message{Role: brtypes.ConversationRoleAssistant},
			},
		},
		"whitespace only": textOutput("   \n\t "),
		"tool use only": {
			StopReason: brtypes.StopReasonToolUse,
			Output: &brtypes.ConverseOutputMemberMessage{
				Value: brtypes.Message{
					Role:    brtypes.ConversationRoleAssistant,
					Content: []brtypes.ContentBlock{&brtypes.ContentBlockMemberToolUse{}},
				},
			},
		},
		"no message in the union": {StopReason: brtypes.StopReasonMaxTokens},
	}
	for name, out := range cases {
		t.Run(name, func(t *testing.T) {
			tgt := &BedrockTarget{Client: &stubConverse{out: out}, ModelID: "m", Region: "us-east-1"}
			resp, err := tgt.Send(context.Background(), Request{Payload: "attack"})
			if err == nil {
				t.Fatalf("scored an unscoreable reply as %q instead of erroring", resp.Text)
			}
		})
	}
}

func TestBedrockRequiresModelID(t *testing.T) {
	tgt := &BedrockTarget{Client: &stubConverse{out: textOutput("hi")}}
	if _, err := tgt.Send(context.Background(), Request{Payload: "attack"}); err == nil {
		t.Error("a target with no model id must error rather than call Bedrock")
	}
}

// An auth or access failure must be reported in terms the user can act on —
// mistaking a 403 for a well-behaved model is the whole failure mode here.
func TestBedrockErrorsAreActionable(t *testing.T) {
	cases := map[string]string{
		"AccessDeniedException":       "access denied",
		"ResourceNotFoundException":   "no such model",
		"ThrottlingException":         "throttled",
		"ValidationException":         "rejected the request",
		"SomethingElseHappenedLaters": "SomethingElseHappenedLaters",
	}
	for code, want := range cases {
		t.Run(code, func(t *testing.T) {
			stub := &stubConverse{err: &smithy.GenericAPIError{Code: code, Message: "detail from aws"}}
			tgt := &BedrockTarget{Client: stub, ModelID: "m", Region: "us-east-1"}
			_, err := tgt.Send(context.Background(), Request{Payload: "attack"})
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not mention %q", err, want)
			}
			if !strings.Contains(err.Error(), "detail from aws") {
				t.Errorf("the provider's own message was dropped: %q", err)
			}
		})
	}

	// A non-API error still has to surface, not be swallowed.
	stub := &stubConverse{err: errors.New("dial tcp: no route to host")}
	tgt := &BedrockTarget{Client: stub, ModelID: "m", Region: "us-east-1"}
	if _, err := tgt.Send(context.Background(), Request{Payload: "attack"}); err == nil ||
		!strings.Contains(err.Error(), "no route to host") {
		t.Errorf("transport error not surfaced: %v", err)
	}
}
