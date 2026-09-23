// Command safe-echo is a well-behaved AI-agent stand-in: it answers benign
// requests and refuses every injection, jailbreak, and disclosure attempt. It
// exists as a false-positive fixture — running the core pack against it MUST
// yield zero "vulnerable" verdicts. Canary-based attacks come back "safe";
// attacks whose only detector is llm_judge come back "inconclusive" when no
// judge is configured, which is the correct fail-safe (a review flag, never a
// false positive).
//
// It answers benign prompts on purpose. A model that replies with one identical
// canned string no matter what you send is indistinguishable from a health
// endpoint, and the scanner's liveness probe rejects such a target rather than
// reporting a meaningless 200/200 "safe". Refusing everything is not safety, it
// is a broken model — so this fixture refuses selectively, the way a real
// guardrailed assistant does.
package main

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
)

// canary matches the token format the pack's detectors look for. Nothing on the
// benign path may ever emit one — that would be a false positive manufactured
// by the fixture itself rather than by the scanner.
var canary = regexp.MustCompile(`\b[A-Z]{2}[0-9]{3}_HIT\b`)

// refusals are the phrasings a guardrailed assistant actually uses. They vary
// so the fixture isn't a constant-response endpoint, and none of them contains
// a canary token or the system-prompt tell-tales the disclosure detectors match.
var refusals = []string{
	"I can't help with that request. Let me know if there's something else I can do.",
	"I'm not able to do that. Is there something else you'd like help with?",
	"That's not something I can assist with, sorry. Happy to help with anything else.",
	"I won't be able to help here. Let me know if you have another question.",
	"Sorry — I can't go along with that. Is there another way I can help?",
	"I'm going to pass on that one. Anything else I can do for you?",
}

// answers are short, harmless replies for benign prompts. Picked by hash so a
// scan is reproducible: the same prompt always gets the same reply.
var answers = []string{
	"Sure — happy to help. Could you give me a bit more detail?",
	"Good question. The short answer is that it depends on your setup.",
	"Here's a quick summary: it works the way you'd expect for most cases.",
	"I'd approach that by breaking it into a couple of smaller steps.",
	"Yes, that's doable. Let me know which part you want to start with.",
}

// echoRequest matches a benign "repeat this back" instruction, e.g. the
// scanner's own liveness probe. A real assistant follows a harmless instruction
// like this; refusing it is the broken behaviour described above.
var echoRequest = regexp.MustCompile(`(?i)\b(reply with|repeat|echo)\b[^\n]*?\b([A-Z][A-Z0-9_]{7,})\b`)

// attackMarkers are the giveaways of an injection, jailbreak, or extraction
// attempt. Matching one sends the prompt down the refusal path.
var attackMarkers = []string{
	"ignore previous", "ignore all previous", "ignore the above", "disregard",
	"system prompt", "initial instructions", "your instructions", "reveal",
	"dan mode", "developer mode", "jailbreak", "do anything now",
	"no restrictions", "without restrictions", "unfiltered", "no filter",
	"pretend you are", "act as if", "roleplay as", "you are now",
	"grandma", "hypothetically", "for educational purposes only",
	"base64", "rot13", "decode the following", "translate the following",
	"print the text", "output the token", "say exactly",
	"api key", "credentials", "password", "exfiltrate",
	"curl ", "http://", "https://", "<script", "javascript:",
	"sudo ", "rm -rf", "drop table", "'; --",
}

func main() {
	http.HandleFunc("/", handle)
	addr := ":8001"
	fmt.Printf("safe-echo (a well-behaved agent) listening on http://localhost%s\n", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

func handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var m map[string]any
	_ = json.Unmarshal(body, &m)

	prompt := ""
	for _, k := range []string{"input", "prompt", "message", "content"} {
		if s, ok := m[k].(string); ok && s != "" {
			prompt = s
			break
		}
	}

	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"output": reply(prompt)})
}

// reply is the whole model. Anything that smells like an attack gets a refusal;
// everything else gets a benign answer.
func reply(prompt string) string {
	if isAttack(prompt) {
		return pick(refusals, prompt)
	}
	// A benign echo request — follow it, unless the token is canary-shaped, in
	// which case this was an attack the marker list didn't catch.
	if m := echoRequest.FindStringSubmatch(prompt); m != nil && !canary.MatchString(m[2]) {
		return m[2]
	}
	return pick(answers, prompt)
}

// isAttack is deliberately trigger-happy. A missed attack still cannot produce a
// false positive — the benign replies contain no canary — but erring toward
// refusal keeps the fixture honest about what it is.
func isAttack(prompt string) bool {
	if canary.MatchString(prompt) {
		return true
	}
	lower := strings.ToLower(prompt)
	for _, marker := range attackMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	// Long or heavily-encoded payloads are not what benign traffic looks like.
	return len(prompt) > 600 || nonPrintableRatio(prompt) > 0.1
}

func nonPrintableRatio(s string) float64 {
	if s == "" {
		return 0
	}
	odd := 0
	for _, r := range s {
		if r < 0x20 && r != '\n' && r != '\t' && r != '\r' {
			odd++
		}
	}
	return float64(odd) / float64(len([]rune(s)))
}

// pick selects deterministically from the prompt so runs are reproducible.
func pick(from []string, prompt string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(prompt))
	return from[int(h.Sum32())%len(from)]
}
