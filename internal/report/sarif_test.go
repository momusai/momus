package report

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/momusai/momus/internal/scanner"
	"github.com/momusai/momus/internal/target"
)

func sarifOf(t *testing.T, findings []scanner.Finding) map[string]any {
	t.Helper()
	var sb strings.Builder
	meta := Meta{Target: "https://api.example/chat", Pack: "packs/core", JudgeName: "none", Version: "1.2.3"}
	if err := WriteSARIF(&sb, meta, findings); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(sb.String()), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	return doc
}

func TestSARIFStructure(t *testing.T) {
	doc := sarifOf(t, []scanner.Finding{
		{AttackID: "pi-001", AttackName: "Ignore previous", Category: "prompt-injection",
			Severity: "high", OWASPLLM: "LLM01", Verdict: scanner.VerdictVulnerable, Reason: "detect rule matched",
			References: []string{"https://owasp.org/x"}},
		{AttackID: "le-002", AttackName: "Leak", Category: "data-exfil", Severity: "medium",
			Verdict: scanner.VerdictInconclusive, Reason: "undecided"},
		{AttackID: "jb-001", AttackName: "DAN", Category: "jailbreak", Severity: "high",
			Verdict: scanner.VerdictSafe, Reason: "did not match"},
	})

	if doc["version"] != "2.1.0" {
		t.Errorf("version = %v, want 2.1.0", doc["version"])
	}
	runs := doc["runs"].([]any)
	run := runs[0].(map[string]any)
	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	if driver["name"] != "Momus" {
		t.Errorf("driver.name = %v, want Momus", driver["name"])
	}
	results := run["results"].([]any)
	// Safe findings are excluded: 1 vulnerable + 1 inconclusive = 2 results.
	if len(results) != 2 {
		t.Fatalf("results = %d, want 2 (safe excluded)", len(results))
	}
	// Rules are only for included findings.
	rules := driver["rules"].([]any)
	if len(rules) != 2 {
		t.Fatalf("rules = %d, want 2", len(rules))
	}

	// Level mapping: high vulnerable -> error; inconclusive -> note.
	byRule := map[string]map[string]any{}
	for _, r := range results {
		m := r.(map[string]any)
		byRule[m["ruleId"].(string)] = m
	}
	if byRule["pi-001"]["level"] != "error" {
		t.Errorf("pi-001 level = %v, want error", byRule["pi-001"]["level"])
	}
	if byRule["le-002"]["level"] != "note" {
		t.Errorf("le-002 level = %v, want note", byRule["le-002"]["level"])
	}
	// ruleIndex points at a real rule.
	idx := int(byRule["pi-001"]["ruleIndex"].(float64))
	if idx < 0 || idx >= len(rules) {
		t.Fatalf("ruleIndex %d out of range", idx)
	}
	if rules[idx].(map[string]any)["id"] != "pi-001" {
		t.Errorf("ruleIndex mismatch: rule[%d].id = %v", idx, rules[idx].(map[string]any)["id"])
	}
}

func TestSARIFSeverityAndTags(t *testing.T) {
	doc := sarifOf(t, []scanner.Finding{
		{AttackID: "c1", Severity: "critical", Category: "excessive-agency", OWASPLLM: "LLM08",
			Tags: []string{"tool-abuse"}, Verdict: scanner.VerdictVulnerable, Reason: "x"},
	})
	rule := doc["runs"].([]any)[0].(map[string]any)["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)[0].(map[string]any)
	props := rule["properties"].(map[string]any)
	if props["security-severity"] != "9.5" {
		t.Errorf("critical security-severity = %v, want 9.5", props["security-severity"])
	}
	tagsAny := props["tags"].([]any)
	var tags []string
	for _, tg := range tagsAny {
		tags = append(tags, tg.(string))
	}
	for _, want := range []string{"security", "excessive-agency", "LLM08", "tool-abuse"} {
		found := false
		for _, g := range tags {
			if g == want {
				found = true
			}
		}
		if !found {
			t.Errorf("tags missing %q (got %v)", want, tags)
		}
	}
}

// TestSARIFEmptyIsValid: a clean scan (all safe) still produces valid SARIF with
// zero results — GitHub upload requires a well-formed file even with no findings.
func TestSARIFEmptyIsValid(t *testing.T) {
	doc := sarifOf(t, []scanner.Finding{
		{AttackID: "s1", Verdict: scanner.VerdictSafe, Reason: "ok"},
	})
	results := doc["runs"].([]any)[0].(map[string]any)["results"].([]any)
	if len(results) != 0 {
		t.Fatalf("all-safe scan should have 0 results, got %d", len(results))
	}
}

// TestSARIFHandlesMessyContent: control characters / quotes in reason must not
// break the JSON (encoding/json escapes them).
func TestSARIFHandlesMessyContent(t *testing.T) {
	doc := sarifOf(t, []scanner.Finding{
		{AttackID: "x", Severity: "high", Verdict: scanner.VerdictVulnerable,
			Reason: "weird \"quotes\" and \n newlines and \x00 nul"},
	})
	// If we got here, json.Unmarshal succeeded in sarifOf -> valid JSON.
	if doc["version"] != "2.1.0" {
		t.Error("doc malformed")
	}
}

// TestSARIFDuplicateIDsDistinct is a regression test for the review finding:
// two findings sharing an attack id (different payloads) must produce results
// with DISTINCT fingerprints, so code-scanning consumers don't collapse them.
func TestSARIFDuplicateIDsDistinct(t *testing.T) {
	doc := sarifOf(t, []scanner.Finding{
		{AttackID: "pi-001", Severity: "high", Verdict: scanner.VerdictVulnerable, Reason: "a", Payload: "variant A"},
		{AttackID: "pi-001", Severity: "high", Verdict: scanner.VerdictVulnerable, Reason: "b", Payload: "variant B"},
	})
	results := doc["runs"].([]any)[0].(map[string]any)["results"].([]any)
	if len(results) != 2 {
		t.Fatalf("want 2 results, got %d", len(results))
	}
	fp := func(i int) string {
		return results[i].(map[string]any)["partialFingerprints"].(map[string]any)["momusAttackTarget"].(string)
	}
	if fp(0) == fp(1) {
		t.Fatalf("duplicate-id findings share a fingerprint %q; they would collapse into one alert", fp(0))
	}
}

func TestWriteSARIFFileValid(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/out.sarif"
	f := []scanner.Finding{{AttackID: "x", Severity: "high", Verdict: scanner.VerdictVulnerable, Reason: "y",
		Response: &target.Response{Text: "z"}}}
	if err := WriteSARIFFile(path, Meta{Target: "http://t", Version: "v"}, f); err != nil {
		t.Fatalf("WriteSARIFFile: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("written file not valid JSON: %v", err)
	}
}
