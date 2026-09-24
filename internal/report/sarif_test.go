package report

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/momusai/momus/internal/mal"
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

// GitHub's SARIF ingestion rejects the ENTIRE upload when any rule's
// properties.tags repeats an item — "contains duplicate item". Duplicates are
// the normal case for this pack (an attack in the prompt-injection category
// also carries a "prompt-injection" tag, and most carry "owasp-llm-01"
// alongside the OWASPLLM field), so before dedup every upload failed and no
// finding ever reached the Security tab.
func TestSARIFRuleTagsHaveNoDuplicates(t *testing.T) {
	cases := []scanner.Finding{
		{
			// The exact shape that broke it: category and OWASP id repeated in Tags.
			AttackID: "pi-002", Category: "prompt-injection", OWASPLLM: "LLM01",
			Tags:     []string{"prompt-injection", "classic", "LLM01", "owasp-llm-01"},
			Severity: "high", Verdict: scanner.VerdictVulnerable,
		},
		{AttackID: "a", Category: "security", Tags: []string{"security"}, Verdict: scanner.VerdictSafe},
		{AttackID: "b", Tags: []string{"x", "x", "x"}, Verdict: scanner.VerdictSafe},
		{AttackID: "c", Verdict: scanner.VerdictSafe},
	}
	for _, f := range cases {
		tags := ruleTags(f)
		seen := map[string]bool{}
		for _, tg := range tags {
			if seen[tg] {
				t.Errorf("%s: duplicate tag %q in %v — GitHub would reject the whole upload",
					f.AttackID, tg, tags)
			}
			seen[tg] = true
			if tg == "" {
				t.Errorf("%s: empty tag in %v", f.AttackID, tags)
			}
		}
		if len(tags) == 0 || tags[0] != "security" {
			t.Errorf("%s: expected \"security\" first, got %v", f.AttackID, tags)
		}
	}
}

// The pack-wide version: emit SARIF for every attack in packs/core and assert
// no rule has duplicate tags. A new attack whose tags repeat its category would
// otherwise silently break code-scanning upload again.
func TestSARIFFromCorePackIsAcceptable(t *testing.T) {
	attacks, err := mal.LoadPack("../../packs/core")
	if err != nil || len(attacks) == 0 {
		t.Skipf("core pack unavailable: %v", err)
	}
	findings := make([]scanner.Finding, 0, len(attacks))
	for i := range attacks {
		a := &attacks[i]
		findings = append(findings, scanner.Finding{
			AttackID: a.ID, AttackName: a.Name, Category: a.Category,
			Severity: a.Severity, OWASPLLM: a.OWASPLLM, Tags: a.Tags,
			Payload: a.Payload, Verdict: scanner.VerdictVulnerable,
			Reason: "test",
		})
	}

	var buf bytes.Buffer
	if err := WriteSARIF(&buf, Meta{Target: "t", Pack: "packs/core"}, findings); err != nil {
		t.Fatal(err)
	}
	var log struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID         string `json:"id"`
						Properties struct {
							Tags []string `json:"tags"`
						} `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("emitted SARIF is not valid JSON: %v", err)
	}
	if len(log.Runs) != 1 || len(log.Runs[0].Tool.Driver.Rules) == 0 {
		t.Fatal("SARIF has no rules")
	}
	for _, r := range log.Runs[0].Tool.Driver.Rules {
		seen := map[string]bool{}
		for _, tg := range r.Properties.Tags {
			if seen[tg] {
				t.Errorf("rule %s has duplicate tag %q: %v", r.ID, tg, r.Properties.Tags)
			}
			seen[tg] = true
		}
	}
	t.Logf("checked %d rules from the core pack", len(log.Runs[0].Tool.Driver.Rules))
}

// GitHub code scanning resolves every SARIF location against the checkout and
// rejects the entire upload when a location carries a URL scheme:
//
//	SARIF URI scheme "http" did not match the checkout URI scheme "file"
//
// Momus used to put the scanned target there, so no finding could ever reach
// the Security tab. Locations must be repo-relative paths.
func TestSARIFLocationsAreRepoRelative(t *testing.T) {
	findings := []scanner.Finding{
		{AttackID: "a", AttackSource: "packs/core/jailbreak/jb-001.yaml", Verdict: scanner.VerdictVulnerable},
		{AttackID: "b", AttackSource: "", Verdict: scanner.VerdictVulnerable},   // embedded/unknown pack
		{AttackID: "c", AttackSource: "  ", Verdict: scanner.VerdictVulnerable}, // blank
		// A Source that somehow arrived as a URL must not be emitted as one.
		{AttackID: "d", AttackSource: "https://example.com/a.yaml", Verdict: scanner.VerdictVulnerable},
	}
	doc := sarifOf(t, findings)
	results := doc["runs"].([]any)[0].(map[string]any)["results"].([]any)
	if len(results) != len(findings) {
		t.Fatalf("got %d results, want %d", len(results), len(findings))
	}
	for i, r := range results {
		loc := r.(map[string]any)["locations"].([]any)[0].(map[string]any)
		uri := loc["physicalLocation"].(map[string]any)["artifactLocation"].(map[string]any)["uri"].(string)
		if uri == "" {
			t.Errorf("result %d has an empty location uri", i)
		}
		if strings.Contains(uri, "://") {
			t.Errorf("result %d location %q carries a URL scheme; GitHub rejects the whole upload", i, uri)
		}
		if strings.HasPrefix(uri, "/") {
			t.Errorf("result %d location %q is absolute; it must be repo-relative", i, uri)
		}
	}
	// The useful case resolves to the attack's own file.
	first := results[0].(map[string]any)["locations"].([]any)[0].(map[string]any)
	if got := first["physicalLocation"].(map[string]any)["artifactLocation"].(map[string]any)["uri"]; got != "packs/core/jailbreak/jb-001.yaml" {
		t.Errorf("uri = %v, want the attack's pack file", got)
	}
}

// Losing the target would make a report useless, so check it survives the move
// off the location field.
func TestSARIFStillRecordsTheTarget(t *testing.T) {
	doc := sarifOf(t, []scanner.Finding{
		{AttackID: "a", AttackSource: "packs/core/x.yaml", Verdict: scanner.VerdictVulnerable},
	})
	props, ok := doc["runs"].([]any)[0].(map[string]any)["properties"].(map[string]any)
	if !ok {
		t.Fatal("run has no properties")
	}
	if props["target"] == nil || props["target"] == "" {
		t.Errorf("the scanned target is not recorded on the run: %v", props)
	}
}

// An inconclusive finding must not be scored as a real vulnerability. GitHub
// colours alerts by the rule's security-severity, so scoring inconclusive
// results on the attack's severity made every "the judge could not decide"
// result appear as a High alert — 78 of them on this repo's own scan against
// 31 genuine ones. Severity describes what a confirmed hit would mean, not what
// was observed.
func TestSARIFDoesNotScoreInconclusiveAsVulnerable(t *testing.T) {
	doc := sarifOf(t, []scanner.Finding{
		{AttackID: "vuln-high", Severity: "high", Verdict: scanner.VerdictVulnerable},
		{AttackID: "incon-high", Severity: "high", Verdict: scanner.VerdictInconclusive},
		{AttackID: "incon-crit", Severity: "critical", Verdict: scanner.VerdictInconclusive},
	})
	rules := doc["runs"].([]any)[0].(map[string]any)["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)
	byID := map[string]map[string]any{}
	for _, r := range rules {
		rm := r.(map[string]any)
		byID[rm["id"].(string)] = rm["properties"].(map[string]any)
	}

	if got := byID["vuln-high"]["security-severity"]; got != "7.5" {
		t.Errorf("a confirmed high finding should still score 7.5, got %v", got)
	}
	for _, id := range []string{"incon-high", "incon-crit"} {
		if got, present := byID[id]["security-severity"]; present {
			t.Errorf("%s: inconclusive finding scored %v; it must carry no security-severity "+
				"or GitHub ranks it as a real vulnerability", id, got)
		}
	}

	// The results themselves must still be present and levelled as notes —
	// suppressing them entirely would hide that those attacks went untested.
	results := doc["runs"].([]any)[0].(map[string]any)["results"].([]any)
	if len(results) != 3 {
		t.Fatalf("got %d results, want all three reported", len(results))
	}
	for _, r := range results {
		rm := r.(map[string]any)
		if rm["properties"].(map[string]any)["verdict"] == "inconclusive" && rm["level"] != "note" {
			t.Errorf("inconclusive result levelled %v, want note", rm["level"])
		}
	}
}
