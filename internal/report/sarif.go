package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/momusai/momus/internal/scanner"
)

// SARIF 2.1.0 output so Momus findings integrate with GitHub code scanning and
// other SARIF viewers. Only problems are emitted as results (vulnerable ->
// error/warning by severity; inconclusive -> note); safe attacks are not.

const sarifSchema = "https://json.schemastore.org/sarif-2.1.0.json"

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool       sarifTool      `json:"tool"`
	Results    []sarifResult  `json:"results"`
	Properties map[string]any `json:"properties,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version"`
	Rules          []sarifRule `json:"rules"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name,omitempty"`
	ShortDescription sarifText      `json:"shortDescription"`
	FullDescription  *sarifText     `json:"fullDescription,omitempty"`
	HelpURI          string         `json:"helpUri,omitempty"`
	Properties       sarifRuleProps `json:"properties"`
}

type sarifRuleProps struct {
	Tags             []string `json:"tags,omitempty"`
	SecuritySeverity string   `json:"security-severity,omitempty"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

// securitySeverity maps a MAL severity to a GitHub 0-10 security-severity score.
func securitySeverity(sev string) string {
	switch sev {
	case "critical":
		return "9.5"
	case "high":
		return "7.5"
	case "medium":
		return "5.0"
	case "low":
		return "3.0"
	default:
		return "1.0"
	}
}

// sarifLevel maps a finding to a SARIF level. Vulnerable findings escalate by
// severity; inconclusive findings are notes for human review.
func sarifLevel(f scanner.Finding) string {
	if f.Verdict == scanner.VerdictInconclusive {
		return "note"
	}
	switch string(f.Severity) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

// fingerprint is a stable per-finding identity for code-scanning alert tracking.
// It folds in the payload so that two findings sharing an attack ID (a pack with
// duplicate ids) stay distinct and are not collapsed into one alert.
func fingerprint(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		_, _ = h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)[:8])
}

func buildSARIF(meta Meta, findings []scanner.Finding) sarifLog {
	rules := []sarifRule{}
	ruleIndex := map[string]int{}
	results := []sarifResult{}

	for _, f := range findings {
		// SARIF carries problems, not passes.
		if f.Verdict == scanner.VerdictSafe {
			continue
		}

		idx, ok := ruleIndex[f.AttackID]
		if !ok {
			idx = len(rules)
			ruleIndex[f.AttackID] = idx
			r := sarifRule{
				ID:               f.AttackID,
				Name:             f.AttackName,
				ShortDescription: sarifText{Text: nonEmpty(f.AttackName, f.AttackID)},
				Properties: sarifRuleProps{
					Tags:             ruleTags(f),
					SecuritySeverity: securitySeverity(string(f.Severity)),
				},
			}
			if len(f.References) > 0 {
				r.HelpURI = f.References[0]
			}
			rules = append(rules, r)
		}

		msg := f.Reason
		for _, e := range f.Evidence {
			if e.Rationale != "" {
				msg += " — judge: " + e.Rationale
				break
			}
		}

		res := sarifResult{
			RuleID:    f.AttackID,
			RuleIndex: idx,
			Level:     sarifLevel(f),
			Message:   sarifText{Text: nonEmpty(msg, string(f.Verdict))},
			Locations: []sarifLocation{{PhysicalLocation: sarifPhysical{
				ArtifactLocation: sarifArtifact{URI: resultURI(f)},
			}}},
			PartialFingerprints: map[string]string{
				"momusAttackTarget": fingerprint(f.AttackID, meta.Target, f.Payload),
			},
			Properties: map[string]any{
				"verdict":  string(f.Verdict),
				"category": f.Category,
				"severity": string(f.Severity),
			},
		}
		results = append(results, res)
	}

	return sarifLog{
		Schema:  sarifSchema,
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "Momus",
				InformationURI: "https://github.com/momusai/momus",
				Version:        nonEmpty(meta.Version, "dev"),
				Rules:          rules,
			}},
			Results:    results,
			Properties: runProperties(meta),
		}},
	}
}

// runProperties records scan scope so a consumer can tell a partial run from a
// full one — a 5-of-200 SARIF otherwise reads as a clean scan.
func runProperties(meta Meta) map[string]any {
	props := map[string]any{"target": meta.Target, "pack": meta.Pack}
	if meta.PartialScope != "" {
		props["partialScan"] = true
		props["scope"] = meta.PartialScope
	}
	return props
}

// resultURI is the file a finding points at.
//
// It must be a REPO-RELATIVE PATH, never the scanned URL. GitHub code scanning
// resolves every location against the checkout and rejects the whole upload
// otherwise: 'SARIF URI scheme "http" did not match the checkout URI scheme
// "file"'. Putting the target here therefore meant no Momus finding could ever
// reach the Security tab, which is the one place a CI user looks for them.
//
// The attack's own pack file is the natural answer: it is a real file, it is
// where the rule that fired is defined, and clicking the alert lands on the
// attack rather than on a URL that says nothing. The target URL is not lost —
// it is on the run's properties and in every result's message.
//
// The fallback matters for a pack loaded from outside the repo, where no
// relative path is meaningful. It is deliberately extension-less and stable so
// alerts group together rather than scattering across invented filenames.
func resultURI(f scanner.Finding) string {
	src := strings.TrimSpace(f.AttackSource)
	if src == "" || hasURIScheme(src) {
		return scanURIFallback
	}
	// An absolute path is what you get from `--pack /abs/path/to/pack`, and it is
	// no more usable to GitHub than a URL was. Re-root it on the working
	// directory; if it lies outside, there is no repo-relative path to give.
	if filepath.IsAbs(src) {
		wd, err := os.Getwd()
		if err != nil {
			return scanURIFallback
		}
		rel, err := filepath.Rel(wd, src)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return scanURIFallback
		}
		src = rel
	}
	return filepath.ToSlash(src)
}

// scanURIFallback is used when a finding has no path that means anything
// inside the checkout — an embedded pack, or one loaded from elsewhere on
// disk. Extension-less and stable, so those alerts group together instead of
// scattering across invented filenames.
const scanURIFallback = "momus-scan"

// hasURIScheme reports whether s looks like "scheme://..." rather than a path.
func hasURIScheme(s string) bool {
	i := strings.Index(s, "://")
	return i > 0 && !strings.ContainsAny(s[:i], "/\\.")
}

// ruleTags builds a rule's SARIF tags, deduplicated.
//
// The dedup is load-bearing, not tidiness: GitHub's SARIF ingestion rejects the
// ENTIRE upload if any rule's properties.tags contains a repeated item, with
// "contains duplicate item". Duplicates are the normal case here — an attack in
// the prompt-injection category also carries a "prompt-injection" tag, and most
// carry an "owasp-llm-01" tag alongside the OWASPLLM field — so before this the
// upload failed for every scan and no findings ever reached the Security tab.
func ruleTags(f scanner.Finding) []string {
	tags := make([]string, 0, len(f.Tags)+3)
	seen := make(map[string]bool, len(f.Tags)+3)
	add := func(t string) {
		if t == "" || seen[t] {
			return
		}
		seen[t] = true
		tags = append(tags, t)
	}
	add("security")
	add(f.Category)
	add(f.OWASPLLM)
	for _, t := range f.Tags {
		add(t)
	}
	return tags
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// WriteSARIF writes a SARIF 2.1.0 log of the findings to w.
func WriteSARIF(w io.Writer, meta Meta, findings []scanner.Finding) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(buildSARIF(meta, findings))
}

// WriteSARIFFile writes the SARIF log to path atomically.
func WriteSARIFFile(path string, meta Meta, findings []scanner.Finding) error {
	return atomicWrite(path, func(w io.Writer) error { return WriteSARIF(w, meta, findings) })
}
