// Package report renders scan findings into a single self-contained HTML file.
//
// Security note: a report embeds attacker-influenced content (target responses,
// judge output, payloads). All dynamic values are rendered through
// html/template, which auto-escapes them, so a malicious response cannot inject
// markup or script into the report. Do NOT switch to text/template or string
// concatenation here.
package report

import (
	"html/template"
	"io"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/momus-ai/momus/internal/scanner"
)

// Meta is scan-level context shown in the report header.
type Meta struct {
	Target      string
	Pack        string
	JudgeName   string
	Version     string
	GeneratedAt string // caller-supplied so the report stays reproducible

	// PartialScope is set when only part of the pack was run (--limit/--category).
	// It must appear in the artifacts: a 5-of-200 scan otherwise looks identical
	// to a full clean pass once the terminal output is gone.
	PartialScope string
}

type findingView struct {
	scanner.Finding
	ResponseText string
	Truncated    bool
}

type reportData struct {
	Meta         Meta
	Total        int
	Vulnerable   int
	Safe         int
	Inconclusive int
	SeverityRows []severityRow
	Findings     []findingView
	HasResponses bool
}

type severityRow struct {
	Severity string
	Count    int
}

const responseExcerptLimit = 4000

var verdictRank = map[scanner.Verdict]int{
	scanner.VerdictVulnerable:   0,
	scanner.VerdictInconclusive: 1,
	scanner.VerdictSafe:         2,
}

var severityRank = map[string]int{
	"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
}

func build(meta Meta, findings []scanner.Finding) reportData {
	d := reportData{Meta: meta, Total: len(findings)}
	sevCount := map[string]int{}

	views := make([]findingView, 0, len(findings))
	for _, f := range findings {
		switch f.Verdict {
		case scanner.VerdictVulnerable:
			d.Vulnerable++
			sevCount[string(f.Severity)]++
		case scanner.VerdictSafe:
			d.Safe++
		default:
			d.Inconclusive++
		}
		fv := findingView{Finding: f}
		if f.Response != nil {
			fv.ResponseText = f.Response.Text
			if len(fv.ResponseText) > responseExcerptLimit {
				fv.ResponseText = truncateRunes(fv.ResponseText, responseExcerptLimit)
				fv.Truncated = true
			}
			if fv.ResponseText != "" {
				d.HasResponses = true
			}
		}
		views = append(views, fv)
	}

	// Sort: problems first (vulnerable, then inconclusive, then safe); within a
	// verdict, by severity; then by attack id for stable, reproducible output.
	sort.SliceStable(views, func(i, j int) bool {
		a, b := views[i], views[j]
		if r := verdictRank[a.Verdict] - verdictRank[b.Verdict]; r != 0 {
			return r < 0
		}
		if r := severityRank[string(a.Severity)] - severityRank[string(b.Severity)]; r != 0 {
			return r < 0
		}
		return a.AttackID < b.AttackID
	})
	d.Findings = views

	// Severity breakdown for vulnerable findings, in canonical order.
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if c := sevCount[sev]; c > 0 {
			d.SeverityRows = append(d.SeverityRows, severityRow{Severity: sev, Count: c})
		}
	}
	return d
}

// truncateLimit trims s to at most limit bytes without splitting a UTF-8 rune:
// after the byte-slice it drops any trailing incomplete rune so the excerpt is
// always valid UTF-8 (avoids a garbled U+FFFD tail in the report).
func truncateRunes(s string, limit int) string {
	if len(s) <= limit {
		return strings.ToValidUTF8(s, "\uFFFD")
	}
	s = s[:limit]
	// Cutting at a byte offset can split the final rune. Strip at most the
	// bytes one rune can occupy: the loop used to be unbounded, so a reply whose
	// first `limit` bytes were not valid UTF-8 at all was eaten down to "" — and
	// the template's {{if .ResponseText}} guard then omitted the response
	// section entirely, leaving a vulnerable finding with no evidence shown.
	for i := 0; i < utf8.UTFMax-1 && len(s) > 0; i++ {
		r, size := utf8.DecodeLastRuneInString(s)
		if r == utf8.RuneError && size <= 1 {
			s = s[:len(s)-1]
			continue
		}
		break
	}
	// Any remaining invalid bytes become replacement characters rather than
	// disappearing: a mangled excerpt is evidence, an empty one is not.
	return strings.ToValidUTF8(s, "\uFFFD")
}

// WriteHTML renders the findings to w as a single self-contained HTML page.
func WriteHTML(w io.Writer, meta Meta, findings []scanner.Finding) error {
	return tmpl.Execute(w, build(meta, findings))
}

// WriteHTMLFile renders the report to path atomically (temp file + rename), so a
// failed render never clobbers a previous report or reports success on a
// truncated file.
func WriteHTMLFile(path string, meta Meta, findings []scanner.Finding) error {
	return atomicWrite(path, func(w io.Writer) error { return WriteHTML(w, meta, findings) })
}

// capitalize upper-cases the first rune (ASCII words like severities/categories).
func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

var tmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"title": capitalize,
	"pct": func(n, total int) int {
		if total == 0 {
			return 0
		}
		return n * 100 / total
	},
}).Parse(htmlTemplate))
