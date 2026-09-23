// Package store persists scan runs to a SQLite file so results can be compared
// over time. Momus is most useful in CI, and the question CI actually asks is
// not "is this model safe?" but "did it get worse than last time?" — which
// needs yesterday's answer on disk.
//
// The package talks to database/sql only; the caller registers the driver. That
// keeps the (large) pure-Go SQLite dependency at a single import site in
// cmd/momus, so it can be swapped or dropped without touching this code.
package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/momus-ai/momus/internal/scanner"
)

// DefaultDriver is the driver name registered by modernc.org/sqlite.
const DefaultDriver = "sqlite"

// responseTextLimit caps how much of a target reply we keep per finding. A
// hostile endpoint may return megabytes, and 200 attacks of that would turn a
// convenience database into a disk problem. 64 KiB is far more than any real
// chat completion while still bounding the worst case.
const responseTextLimit = 64 << 10

// Store is an open evidence database.
type Store struct {
	db   *sql.DB
	path string
}

// Run is the scan-level record. It mirrors report.Meta plus timing, but is
// declared here so internal/store does not depend on internal/report.
type Run struct {
	StartedAt    time.Time
	FinishedAt   time.Time
	Target       string
	Pack         string
	Version      string
	JudgeName    string
	PartialScope string // "" means the full pack ran; see schema.go
}

// Open opens (creating if absent) the evidence database at path and applies the
// schema. driver may be "" to use DefaultDriver.
func Open(driver, path string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("store: empty database path")
	}
	if driver == "" {
		driver = DefaultDriver
	}
	db, err := sql.Open(driver, dsn(path))
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	// sql.Open is lazy; force a connection now so a bad path fails here rather
	// than after a scan has already spent minutes and real API credit.
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	s := &Store{db: db, path: path}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// dsn builds a driver DSN with the pragmas this schema relies on.
//
// foreign_keys is required for the ON DELETE CASCADE in the schema to actually
// fire — SQLite has it OFF by default, which would leave orphaned findings
// behind whenever a run is deleted. busy_timeout matters because two CI jobs
// can legitimately write the same database at once; without it the second one
// fails instantly with SQLITE_BUSY instead of waiting its turn.
func dsn(path string) string {
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(10000)")
	q.Add("_pragma", "foreign_keys(1)")
	return "file:" + path + "?" + q.Encode()
}

// migrate creates the schema, or verifies an existing file is a version we can
// read. A file written by a newer Momus is refused rather than partially read.
func (s *Store) migrate() error {
	var have int
	err := s.db.QueryRow(`SELECT version FROM schema_version LIMIT 1`).Scan(&have)
	switch {
	case err == nil:
		if have > schemaVersion {
			return fmt.Errorf("store: %s was written by a newer Momus (schema v%d, this build reads v%d); upgrade Momus or use a different --store file",
				s.path, have, schemaVersion)
		}
		if have < schemaVersion {
			return fmt.Errorf("store: %s uses schema v%d and this build expects v%d; no migration path exists yet, so point --store at a new file",
				s.path, have, schemaVersion)
		}
		return nil
	case isMissingTable(err):
		// Fresh (or non-Momus) file: create everything.
	default:
		return fmt.Errorf("store: reading schema version from %s: %w", s.path, err)
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("store: begin schema tx: %w", err)
	}
	// Rollback is a no-op once Commit succeeds; the error is intentionally
	// ignored because a failed rollback cannot be acted on here.
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(ddl); err != nil {
		return fmt.Errorf("store: applying schema to %s: %w", s.path, err)
	}
	if _, err := tx.Exec(`INSERT INTO schema_version(version) VALUES(?)`, schemaVersion); err != nil {
		return fmt.Errorf("store: recording schema version: %w", err)
	}
	return tx.Commit()
}

func isMissingTable(err error) bool {
	return err != nil && strings.Contains(err.Error(), "no such table")
}

// Close releases the database.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Path reports the database file this Store was opened on.
func (s *Store) Path() string { return s.path }

// SaveRun writes one scan and all its findings in a single transaction, so an
// interrupted or failed write leaves no half-recorded run for `momus diff` to
// compare against.
//
// It returns the run's uid.
func (s *Store) SaveRun(r Run, findings []scanner.Finding) (string, error) {
	uid, err := newRunUID()
	if err != nil {
		return "", err
	}

	var vuln, safe, inconc int
	for _, f := range findings {
		switch f.Verdict {
		case scanner.VerdictVulnerable:
			vuln++
		case scanner.VerdictSafe:
			safe++
		default:
			inconc++
		}
	}

	tx, err := s.db.Begin()
	if err != nil {
		return "", fmt.Errorf("store: begin run tx: %w", err)
	}
	// Rollback is a no-op once Commit succeeds; the error is intentionally
	// ignored because a failed rollback cannot be acted on here.
	defer func() { _ = tx.Rollback() }()

	res, err := tx.Exec(`INSERT INTO runs
		(run_uid, started_at, finished_at, target, pack, momus_version, judge_name,
		 partial_scope, attacks_total, vulnerable, safe, inconclusive)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		uid, utc(r.StartedAt), utc(r.FinishedAt), r.Target, r.Pack, r.Version,
		r.JudgeName, r.PartialScope, len(findings), vuln, safe, inconc)
	if err != nil {
		return "", fmt.Errorf("store: recording run: %w", err)
	}
	runID, err := res.LastInsertId()
	if err != nil {
		return "", fmt.Errorf("store: run id: %w", err)
	}

	insFinding, err := tx.Prepare(`INSERT INTO findings
		(run_id, attack_id, attack_name, category, severity, owasp_llm, tags,
		 verdict, reason, payload, response_text, response_trunc, response_status, latency_ms)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return "", fmt.Errorf("store: prepare finding insert: %w", err)
	}
	defer insFinding.Close()

	insEvidence, err := tx.Prepare(`INSERT INTO judge_evidence
		(finding_id, model, resolved_model, decision, confidence, evidence_quote,
		 rationale, nonce_ok, cache_hit)
		VALUES (?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return "", fmt.Errorf("store: prepare evidence insert: %w", err)
	}
	defer insEvidence.Close()

	for _, f := range findings {
		text, status, latency := "", 0, int64(0)
		if f.Response != nil {
			text, status, latency = f.Response.Text, f.Response.Status, f.Response.LatencyMs
		}
		trimmed, truncated := truncate(text, responseTextLimit)

		fr, err := insFinding.Exec(runID, f.AttackID, f.AttackName, f.Category,
			string(f.Severity), f.OWASPLLM, encodeTags(f.Tags), string(f.Verdict),
			f.Reason, f.Payload, trimmed, boolInt(truncated), status, latency)
		if err != nil {
			return "", fmt.Errorf("store: recording finding %s: %w", f.AttackID, err)
		}
		findingID, err := fr.LastInsertId()
		if err != nil {
			return "", fmt.Errorf("store: finding id for %s: %w", f.AttackID, err)
		}
		for _, e := range f.Evidence {
			quote, _ := truncate(e.EvidenceQuote, responseTextLimit)
			if _, err := insEvidence.Exec(findingID, e.Model, e.ResolvedModel,
				e.DecisionStr, e.Confidence, quote, e.Rationale,
				boolInt(e.NonceOK), boolInt(e.CacheHit)); err != nil {
				return "", fmt.Errorf("store: recording judge evidence for %s: %w", f.AttackID, err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("store: committing run: %w", err)
	}
	return uid, nil
}

// newRunUID returns a random run identifier. It is random rather than derived
// from the run's content because two identical scans are two distinct runs and
// must both be kept.
func newRunUID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("store: generating run id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// utc normalises timestamps to RFC3339 UTC so string ordering in SQL matches
// chronological ordering regardless of the machine's timezone.
func utc(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func encodeTags(tags []string) string {
	if len(tags) == 0 {
		return "[]"
	}
	b, err := json.Marshal(tags)
	if err != nil {
		return "[]"
	}
	return string(b)
}

func decodeTags(s string) []string {
	if s == "" || s == "[]" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil
	}
	return out
}

// truncate trims s to at most limit bytes without splitting a UTF-8 rune, and
// reports whether it cut anything.
func truncate(s string, limit int) (string, bool) {
	if len(s) <= limit {
		return s, false
	}
	s = s[:limit]
	for len(s) > 0 {
		r, size := utf8.DecodeLastRuneInString(s)
		if r == utf8.RuneError && size <= 1 {
			s = s[:len(s)-1]
			continue
		}
		break
	}
	return s, true
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
