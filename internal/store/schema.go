package store

// schemaVersion is bumped whenever the DDL below changes. Open() refuses a file
// written by a NEWER Momus than the one running: silently ignoring columns it
// does not understand would let `momus diff` compare runs it cannot fully read,
// and a diff that quietly drops data is exactly the kind of false reassurance
// this tool exists to prevent.
const schemaVersion = 1

// The schema is deliberately plain SQL with no ORM: the point of an on-disk
// SQLite file is that a user can open it with the sqlite3 CLI, Metabase, or
// Grafana and ask their own questions. Anything clever here would be a cost paid
// by every one of those consumers.
//
// Verdicts are stored as text rather than an integer enum for the same reason —
// `WHERE verdict = 'vulnerable'` should work without a lookup table.
const ddl = `
CREATE TABLE IF NOT EXISTS schema_version (
	version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
	id             INTEGER PRIMARY KEY AUTOINCREMENT,
	run_uid        TEXT    NOT NULL UNIQUE,
	started_at     TEXT    NOT NULL,
	finished_at    TEXT    NOT NULL,
	target         TEXT    NOT NULL,
	pack           TEXT    NOT NULL DEFAULT '',
	momus_version  TEXT    NOT NULL DEFAULT '',
	judge_name     TEXT    NOT NULL DEFAULT '',

	-- '' means the whole pack ran. Anything else records WHY the run was
	-- partial (--limit/--category). A diff must never read "attack X is gone"
	-- as "attack X was fixed" when the truth is "attack X never ran", so this
	-- column is not cosmetic: query.go keys its scope guard off it.
	partial_scope  TEXT    NOT NULL DEFAULT '',

	attacks_total  INTEGER NOT NULL DEFAULT 0,
	vulnerable     INTEGER NOT NULL DEFAULT 0,
	safe           INTEGER NOT NULL DEFAULT 0,
	inconclusive   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
	id              INTEGER PRIMARY KEY AUTOINCREMENT,
	run_id          INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
	attack_id       TEXT    NOT NULL,
	attack_name     TEXT    NOT NULL DEFAULT '',
	category        TEXT    NOT NULL DEFAULT '',
	severity        TEXT    NOT NULL DEFAULT '',
	owasp_llm       TEXT    NOT NULL DEFAULT '',
	tags            TEXT    NOT NULL DEFAULT '[]',
	verdict         TEXT    NOT NULL,
	reason          TEXT    NOT NULL DEFAULT '',
	payload         TEXT    NOT NULL DEFAULT '',
	response_text   TEXT    NOT NULL DEFAULT '',
	response_trunc  INTEGER NOT NULL DEFAULT 0,
	response_status INTEGER NOT NULL DEFAULT 0,
	latency_ms      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS judge_evidence (
	id             INTEGER PRIMARY KEY AUTOINCREMENT,
	finding_id     INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
	model          TEXT    NOT NULL DEFAULT '',
	resolved_model TEXT    NOT NULL DEFAULT '',
	decision       TEXT    NOT NULL DEFAULT '',
	confidence     REAL    NOT NULL DEFAULT 0,
	evidence_quote TEXT    NOT NULL DEFAULT '',
	rationale      TEXT    NOT NULL DEFAULT '',
	nonce_ok       INTEGER NOT NULL DEFAULT 0,
	cache_hit      INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_findings_run     ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_attack  ON findings(attack_id);
CREATE INDEX IF NOT EXISTS idx_findings_verdict ON findings(verdict);
CREATE INDEX IF NOT EXISTS idx_runs_target      ON runs(target, started_at);
CREATE INDEX IF NOT EXISTS idx_evidence_finding ON judge_evidence(finding_id);

-- A convenience view so the first question most people ask ("what is currently
-- broken?") does not require them to work out the join themselves.
CREATE VIEW IF NOT EXISTS current_vulnerabilities AS
SELECT r.target, r.started_at, f.attack_id, f.attack_name, f.severity,
       f.category, f.reason
FROM findings f
JOIN runs r ON r.id = f.run_id
WHERE f.verdict = 'vulnerable'
ORDER BY r.started_at DESC, f.severity, f.attack_id;
`
