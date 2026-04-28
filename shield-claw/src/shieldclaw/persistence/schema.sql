-- ShieldClaw v0.2 — scan persistence schema
-- All timestamps are stored as ISO-8601 UTC strings.
-- WAL mode is enabled at connection time in store.py.

CREATE TABLE IF NOT EXISTS scans (
    scan_id          TEXT PRIMARY KEY,
    target_dir       TEXT NOT NULL,
    semgrep_input_path TEXT,
    state            TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    pipeline_error   TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id       TEXT PRIMARY KEY,
    scan_id          TEXT NOT NULL REFERENCES scans(scan_id),
    rule_id          TEXT NOT NULL,
    severity         TEXT NOT NULL,
    path             TEXT NOT NULL,
    start_line       INTEGER NOT NULL,
    end_line         INTEGER NOT NULL,
    cwe              TEXT NOT NULL,
    metavars_json    TEXT NOT NULL,
    raw_extra_json   TEXT NOT NULL,
    triage_verdict   TEXT,
    triage_reason    TEXT,
    state            TEXT NOT NULL DEFAULT 'INGESTED'
);

CREATE TABLE IF NOT EXISTS scores (
    finding_id       TEXT PRIMARY KEY REFERENCES findings(finding_id),
    score            REAL NOT NULL,
    attack_surface   TEXT NOT NULL,
    prerequisites_json TEXT NOT NULL,
    reasoning        TEXT NOT NULL,
    model_name       TEXT NOT NULL,
    scored_at        TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_scan  ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_state ON findings(state);
