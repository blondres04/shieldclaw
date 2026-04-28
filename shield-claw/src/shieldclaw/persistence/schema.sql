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

CREATE TABLE IF NOT EXISTS approvals (
    finding_id   TEXT PRIMARY KEY REFERENCES findings(finding_id),
    decision     TEXT NOT NULL,     -- 'APPROVED' or 'REJECTED'
    decided_by   TEXT NOT NULL,     -- username from os.getlogin() fallback 'unknown'
    decided_at   TEXT NOT NULL,
    note         TEXT,
    auto         INTEGER NOT NULL DEFAULT 0   -- 1 when set by SHIELDCLAW_AUTO_APPROVE
);

CREATE TABLE IF NOT EXISTS pocs (
    poc_id             TEXT PRIMARY KEY,
    finding_id         TEXT NOT NULL REFERENCES findings(finding_id),
    raw_code           TEXT NOT NULL,
    target_dns         TEXT NOT NULL,
    execution_command  TEXT NOT NULL,
    language           TEXT NOT NULL,
    generated_at       TEXT NOT NULL,
    model_name         TEXT NOT NULL,
    iteration          INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS evidence (
    evidence_id    TEXT PRIMARY KEY,
    finding_id     TEXT NOT NULL REFERENCES findings(finding_id),
    observer_name  TEXT NOT NULL,
    tier           INTEGER NOT NULL,
    summary        TEXT NOT NULL,
    payload_json   TEXT NOT NULL,
    captured_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS verdicts (
    finding_id   TEXT PRIMARY KEY REFERENCES findings(finding_id),
    verdict      TEXT NOT NULL,
    confidence   REAL NOT NULL,
    summary      TEXT NOT NULL,
    decided_at   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_scan  ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_state ON findings(state);
CREATE INDEX IF NOT EXISTS idx_pocs_finding   ON pocs(finding_id);
CREATE INDEX IF NOT EXISTS idx_evidence_find  ON evidence(finding_id);
