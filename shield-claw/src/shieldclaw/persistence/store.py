"""SQLite-backed scan store enabling resumable ShieldClaw pipelines.

The database file lives at ``<target_dir>/.shieldclaw/scans.db``.  The
``.shieldclaw/`` directory is created on first write.

Design principles
-----------------
* Parameterised queries only — no string interpolation into SQL.
* WAL mode enabled at connect time for better concurrent-write safety.
* Narrow public API: one method per concern; no ORM.
* All methods that write also update ``scans.updated_at``.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from shieldclaw.models import ExploitabilityScore, Finding

_SCHEMA_PATH: Final[Path] = Path(__file__).with_name("schema.sql")

# ---------------------------------------------------------------------------
# Row types returned by the store.
# ---------------------------------------------------------------------------


@dataclass
class ScanRow:
    """Projection of the ``scans`` table."""

    scan_id: str
    target_dir: str
    semgrep_input_path: str | None
    state: str
    created_at: str
    updated_at: str
    pipeline_error: str | None


@dataclass
class FindingRow:
    """Projection of the ``findings`` table."""

    finding_id: str
    scan_id: str
    rule_id: str
    severity: str
    path: str
    start_line: int
    end_line: int
    cwe: str  # JSON array string e.g. '["CWE-89"]'
    metavars_json: str
    raw_extra_json: str
    triage_verdict: str | None
    triage_reason: str | None
    state: str


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------


class ScanStore:
    """Manages scan lifecycle records in a per-target SQLite database.

    Args:
        target_dir: Root directory of the repository being scanned.
            The database is written to ``<target_dir>/.shieldclaw/scans.db``.
    """

    def __init__(self, target_dir: str) -> None:
        db_dir = Path(target_dir).expanduser().resolve() / ".shieldclaw"
        db_dir.mkdir(parents=True, exist_ok=True)
        self._db_path = db_dir / "scans.db"
        self._init_db()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self) -> None:
        schema = _SCHEMA_PATH.read_text(encoding="utf-8")
        with self._connect() as conn:
            conn.executescript(schema)

    @staticmethod
    def _now() -> str:
        return datetime.now(tz=UTC).isoformat()

    def _touch_scan(self, conn: sqlite3.Connection, scan_id: str) -> None:
        conn.execute(
            "UPDATE scans SET updated_at = ? WHERE scan_id = ?",
            (self._now(), scan_id),
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create_scan(
        self,
        scan_id: str,
        target_dir: str,
        semgrep_input_path: str | None,
    ) -> None:
        """Insert a new scan record in CREATED state.

        Args:
            scan_id: UUID string for this run.
            target_dir: Repository root being scanned.
            semgrep_input_path: Path to the Semgrep JSON report, or ``None``
                when running in legacy diff mode.
        """
        now = self._now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO scans
                    (scan_id, target_dir, semgrep_input_path, state, created_at, updated_at)
                VALUES (?, ?, ?, 'CREATED', ?, ?)
                """,
                (scan_id, str(target_dir), semgrep_input_path, now, now),
            )

    def record_findings(self, scan_id: str, findings: tuple[Finding, ...]) -> None:
        """Persist a batch of ingested findings (state = INGESTED).

        Args:
            scan_id: Parent scan identifier.
            findings: Tuple of ``Finding`` objects to store.
        """
        rows = [
            (
                str(f.finding_id),
                scan_id,
                f.rule_id,
                f.severity,
                f.path,
                f.start_line,
                f.end_line,
                json.dumps(list(f.cwe)),
                json.dumps(f.metavars),
                f.raw_extra,
                "INGESTED",
            )
            for f in findings
        ]
        with self._connect() as conn:
            conn.executemany(
                """
                INSERT OR IGNORE INTO findings
                    (finding_id, scan_id, rule_id, severity, path, start_line, end_line,
                     cwe, metavars_json, raw_extra_json, state)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
            self._touch_scan(conn, scan_id)

    def set_triage(self, finding_id: str, verdict: str, reason: str) -> None:
        """Write the triage verdict and reason for a finding.

        Args:
            finding_id: UUID string for the finding.
            verdict: ``TriageVerdict`` value string.
            reason: Short explanation of the classification.
        """
        with self._connect() as conn:
            conn.execute(
                "UPDATE findings SET triage_verdict = ?, triage_reason = ? WHERE finding_id = ?",
                (verdict, reason, finding_id),
            )

    def record_score(self, finding_id: str, score: ExploitabilityScore) -> None:
        """Insert an exploitability score for a finding.

        Args:
            finding_id: UUID string for the finding.
            score: ``ExploitabilityScore`` produced by the scorer.
        """
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO scores
                    (finding_id, score, attack_surface, prerequisites_json,
                     reasoning, model_name, scored_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding_id,
                    score.score,
                    score.attack_surface,
                    json.dumps(list(score.prerequisites)),
                    score.reasoning,
                    score.model_name,
                    score.scored_at.isoformat(),
                ),
            )

    def get_pending_findings(self, scan_id: str, state: str) -> list[FindingRow]:
        """Return findings for a scan that are in the given state.

        Args:
            scan_id: Scan to query.
            state: Target state (e.g. ``"TRIAGED"`` to find findings ready
                for scoring).

        Returns:
            List of ``FindingRow`` objects ordered by finding_id.
        """
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT finding_id, scan_id, rule_id, severity, path, start_line, end_line,
                       cwe, metavars_json, raw_extra_json, triage_verdict, triage_reason, state
                FROM findings
                WHERE scan_id = ? AND state = ?
                ORDER BY finding_id
                """,
                (scan_id, state),
            ).fetchall()
        return [
            FindingRow(
                finding_id=r["finding_id"],
                scan_id=r["scan_id"],
                rule_id=r["rule_id"],
                severity=r["severity"],
                path=r["path"],
                start_line=r["start_line"],
                end_line=r["end_line"],
                cwe=r["cwe"],
                metavars_json=r["metavars_json"],
                raw_extra_json=r["raw_extra_json"],
                triage_verdict=r["triage_verdict"],
                triage_reason=r["triage_reason"],
                state=r["state"],
            )
            for r in rows
        ]

    def update_finding_state(self, finding_id: str, state: str) -> None:
        """Transition a finding to a new state.

        Args:
            finding_id: UUID string for the finding.
            state: New state string (e.g. ``"TRIAGED"``, ``"SCORED"``).
        """
        with self._connect() as conn:
            conn.execute(
                "UPDATE findings SET state = ? WHERE finding_id = ?",
                (state, finding_id),
            )

    def update_scan_state(self, scan_id: str, state: str) -> None:
        """Transition a scan to a new state.

        Args:
            scan_id: UUID string for the scan.
            state: New state string.
        """
        with self._connect() as conn:
            conn.execute(
                "UPDATE scans SET state = ?, updated_at = ? WHERE scan_id = ?",
                (state, self._now(), scan_id),
            )

    def load_scan(self, scan_id: str) -> ScanRow | None:
        """Retrieve a scan record by its identifier.

        Args:
            scan_id: UUID string to look up.

        Returns:
            ``ScanRow`` if found, ``None`` otherwise.
        """
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT scan_id, target_dir, semgrep_input_path, state,
                       created_at, updated_at, pipeline_error
                FROM scans WHERE scan_id = ?
                """,
                (scan_id,),
            ).fetchone()
        if row is None:
            return None
        return ScanRow(
            scan_id=row["scan_id"],
            target_dir=row["target_dir"],
            semgrep_input_path=row["semgrep_input_path"],
            state=row["state"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            pipeline_error=row["pipeline_error"],
        )

    def get_latest_scan(self, target_dir: str) -> ScanRow | None:
        """Return the most recently created scan for a target directory.

        Args:
            target_dir: Repository root path to filter by.

        Returns:
            Most recent ``ScanRow``, or ``None`` if no scans exist.
        """
        resolved = str(Path(target_dir).expanduser().resolve())
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT scan_id, target_dir, semgrep_input_path, state,
                       created_at, updated_at, pipeline_error
                FROM scans
                WHERE target_dir = ?
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (resolved,),
            ).fetchone()
        if row is None:
            return None
        return ScanRow(
            scan_id=row["scan_id"],
            target_dir=row["target_dir"],
            semgrep_input_path=row["semgrep_input_path"],
            state=row["state"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            pipeline_error=row["pipeline_error"],
        )

    def list_scans(self, target_dir: str | None = None) -> list[ScanRow]:
        """Return all scans, optionally filtered by target directory.

        Args:
            target_dir: If supplied, only scans for this path are returned.

        Returns:
            List of ``ScanRow`` objects ordered by ``created_at`` descending.
        """
        if target_dir is not None:
            resolved = str(Path(target_dir).expanduser().resolve())
            query = "SELECT * FROM scans WHERE target_dir = ? ORDER BY created_at DESC"
            params: tuple[str, ...] = (resolved,)
        else:
            query = "SELECT * FROM scans ORDER BY created_at DESC"
            params = ()
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [
            ScanRow(
                scan_id=r["scan_id"],
                target_dir=r["target_dir"],
                semgrep_input_path=r["semgrep_input_path"],
                state=r["state"],
                created_at=r["created_at"],
                updated_at=r["updated_at"],
                pipeline_error=r["pipeline_error"],
            )
            for r in rows
        ]

    # ------------------------------------------------------------------
    # Approvals
    # ------------------------------------------------------------------

    def record_approval(
        self,
        finding_id: str,
        decision: str,
        decided_by: str,
        *,
        note: str | None = None,
        auto: bool = False,
    ) -> None:
        """Persist an approval or rejection decision for a finding."""
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO approvals
                    (finding_id, decision, decided_by, decided_at, note, auto)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (finding_id, decision, decided_by, self._now(), note, int(auto)),
            )

    def get_approval(self, finding_id: str) -> dict[str, object] | None:
        """Return the approval record for a finding, or None."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM approvals WHERE finding_id = ?", (finding_id,)
            ).fetchone()
        if row is None:
            return None
        return dict(row)

    # ------------------------------------------------------------------
    # PoCs
    # ------------------------------------------------------------------

    def record_poc(
        self,
        poc_id: str,
        finding_id: str,
        raw_code: str,
        target_dns: str,
        execution_command: str,
        language: str,
        model_name: str,
        iteration: int = 1,
    ) -> None:
        """Persist a generated proof-of-concept exploit."""
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO pocs
                    (poc_id, finding_id, raw_code, target_dns,
                     execution_command, language, generated_at, model_name, iteration)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    poc_id,
                    finding_id,
                    raw_code,
                    target_dns,
                    execution_command,
                    language,
                    self._now(),
                    model_name,
                    iteration,
                ),
            )

    def get_poc_for_finding(self, finding_id: str) -> dict[str, object] | None:
        """Return the latest PoC for a finding (highest iteration), or None."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM pocs WHERE finding_id = ? ORDER BY iteration DESC LIMIT 1",
                (finding_id,),
            ).fetchone()
        return dict(row) if row is not None else None

    # ------------------------------------------------------------------
    # Evidence
    # ------------------------------------------------------------------

    def record_evidence(
        self,
        evidence_id: str,
        finding_id: str,
        observer_name: str,
        tier: int,
        summary: str,
        payload_json: str,
        captured_at: str,
    ) -> None:
        """Persist a single piece of observer evidence."""
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO evidence
                    (evidence_id, finding_id, observer_name, tier,
                     summary, payload_json, captured_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (evidence_id, finding_id, observer_name, tier, summary, payload_json, captured_at),
            )

    def get_evidence_for_finding(self, finding_id: str) -> list[dict[str, object]]:
        """Return all evidence records for a finding."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM evidence WHERE finding_id = ? ORDER BY captured_at",
                (finding_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Verdicts
    # ------------------------------------------------------------------

    def record_verdict(
        self,
        finding_id: str,
        verdict: str,
        confidence: float,
        summary: str,
    ) -> None:
        """Persist the synthesised verdict for a finding."""
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO verdicts
                    (finding_id, verdict, confidence, summary, decided_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (finding_id, verdict, confidence, summary, self._now()),
            )

    def get_verdict(self, finding_id: str) -> dict[str, object] | None:
        """Return the verdict for a finding, or None."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM verdicts WHERE finding_id = ?", (finding_id,)
            ).fetchone()
        return dict(row) if row is not None else None

    def count_findings_by_state(self, scan_id: str) -> dict[str, int]:
        """Return a ``{state: count}`` map for all findings in a scan.

        Args:
            scan_id: Scan to query.

        Returns:
            Dictionary mapping state strings to finding counts.
        """
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT state, COUNT(*) AS n FROM findings WHERE scan_id = ? GROUP BY state",
                (scan_id,),
            ).fetchall()
        return {r["state"]: r["n"] for r in rows}
