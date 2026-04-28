"""SAST report ingestion: parse external tool output into Finding records."""

from __future__ import annotations

from shieldclaw.ingest.semgrep import parse_semgrep_json

__all__ = ["parse_semgrep_json"]
