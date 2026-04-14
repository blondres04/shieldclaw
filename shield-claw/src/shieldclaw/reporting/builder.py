"""Serialize ``ScanResult`` into JSON for operators, CI systems, and ``jq``."""

from __future__ import annotations

import json
import logging
import sys
from dataclasses import fields, is_dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import UUID

from shieldclaw.models import ScanResult

_LOG = logging.getLogger(__name__)


def _jsonable(value: Any) -> Any:
    """Recursively convert values into JSON-serializable primitives."""
    if value is None:
        return None
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return {f.name: _jsonable(getattr(value, f.name)) for f in fields(value)}
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


class ReportBuilder:
    """Turns in-memory scan outcomes into stable JSON for stdout or files.

    Serialization covers UUIDs, datetimes, enums, and nested dataclasses so
    downstream tooling never sees raw Python objects in JSON output.
    """

    def build(self, result: ScanResult) -> str:
        """Serialize a ``ScanResult`` into a formatted JSON document.

        Args:
            result: Fully or partially populated pipeline outcome.

        Returns:
            A JSON string with deterministic key ordering and indentation.
        """
        payload = _jsonable(result)
        assert isinstance(payload, dict)
        return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"

    def write(self, json_report: str, output_path: str | None) -> None:
        """Emit a JSON report to a file or standard output.

        Args:
            json_report: Serialized report from :meth:`build`.
            output_path: Optional filesystem path; ``None`` writes to stdout.

        Returns:
            None. File failures are logged at ERROR and mirrored to stdout.
        """
        if output_path is None:
            sys.stdout.write(json_report)
            return
        try:
            Path(output_path).expanduser().write_text(json_report, encoding="utf-8")
        except OSError as exc:
            _LOG.error("Failed to write report to %s: %s", output_path, exc)
            sys.stdout.write(json_report)
