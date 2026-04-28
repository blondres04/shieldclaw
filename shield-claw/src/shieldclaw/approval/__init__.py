"""Human-in-the-loop approval gate for SAST findings before detonation."""

from __future__ import annotations

from shieldclaw.approval.gate import (
    ApprovalContext,
    format_approval_context,
    get_current_user,
    is_auto_approve_enabled,
)

__all__ = [
    "ApprovalContext",
    "format_approval_context",
    "get_current_user",
    "is_auto_approve_enabled",
]
