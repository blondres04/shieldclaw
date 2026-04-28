"""Re-export of the observer base types from ``models.py``.

``DetonationObserver`` and ``ObserverEvidence`` live in ``models.py`` so that
``sandbox/docker_orchestrator.py`` can import them without violating the
package-isolation rule.  This module simply re-exports them for convenience.
"""

from __future__ import annotations

from shieldclaw.models import DetonationObserver, ObserverEvidence

__all__ = ["DetonationObserver", "ObserverEvidence"]
