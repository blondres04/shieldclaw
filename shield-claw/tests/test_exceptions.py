"""Ensures the exception hierarchy remains catchable at the ShieldClawError base."""

from __future__ import annotations

import pytest

from shieldclaw.exceptions import (
    AggregationError,
    DetonationError,
    DockerNotAvailableError,
    LLMConnectionError,
    LLMRefusalError,
    LLMResponseError,
    SandboxStartError,
    ShieldClawError,
)


@pytest.mark.parametrize(
    "exc_type",
    [
        AggregationError,
        LLMRefusalError,
        LLMResponseError,
        LLMConnectionError,
        DockerNotAvailableError,
        SandboxStartError,
        DetonationError,
    ],
)
def test_subclass_is_catchable_as_shieldclaw_error(exc_type: type[ShieldClawError]) -> None:
    """Each concrete error should expose message and be a ShieldClawError."""

    err = exc_type("unit-test failure")
    assert err.message == "unit-test failure"
    assert isinstance(err, ShieldClawError)
