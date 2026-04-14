"""Tests for ``OllamaProvider`` with mocked ``httpx`` transports."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import httpx
import pytest
from pytest_mock import MockerFixture

from shieldclaw.exceptions import LLMConnectionError, LLMResponseError
from shieldclaw.intelligence.ollama import OllamaProvider
from shieldclaw.models import ScanContext

_PAYLOAD = {
    "language": "python",
    "target_dns": "web",
    "raw_code": "import sys\nsys.exit(0)\n",
    "execution_command": "python3 /exploit/exploit.py",
}


def _scan_context() -> ScanContext:
    return ScanContext(
        target_dir="/tmp/target",
        git_diff_content="diff --git a/app.py b/app.py\n+1\n",
        docker_compose_content="services:\n  web:\n    image: python:3.11-slim\n",
        timestamp=datetime(2026, 4, 13, tzinfo=UTC),
    )


def _ollama_request() -> httpx.Request:
    return httpx.Request("POST", "http://ollama.test/api/chat")


def _install_client_mock(mocker: MockerFixture, response: httpx.Response) -> None:
    post = mocker.MagicMock(return_value=response)
    instance = mocker.MagicMock()
    instance.post = post
    client_ctx = mocker.MagicMock()
    client_ctx.__enter__.return_value = instance
    client_ctx.__exit__.return_value = False
    mocker.patch("shieldclaw.intelligence.ollama.httpx.Client", return_value=client_ctx)


def test_generate_exploit_success(mocker: MockerFixture) -> None:
    """Happy path should parse assistant JSON returned by Ollama."""
    body = {"message": {"content": json.dumps(_PAYLOAD)}}
    fake_response = httpx.Response(200, json=body, request=_ollama_request())
    _install_client_mock(mocker, fake_response)

    provider = OllamaProvider(base_url="http://ollama.test", model="test-model")
    payload = provider.generate_exploit(_scan_context())

    assert payload.language == "python"
    assert payload.target_dns == "web"


def test_generate_exploit_http_error(mocker: MockerFixture) -> None:
    """Transport failures must be wrapped as ``LLMConnectionError``."""
    post = mocker.MagicMock(side_effect=httpx.ConnectError("boom", request=mocker.Mock()))
    instance = mocker.MagicMock()
    instance.post = post
    client_ctx = mocker.MagicMock()
    client_ctx.__enter__.return_value = instance
    client_ctx.__exit__.return_value = False
    mocker.patch("shieldclaw.intelligence.ollama.httpx.Client", return_value=client_ctx)

    provider = OllamaProvider(base_url="http://missing.local")
    with pytest.raises(LLMConnectionError):
        provider.generate_exploit(_scan_context())


def test_generate_exploit_invalid_json_envelope(mocker: MockerFixture) -> None:
    """Malformed Ollama envelopes should raise ``LLMResponseError``."""
    fake_response = httpx.Response(200, json={"unexpected": True}, request=_ollama_request())
    _install_client_mock(mocker, fake_response)

    provider = OllamaProvider(base_url="http://ollama.test")
    with pytest.raises(LLMResponseError):
        provider.generate_exploit(_scan_context())


def test_generate_exploit_non_json_body(mocker: MockerFixture) -> None:
    """Non-JSON HTTP bodies should map to ``LLMResponseError``."""
    fake_response = httpx.Response(200, content=b"not-json", request=_ollama_request())
    _install_client_mock(mocker, fake_response)

    provider = OllamaProvider(base_url="http://ollama.test")
    with pytest.raises(LLMResponseError):
        provider.generate_exploit(_scan_context())
