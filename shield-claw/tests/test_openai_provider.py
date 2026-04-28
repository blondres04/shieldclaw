"""Unit tests for OpenAIProvider against a mocked httpx transport."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import httpx
import pytest
from pytest_mock import MockerFixture

from shieldclaw.exceptions import LLMConnectionError, LLMRefusalError, LLMResponseError
from shieldclaw.intelligence.openai_provider import OpenAIProvider
from shieldclaw.models import ScanContext

_PAYLOAD = {
    "language": "python",
    "target_dns": "web",
    "raw_code": "import sys\nimport requests\nsys.exit(0)\n",
    "execution_command": "python3 /exploit/exploit.py",
}


def _context() -> ScanContext:
    return ScanContext(
        target_dir="/tmp/target",
        git_diff_content="diff --git a/app.py b/app.py\n+1\n",
        docker_compose_content="services:\n  web:\n    image: python:3.11-slim\n",
        timestamp=datetime(2026, 4, 28, tzinfo=UTC),
    )


def _openai_response(content: str) -> dict[str, object]:
    return {
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "model": "gpt-4o-mini",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
    }


def _install_mock(
    mocker: MockerFixture,
    response_body: dict[str, object],
    status_code: int = 200,
) -> None:
    req = httpx.Request("POST", "https://api.openai.com/v1/chat/completions")
    fake_response = httpx.Response(status_code, json=response_body, request=req)
    client_mock = mocker.MagicMock()
    client_mock.post.return_value = fake_response
    ctx_mock = mocker.MagicMock()
    ctx_mock.__enter__.return_value = client_mock
    ctx_mock.__exit__.return_value = False
    mocker.patch("shieldclaw.intelligence.openai_provider.httpx.Client", return_value=ctx_mock)


class TestOpenAIProviderGenerateExploit:
    def test_generate_exploit_success(self, mocker: MockerFixture) -> None:
        """Happy path: JSON response is parsed into ExploitPayload."""
        _install_mock(mocker, _openai_response(json.dumps(_PAYLOAD)))
        provider = OpenAIProvider(api_key="sk-test")
        payload = provider.generate_exploit(_context())
        assert payload.language == "python"
        assert payload.target_dns == "web"
        assert "sys.exit(0)" in payload.raw_code

    def test_generate_exploit_raises_when_no_api_key(self, mocker: MockerFixture) -> None:
        """Missing API key must raise LLMConnectionError before any HTTP call."""
        mocker.patch.dict("os.environ", {}, clear=True)
        for k in ("OPENAI_API_KEY",):
            import os

            os.environ.pop(k, None)
        provider = OpenAIProvider(api_key="")
        with pytest.raises(LLMConnectionError, match="OPENAI_API_KEY"):
            provider.generate_exploit(_context())

    def test_generate_exploit_raises_on_http_error(self, mocker: MockerFixture) -> None:
        """Network failures must map to LLMConnectionError."""
        client_mock = mocker.MagicMock()
        client_mock.post.side_effect = httpx.ConnectError("timeout", request=mocker.Mock())
        ctx_mock = mocker.MagicMock()
        ctx_mock.__enter__.return_value = client_mock
        ctx_mock.__exit__.return_value = False
        mocker.patch("shieldclaw.intelligence.openai_provider.httpx.Client", return_value=ctx_mock)
        provider = OpenAIProvider(api_key="sk-test")
        with pytest.raises(LLMConnectionError):
            provider.generate_exploit(_context())

    def test_generate_exploit_raises_on_content_filter(self, mocker: MockerFixture) -> None:
        """finish_reason=content_filter must raise LLMRefusalError."""
        body = {
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "Blocked."},
                    "finish_reason": "content_filter",
                }
            ]
        }
        _install_mock(mocker, body)
        provider = OpenAIProvider(api_key="sk-test")
        with pytest.raises(LLMRefusalError, match="content filter"):
            provider.generate_exploit(_context())

    def test_generate_exploit_raises_on_refusal_text(self, mocker: MockerFixture) -> None:
        """Text that looks like a refusal must raise LLMRefusalError."""
        body = _openai_response("I cannot help with that request.")
        _install_mock(mocker, body)
        provider = OpenAIProvider(api_key="sk-test")
        with pytest.raises(LLMRefusalError):
            provider.generate_exploit(_context())

    def test_generate_exploit_raises_on_missing_choices(self, mocker: MockerFixture) -> None:
        """Empty choices array must raise LLMResponseError."""
        _install_mock(mocker, {"choices": []})
        provider = OpenAIProvider(api_key="sk-test")
        with pytest.raises(LLMResponseError, match="choices"):
            provider.generate_exploit(_context())

    def test_generate_exploit_raises_on_invalid_json(self, mocker: MockerFixture) -> None:
        """Unparseable content must raise LLMResponseError."""
        _install_mock(mocker, _openai_response("not-json at all"))
        provider = OpenAIProvider(api_key="sk-test")
        with pytest.raises(LLMResponseError):
            provider.generate_exploit(_context())

    def test_generate_exploit_400_raises_connection_error(self, mocker: MockerFixture) -> None:
        """HTTP 401 Unauthorized must raise LLMConnectionError."""
        req = httpx.Request("POST", "https://api.openai.com/v1/chat/completions")
        error_resp = httpx.Response(
            401, json={"error": {"message": "Incorrect API key"}}, request=req
        )
        client_mock = mocker.MagicMock()
        client_mock.post.return_value = error_resp
        ctx_mock = mocker.MagicMock()
        ctx_mock.__enter__.return_value = client_mock
        ctx_mock.__exit__.return_value = False
        mocker.patch("shieldclaw.intelligence.openai_provider.httpx.Client", return_value=ctx_mock)

        # httpx does not auto-raise on 4xx unless we call raise_for_status.
        # The provider calls raise_for_status() explicitly.
        provider = OpenAIProvider(api_key="sk-test")
        with pytest.raises(LLMConnectionError, match="401"):
            provider.generate_exploit(_context())


class TestOpenAIProviderComplete:
    def test_complete_returns_raw_text(self, mocker: MockerFixture) -> None:
        """complete() returns the verbatim assistant message."""
        expected = '{"score": 0.9, "attack_surface": "NETWORK"}'
        _install_mock(mocker, _openai_response(expected))
        provider = OpenAIProvider(api_key="sk-test")
        result = provider.complete("system prompt", "user prompt")
        assert result == expected

    def test_complete_raises_on_connection_error(self, mocker: MockerFixture) -> None:
        """complete() maps transport failures to LLMConnectionError."""
        client_mock = mocker.MagicMock()
        client_mock.post.side_effect = httpx.ConnectTimeout("timed out", request=mocker.Mock())
        ctx_mock = mocker.MagicMock()
        ctx_mock.__enter__.return_value = client_mock
        ctx_mock.__exit__.return_value = False
        mocker.patch("shieldclaw.intelligence.openai_provider.httpx.Client", return_value=ctx_mock)
        provider = OpenAIProvider(api_key="sk-test")
        with pytest.raises(LLMConnectionError):
            provider.complete("sys", "user")
