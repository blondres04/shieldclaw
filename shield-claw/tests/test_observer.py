"""Unit tests for Tier-1 and Tier-2 observer implementations."""

from __future__ import annotations

import json
import subprocess

from pytest_mock import MockerFixture

from shieldclaw.observer.docker_diff import DockerDiffObserver
from shieldclaw.observer.exit_code import ExitCodeObserver
from shieldclaw.observer.target_logs import TargetLogObserver


class TestExitCodeObserver:
    def test_before_detonate_returns_none(self) -> None:
        obs = ExitCodeObserver()
        assert obs.before_detonate(None, "net") is None

    def test_after_detonate_success(self) -> None:
        obs = ExitCodeObserver()
        ev = obs.after_detonate(None, 0, "success", "", None)
        assert ev.observer_name == "exit_code"
        assert ev.tier == 1
        assert "exit_code=0" in ev.summary
        assert "SUCCEEDED" in ev.summary.upper()
        payload = json.loads(ev.payload_json)
        assert payload["exit_code"] == 0

    def test_after_detonate_failure(self) -> None:
        obs = ExitCodeObserver()
        ev = obs.after_detonate(None, 1, "", "error", None)
        payload = json.loads(ev.payload_json)
        assert payload["exit_code"] == 1
        assert "exit_code=1" in ev.summary

    def test_after_detonate_timeout(self) -> None:
        obs = ExitCodeObserver()
        ev = obs.after_detonate(None, 124, "", "", None)
        payload = json.loads(ev.payload_json)
        assert payload["exit_code"] == 124


class TestDockerDiffObserver:
    def test_before_detonate_is_noop(self) -> None:
        obs = DockerDiffObserver()
        assert obs.before_detonate("container123", "net") is None

    def test_skipped_when_no_container(self) -> None:
        obs = DockerDiffObserver()
        ev = obs.after_detonate(None, 0, "", "", None)
        assert "skipped" in ev.summary

    def test_parses_diff_output(self, mocker: MockerFixture) -> None:
        diff_output = "A /app/data/flag.txt\nC /etc/hosts\nD /tmp/noisefile\n"
        proc = subprocess.CompletedProcess(["docker", "diff"], 0, diff_output, "")
        mocker.patch("shieldclaw.observer.docker_diff.subprocess.run", return_value=proc)

        obs = DockerDiffObserver()
        ev = obs.after_detonate(None, 0, "", "", "container123")
        payload = json.loads(ev.payload_json)
        # /tmp/ should be filtered out as noise.
        assert "/app/data/flag.txt" in payload["added"]
        assert "/etc/hosts" in payload["modified"]
        assert payload["deleted"] == []  # /tmp/ filtered

    def test_reports_non_trivial_side_effects(self, mocker: MockerFixture) -> None:
        diff_output = "A /app/uploaded/shell.php\n"
        proc = subprocess.CompletedProcess(["docker", "diff"], 0, diff_output, "")
        mocker.patch("shieldclaw.observer.docker_diff.subprocess.run", return_value=proc)

        obs = DockerDiffObserver()
        ev = obs.after_detonate(None, 0, "", "", "c1")
        assert "non-trivial" in ev.summary

    def test_handles_docker_error(self, mocker: MockerFixture) -> None:
        mocker.patch(
            "shieldclaw.observer.docker_diff.subprocess.run",
            side_effect=FileNotFoundError("docker not found"),
        )
        obs = DockerDiffObserver()
        ev = obs.after_detonate(None, 0, "", "", "c1")
        assert "error" in ev.summary.lower()


class TestTargetLogObserver:
    def test_before_detonate_returns_timestamp_string(self) -> None:
        obs = TargetLogObserver()
        ts = obs.before_detonate("c1", "net")
        assert isinstance(ts, str)
        assert "T" in ts  # ISO-8601 format

    def test_skipped_when_no_container(self) -> None:
        obs = TargetLogObserver()
        ev = obs.after_detonate("2026-01-01T00:00:00", 0, "", "", None)
        assert "skipped" in ev.summary

    def test_captures_logs(self, mocker: MockerFixture) -> None:
        log_output = '127.0.0.1 - - [01/Jan/2026 00:00:01] "GET /user?id=1 HTTP/1.1" 200 -\n'
        proc = subprocess.CompletedProcess(["docker", "logs"], 0, log_output, "")
        mocker.patch("shieldclaw.observer.target_logs.subprocess.run", return_value=proc)

        obs = TargetLogObserver()
        ev = obs.after_detonate("2026-01-01T00:00:00", 0, "", "", "c1")
        payload = json.loads(ev.payload_json)
        assert payload["has_200"] is True
        assert "200 response" in ev.summary

    def test_detects_stack_traces(self, mocker: MockerFixture) -> None:
        log_output = "Traceback (most recent call last):\n  File app.py\nSQLAlchemyError\n"
        proc = subprocess.CompletedProcess(["docker", "logs"], 0, log_output, "")
        mocker.patch("shieldclaw.observer.target_logs.subprocess.run", return_value=proc)

        obs = TargetLogObserver()
        ev = obs.after_detonate("2026-01-01T00:00:00", 0, "", "", "c1")
        payload = json.loads(ev.payload_json)
        assert payload["has_error"] is True
