"""A run the Job kills (activeDeadlineSeconds, eviction) is recorded Failed, never left Running."""
import signal

import pytest

import main


class _Api:
    def __init__(self):
        self.writes = []

    def patch_namespaced_custom_object_status(self, group, version, ns, plural, name, body):
        self.writes.append((name, body))


def test_sigterm_records_the_run_and_its_running_step_as_failed():
    api = _Api()
    st = {"phase": "Running", "steps": [
        {"name": "gather", "phase": "Succeeded"},
        {"name": "analyse", "phase": "Running", "startedAt": "2026-09-30T02:00:00+00:00"},
    ]}
    previous = signal.getsignal(signal.SIGTERM)
    try:
        main._on_terminate(api, "rr-x", st)
        with pytest.raises(SystemExit) as exit_:
            signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
    finally:
        signal.signal(signal.SIGTERM, previous)
    assert exit_.value.code == 143
    (name, body), = api.writes
    status = body["status"]
    assert name == "rr-x" and status["phase"] == "Failed" and "activeDeadlineSeconds" in status["error"]
    assert [s["phase"] for s in status["steps"]] == ["Succeeded", "Failed"]
    assert status["finishedAt"]
