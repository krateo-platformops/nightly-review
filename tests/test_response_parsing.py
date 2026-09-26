"""Parsing the agent's reply. A response we had to guess at is a response we should refuse."""
import sys, os, types
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import importlib.util
# Stub ONLY when requests is genuinely absent. An unconditional stub shadowed the real
# package, and anything importing the kubernetes client (which imports requests.utils) then
# failed to collect — so a test file could break its neighbours purely by import order.
if importlib.util.find_spec("requests") is None:
    sys.modules.setdefault("requests", types.ModuleType("requests"))

import pytest
import autopilot as A


def test_bare_json_is_accepted():
    assert A.extract_json('{"proposals": []}') == {"proposals": []}


def test_a_fenced_object_is_accepted_because_models_fence_anyway():
    assert A.extract_json('here you go\n```json\n{"proposals": []}\n```\n') == {"proposals": []}


def test_prose_around_the_object_is_tolerated():
    assert A.extract_json('I reviewed it.\n{"proposals": []}\nHope that helps.') == {"proposals": []}


@pytest.mark.parametrize("bad", ['', '   ', 'no json here', '{"proposals": ', '}{'])
def test_malformed_is_refused_never_repaired(bad):
    with pytest.raises((ValueError, Exception)):
        A.extract_json(bad)


def test_the_context_id_is_stable_per_run_and_distinct_across_runs():
    """One thread per run. Dedup is done deterministically by fingerprint in code, so correctness
    never depends on the model remembering what it proposed last night."""
    assert A.context_id("rr-1") == A.context_id("rr-1")
    assert A.context_id("rr-1") != A.context_id("rr-2")


class _Endless:
    """A stream that never stops talking. This is the 02:00 run: the agent delegated, kept calling
    tools, and emitted a `working` event well inside any per-read timeout — forever."""
    def __init__(self):
        self.closed = False
        self.emitted = 0

    def raise_for_status(self):
        pass

    def close(self):
        self.closed = True

    def iter_lines(self, decode_unicode=False):
        while True:
            self.emitted += 1
            yield 'data: {"result": {"status": {"state": "working"}}}'


def test_a_stream_that_never_ends_is_cut_off_by_the_total_budget(monkeypatch):
    """The bug this guards: requests' timeout on a streaming response bounds SILENCE, not duration,
    so a chatty runaway task was unbounded. ask() must return control, and say why."""
    stream = _Endless()
    monkeypatch.setattr(A, "requests", types.SimpleNamespace(post=lambda *a, **k: stream))
    monkeypatch.setattr(A, "A2A_TIMEOUT", 0)

    with pytest.raises(ValueError) as err:
        A.ask("sys", "msg", "rr-endless")

    assert "deadline exceeded" in str(err.value)
    assert "0s" in str(err.value)
    assert stream.closed, "the response must be closed, not left dangling"


def test_the_read_timeout_is_separate_from_the_total_budget():
    """Two clocks, two knobs. Collapsing them back into one re-opens the overrun."""
    assert A.A2A_READ_TIMEOUT < A.A2A_TIMEOUT


def test_a_normal_answer_is_unaffected_by_the_deadline(monkeypatch):
    """The cutoff must not cost anything on the path that already worked."""
    lines = ['data: {"result": {"status": {"state": "submitted"}}}',
             'data: {"result": {"status": {"state": "working"}}}',
             'data: {"result": {"status": {"state": "completed", "message": {"parts": '
             '[{"kind": "text", "text": "{\\"proposals\\": []}"}]}}}}']
    resp = types.SimpleNamespace(raise_for_status=lambda: None, close=lambda: None,
                                 iter_lines=lambda decode_unicode=False: iter(lines))
    monkeypatch.setattr(A, "requests", types.SimpleNamespace(post=lambda *a, **k: resp))

    obj, raw, usage = A.ask("sys", "msg", "rr-ok")
    assert obj == {"proposals": []}
