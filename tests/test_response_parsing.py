"""Parsing the agent's reply. A response we had to guess at is a response we should refuse."""
import sys, os, types
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
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
