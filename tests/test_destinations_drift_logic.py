"""Offline tests of drift/destinations_drift.py — the logic the drift workflow runs against the installer's
live pins. Each case is one way the seeded destination map can go stale without anything failing."""
import os
import sys
import types

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "drift"))

import destinations_drift as D

DEFAULT = "oci://ghcr.io/krateo-platformops/charts"
PINS = [{"name": "snowplow"}, {"name": "autopilot-x", "repo": "oci://ghcr.io/krateo-agentiko/charts"},
        {"name": "cert-manager", "repo": "oci://ghcr.io/krateo-blueprints/charts"}]
COMPS = {"snowplow": {"repo": "krateo-platformops/snowplow"},
         "autopilot-x": {"repo": "krateo-agentiko/autopilot",
                         "prompt": {"repo": "krateo-agentiko/autopilot", "path": "p.yaml"}}}
UNMAPPED = {"cert-manager": "upstream"}


def test_in_step_is_no_problem():
    assert D.problems(PINS, DEFAULT, COMPS, UNMAPPED) == []


def test_a_new_pin_fails_and_says_what_to_add():
    found = D.problems(PINS + [{"name": "new-thing", "repo": "oci://ghcr.io/krateo-agentiko/charts"}],
                       DEFAULT, COMPS, UNMAPPED)
    (msg,) = found
    assert "config.destinations.components.new-thing" in msg and "drift/unmapped-components.yaml" in msg


def test_a_default_registry_pin_without_an_entry_fails():
    (msg,) = D.problems(PINS + [{"name": "plain"}], DEFAULT, COMPS, UNMAPPED)
    assert "plain (published from the default registry) has no destination" in msg and "krateo-platformops" in msg


@pytest.mark.parametrize("field", ["repo", "prompt"])
def test_an_entry_in_the_wrong_org_fails(field):
    comps = {k: dict(v) for k, v in COMPS.items()}
    if field == "repo":
        comps["autopilot-x"]["repo"] = "krateo-platformops/autopilot"
    else:
        comps["autopilot-x"]["prompt"] = {"repo": "krateo-blueprints/autopilot", "path": "p.yaml"}
    (msg,) = D.problems(PINS, DEFAULT, comps, UNMAPPED)
    assert "autopilot-x" in msg and "from krateo-agentiko" in msg


def test_a_default_registry_pin_is_compared_with_the_default_org():
    comps = dict(COMPS, snowplow={"repo": "krateo-agentiko/snowplow"})
    (msg,) = D.problems(PINS, DEFAULT, comps, UNMAPPED)
    assert "snowplow.repo is krateo-agentiko/snowplow" in msg and "from krateo-platformops" in msg


def test_the_allowlist_is_checked_both_ways():
    found = D.problems(PINS, DEFAULT, dict(COMPS, **{"cert-manager": {"repo": "krateo-blueprints/x"}}),
                       dict(UNMAPPED, gone="was pinned once", **{"autopilot-x": ""}))
    assert any("cert-manager has a destination AND a reason" in m for m in found)
    assert any("gone is in drift/unmapped-components.yaml but the installer no longer pins it" in m for m in found)
    assert any("autopilot-x is in drift/unmapped-components.yaml without a reason" in m for m in found)


def test_an_unparseable_default_registry_is_a_problem():
    assert any("ociRepo" in m for m in D.problems(PINS, "ghcr.io/x", COMPS, UNMAPPED))


@pytest.mark.parametrize("resp", [OSError("dns"), types.SimpleNamespace(status_code=404, text="")])
def test_a_failed_fetch_fails_it_never_skips(resp, monkeypatch):
    def get(url, **k):
        if isinstance(resp, Exception):
            raise resp
        return resp
    monkeypatch.setattr(D, "requests", types.SimpleNamespace(get=get))
    with pytest.raises(RuntimeError, match="does not pass without them"):
        D.load_installer()


def test_the_repo_files_parse_and_every_reason_is_written():
    components, unmapped = D.load_local()
    assert components and unmapped
    assert all(isinstance(r, str) and r.strip() for r in unmapped.values())


def test_the_not_pinned_record_has_reasons_and_contradicts_no_entry():
    assert D.not_pinned_problems() == []


def test_a_not_pinned_glob_matching_a_mapped_key_is_a_contradiction(monkeypatch, tmp_path):
    f = tmp_path / "u.yaml"
    f.write_text("unmapped: {}\nnotPinned:\n  '*-agent': covers too much\n  bare: ''\n")
    monkeypatch.setattr(D, "ALLOWLIST", f)
    found = D.not_pinned_problems()
    assert any("installer-agent has a destination but matches notPinned" in m for m in found)
    assert any("bare is in drift/unmapped-components.yaml notPinned without a reason" in m for m in found)
