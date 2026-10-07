"""The contract between the compositions evidence, the prompt and the blueprint registry.

A finding about a blueprint only reaches that blueprint's source repository if three things agree on one
string: how failures.py SPELLS a blueprint in the evidence, how prompt.py tells the model to spell the
subject's component, and how targets.py KEYS the registry it looks the component up in. Nothing checked
that before #44, and they disagreed by the word "blueprint" — so every blueprint finding ever produced was
dropped with TargetResolved=False/NoDestination.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import failures as F
import proposals as P
import targets as T

POLICY = {"orgs": ["krateo-blueprints"], "pathPrefix": "proposals"}
FOUND = {"meetup-site": "krateo-blueprints/meetup-site"}


def _evidence_component(name):
    """The component a model obeying prompt.py would write, derived from the evidence line itself."""
    text = F._blueprint_text({"name": name, "namespace": "krateo-system", "url": "oci://x", "version": "0.3.0"},
                             {}, {})
    assert text.startswith(f"blueprint {name} ("), text
    return P.normalise_subject(f"{text.split(' (')[0]}/x").partition("/")[0]


def test_the_registry_key_is_the_component_the_evidence_produces():
    """The contract. If this fails, no blueprint finding can resolve a destination."""
    T.register_blueprints(FOUND, POLICY)
    assert T.blueprint_component("meetup-site") == _evidence_component("meetup-site")
    assert _evidence_component("meetup-site") in T.register_blueprints(FOUND, POLICY)


def test_a_blueprint_finding_lands_in_the_blueprint_repository(monkeypatch):
    # pathPrefix is read from the module-level policy, not from register_blueprints' argument.
    monkeypatch.setattr(T, "BLUEPRINT_POLICY", POLICY)
    T.register_blueprints(FOUND, POLICY)
    repo, path, source = T.destination(
        {"kind": "Documentation",
         "subject": f"{_evidence_component('meetup-site')}/cpu-request-exceeds-limit",
         "target": {"path": "resource-configuration.md"}},
        destinations={}, components={})
    assert repo == "krateo-blueprints/meetup-site", (repo, source)
    assert path == "proposals/resource-configuration.md"
    assert "blueprint" in source


def test_both_spellings_resolve_so_nothing_that_worked_stops_working():
    """The evidence spelling is the one real proposals carry; the bare name is what the registry always
    held. Both must find the blueprint — the fix adds a lookup, it does not move one."""
    reg = T.register_blueprints(FOUND, POLICY)
    assert set(reg) == {"blueprint-meetup-site", "meetup-site"}
    for subject in ("blueprint-meetup-site/cpu-request-exceeds-limit", "meetup-site/cpu-request-exceeds-limit"):
        repo, _, _ = T.destination({"kind": "Documentation", "subject": subject, "target": {}},
                                   destinations={}, components={})
        assert repo == "krateo-blueprints/meetup-site", subject


def test_a_prompt_proposal_still_never_derives_a_blueprint_repository():
    T.register_blueprints(FOUND, POLICY)
    repo, _, why = T.destination(
        {"kind": "Prompt", "subject": f"{_evidence_component('meetup-site')}/x", "target": {}},
        destinations={}, components={})
    assert repo is None, why


def test_an_org_outside_the_policy_derives_nothing():
    assert T.register_blueprints({"other": "someone-else/other"}, POLICY) == {}
