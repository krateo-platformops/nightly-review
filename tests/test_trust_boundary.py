"""The trust boundary, asserted by exercising it.

Everything here is a control that stands between attacker-influenceable text and a pull request. A
control nobody runs is a comment — frontend#334 is the record of what that costs: 1891 tests sat in
the repo while three regressions shipped on one code path, because CI never executed them.
"""
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

import proposals as P


def _p(**over):
    base = {
        "kind": "Alert", "subject": "svc/some-signal", "title": "t", "rationale": "r", "confidence": "medium",
        "evidence": [{"source": "clickhouse", "summary": "s", "observedCount": 9},
                     {"source": "clickhouse", "summary": "s2", "observedCount": 4}],
        "target": {"repo": "org/allowed", "path": "p.yaml"},
        "change": {"format": "yaml", "content": "a: 1"},
    }
    base.update(over)
    return base


NOOP = lambda payload: None


# --- what replaced the allowlist ----------------------------------------------------------------
# Three tests stood here and are deliberately gone rather than rewritten: they asserted that a proposal
# naming a repository outside a per-kind allowlist was refused, marked as a possible injection signal,
# and never publishable. That control has been REMOVED on purpose — publishing moved to the platform's
# own chain, so this service no longer holds the write credential the allowlist existed to bound, and
# every proposal now becomes a pull request a human reads before anything merges.
#
# Deleting a test is the part of a removal that is easy to get wrong, so: what remains below is every
# control that still stands between attacker-influenceable text and a pull request — redaction, the
# confidence cap, the fingerprint, and per-item validation. None of those depended on the allowlist.
# What is NO LONGER asserted anywhere, because it is no longer true, is that the reviewer cannot name
# an arbitrary repository. It can. That is the accepted consequence, not an oversight.


# --- redaction ---------------------------------------------------------------------------------
@pytest.mark.parametrize("secret,marker", [
    ("eyJhbGciOiJIUzI1NiJ9.aaaaaaaaaaaaaaaaaaaaaaaaaa.bbb", "<REDACTED-JWT>"),
    ("AKIAIOSFODNN7EXAMPLE", "<REDACTED-AWS-KEY-ID>"),
    ("ghp_abcdefghijklmnopqrstuvwxyz0123", "<REDACTED-GITHUB-PAT>"),
    ("Bearer abcdefghijklmnopqrstuvwxyz", "Bearer <REDACTED>"),
])
def test_secrets_are_scrubbed_wherever_they_appear(secret, marker):
    """Not only in change.content: the model writes rationale and summary too, so assuming a
    credential could only land in the obvious field assumes away the thing being guarded."""
    out = P.redact({"rationale": secret, "nested": [{"summary": secret}]})
    assert marker in out["rationale"] and secret not in out["rationale"]
    assert marker in out["nested"][0]["summary"]


def test_redaction_reaches_every_field_of_a_real_proposal():
    kept, notes = P.validate_batch(
        {"proposals": [_p(rationale="token eyJhbGciOiJIUzI1NiJ9.aaaaaaaaaaaaaaaaaaaaaaaaaa.ccc")]},
        NOOP)
    assert "eyJ" not in json.dumps(kept)
    assert any("redacted" in n for n in notes)


# --- confidence --------------------------------------------------------------------------------
# These two replace test_high_confidence_from_a_single_observation_is_capped, which asserted a cap that
# #14 removed. They assert the OPPOSITE invariant on purpose: confidence now passes through untouched,
# because the service does not verify it and must not appear to. If someone reintroduces a cap derived
# from model-authored fields, these fail and point at #14.
def test_confidence_passes_through_untouched_even_on_one_observation():
    """#14: the cap was arithmetic on the model's own observedCount, so it tested nothing."""
    kept, notes = P.validate_batch(
        {"proposals": [_p(confidence="high",
                          evidence=[{"source": "kagent-sessions", "summary": "once", "observedCount": 1}])]},
        NOOP)
    assert kept[0]["confidence"] == "high"
    assert not any("capped" in n for n in notes)


def test_a_fabricated_observedcount_cannot_be_what_earns_high():
    """The exact shape that defeated the old cap: one evidence item asserting a huge count.

    It kept `high` under the cap too — that is the point. The cap's `observed < 2` clause was cleared by
    any number the model chose to write, and on the first nine real proposals from 057 the four
    single-evidence ones all carried four-figure counts. Asserting it here keeps the reason the check
    was removed legible, so nobody restores it believing it discriminated."""
    kept, notes = P.validate_batch(
        {"proposals": [_p(confidence="high",
                          evidence=[{"source": "clickhouse", "summary": "s", "observedCount": 900}])]},
        NOOP)
    assert kept[0]["confidence"] == "high"
    assert not any("capped" in n for n in notes)


# The CONTRACT is untouched by #14: an out-of-enum confidence is still rejected per-item. That is
# already asserted by test_a_bad_item_is_dropped_and_its_siblings_survive, which uses
# confidence="very high" as its bad item — not duplicated here.


# --- fingerprint -------------------------------------------------------------------------------
def test_rewording_the_rationale_does_not_change_the_fingerprint():
    """Otherwise night two re-proposes night one under a new identity and dedup silently stops."""
    a = P.fingerprint(_p(rationale="because X"))
    b = P.fingerprint(_p(rationale="a completely different explanation"))
    assert a == b


def test_trailing_whitespace_and_blank_lines_do_not_change_it():
    a = P.fingerprint(_p(change={"format": "yaml", "content": "a: 1\nb: 2"}))
    b = P.fingerprint(_p(change={"format": "yaml", "content": "a: 1  \n\n\nb: 2   "}))
    assert a == b


def test_a_different_target_IS_a_different_proposal():
    a = P.fingerprint(_p())
    b = P.fingerprint(_p(target={"repo": "org/allowed", "path": "other.yaml"}))
    assert a != b


# --- batch semantics ---------------------------------------------------------------------------
def test_an_empty_proposal_list_is_valid_and_not_an_error():
    """Most nights a healthy platform deserves no changes. A loop that must produce something will."""
    kept, notes = P.validate_batch({"proposals": []}, NOOP)
    assert kept == [] and notes == []


def test_a_non_object_response_is_refused_whole():
    with pytest.raises(P.Refused):
        P.validate_batch(["not", "an", "object"], NOOP)


def test_an_unexpected_target_is_kept_verbatim_and_never_rewritten():
    """The allowlist is gone, so an unusual target is no longer refused — but the older guarantee still
    holds and is the one worth keeping: the target is recorded EXACTLY as the model asked for it. A
    silently rewritten target would be far harder to notice than a surprising one, and the pull request
    is where a human sees it."""
    kept, _ = P.validate_batch(
        {"proposals": [_p(), _p(target={"repo": "somewhere/unexpected", "path": "x.yaml"}), _p()]}, NOOP)
    assert len(kept) == 3
    assert [p["target"]["repo"] for p in kept] == ["org/allowed", "somewhere/unexpected", "org/allowed"]


def test_the_shipped_default_still_produces_something_to_read():
    """A fresh install runs dryRun=true, and values.yaml promises a review "you can read". With the
    allowlist removed, dryRun is the ONLY switch: every proposal is kept and fingerprinted so a Proposal
    object exists to read, and nothing opens a pull request because the publisher never runs."""
    kept, notes = P.validate_batch({"proposals": [_p(), _p(title="another")]}, NOOP)
    assert len(kept) == 2
    assert all(p.get("fingerprint") for p in kept)        # each still gets a stable name
    assert not any("REFUSED" in n for n in notes)         # nothing is refused any more


def test_a_bad_item_is_dropped_and_its_siblings_survive():
    """Per-item validation. One wrong enum used to raise over the whole payload and discard the night —
    the cheapest way for an injected instruction to suppress the review entirely."""
    import jsonschema, prompt
    item = lambda p: jsonschema.validate(p, prompt.ITEM_SCHEMA)
    good, bad = _p(), _p(confidence="very high")
    kept, notes = P.validate_batch({"proposals": [good, bad, good]}, NOOP, item_check=item)
    assert len(kept) == 2 and any(n.startswith("DROPPED") for n in notes)
