"""The bookkeeping a reviewer is judged by: what it says it redacted, what it treats as the same
suggestion twice, and what it calls an undecided proposal.

Every test here was written to FAIL against the code as it stood, so each one names a defect that was
reasoned about from the source and is now demonstrated rather than asserted."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import proposals as P
import publish


def _prop(content, kind="Documentation", repo="krateo-platformops/installer", path="README.md"):
    return {"kind": kind, "title": "t", "rationale": "r", "confidence": "low",
            "evidence": [], "target": {"repo": repo, "path": path},
            "change": {"format": "yaml", "content": content}}


# --- #4: a function named `count` that cannot count -------------------------------------------

def test_redaction_count_reports_how_many_not_merely_whether():
    """It returned a bool from a name promising a number, so one redaction and three were
    indistinguishable — and the docstring's promise (a run SAYS what it scrubbed) could not be kept."""
    one = {"a": "token: " + "A" * 60}
    three = {"a": "token: " + "A" * 60, "b": "ghp_" + "b" * 30, "c": "eyJ" + "c" * 40}
    assert P.redaction_count(one, P.redact(one)) == 1
    assert P.redaction_count(three, P.redact(three)) == 3


def test_redaction_count_is_zero_when_nothing_fired():
    clean = {"a": "nothing secret here"}
    assert P.redaction_count(clean, P.redact(clean)) == 0


def test_redaction_count_is_an_int_not_a_bool():
    """bool is a subclass of int, so `== 1` alone would not have caught the original."""
    v = P.redaction_count({"a": "x"}, {"a": "x"})
    assert not isinstance(v, bool)


# --- #6: dedup that does not dedup ------------------------------------------------------------

def test_a_reworded_comment_is_the_same_suggestion():
    """The model rewords its prose every night. If a comment change makes a new fingerprint, night two
    re-proposes night one and the reviewer stops reading — the exact outcome the docstring fears."""
    a = _prop("# bump the replica count\nreplicas: 3\n")
    b = _prop("# increase replicas to three\nreplicas: 3\n")
    assert P.fingerprint(a) == P.fingerprint(b)


def test_reordered_yaml_keys_are_the_same_suggestion():
    a = _prop("replicas: 3\nimage: nginx\n")
    b = _prop("image: nginx\nreplicas: 3\n")
    assert P.fingerprint(a) == P.fingerprint(b)


def test_a_genuinely_different_change_is_a_different_suggestion():
    """The normalisation must not collapse everything into one bucket."""
    a = _prop("replicas: 3\n")
    b = _prop("replicas: 4\n")
    assert P.fingerprint(a) != P.fingerprint(b)


def test_the_same_body_aimed_at_a_different_file_is_a_different_suggestion():
    a = _prop("replicas: 3\n", path="a.yaml")
    b = _prop("replicas: 3\n", path="b.yaml")
    assert P.fingerprint(a) != P.fingerprint(b)


# --- #6b: superseded was hardcoded 0 ----------------------------------------------------------

def test_a_changed_proposal_for_the_same_target_supersedes_rather_than_duplicates():
    """Same kind/repo/path, different body: night one is stale, not a duplicate. Counting it as either
    `deduplicated` or `created` loses the fact that an open proposal was replaced."""
    old = _prop("replicas: 3\n")
    new = _prop("replicas: 5\n")
    index = {P.target_key(old): {"fingerprint": P.fingerprint(old), "name": "p-old"}}
    assert P.classify(new, {}, index) == ("supersede", "p-old")


def test_an_identical_proposal_is_deduplicated_not_superseded():
    old = _prop("replicas: 3\n")
    by_fp = {P.fingerprint(old): "p-old"}
    index = {P.target_key(old): {"fingerprint": P.fingerprint(old), "name": "p-old"}}
    assert P.classify(old, by_fp, index) == ("dedup", "p-old")


def test_an_unseen_proposal_is_new():
    assert P.classify(_prop("replicas: 3\n"), {}, {}) == ("new", None)


# --- #7: a bare-string contract in two files --------------------------------------------------

def test_the_open_phases_are_one_shared_constant():
    """`open_fingerprints` matched literals written elsewhere in the same module. They agreed, but a
    rename in one place would have silently re-proposed everything, with no error anywhere."""
    assert publish.OPEN_PHASES == frozenset({None, publish.PHASE_PROPOSED, publish.PHASE_PR_OPEN})


def test_every_phase_the_publisher_writes_is_declared_in_the_crd_enum():
    """The apiserver rejects an undeclared phase, and it rejects it at WRITE time — long after the
    review has been done and paid for."""
    import re, pathlib
    crd = pathlib.Path("helm/nightly-review-crds/templates/proposal.crd.yaml").read_text()
    m = re.search(r"phase:\s*\n\s*type: string\s*\n\s*enum: \[([^\]]+)\]", crd)
    declared = set(m.group(1).replace(" ", "").split(","))
    assert publish.WRITTEN_PHASES <= declared, publish.WRITTEN_PHASES - declared
