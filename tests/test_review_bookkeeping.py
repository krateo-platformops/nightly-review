"""The bookkeeping a reviewer is judged by: what it says it redacted, what it treats as the same
suggestion twice, and what it calls an undecided proposal.

Every test here was written to FAIL against the code as it stood, so each one names a defect that was
reasoned about from the source and is now demonstrated rather than asserted."""
import sys, os, types
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


# --- a refused response must leave evidence of itself ------------------------------------------

def test_a_secret_in_an_unusable_response_is_redacted_before_it_is_stored():
    """The diagnostic excerpt is model output over a corpus that has held credentials. Storing it raw
    on a CR, and printing it to a pod log, would be a worse bug than the failure it explains."""
    raw = 'I suggest using token ghp_' + 'a' * 30 + ' and eyJ' + 'b' * 40
    out = P.redact(raw)
    assert "ghp_" not in out and "eyJ" not in out
    assert "<REDACTED-GITHUB-PAT>" in out and "<REDACTED-JWT>" in out


# --- the contract must actually reach the model ------------------------------------------------

def test_the_response_contract_is_sent_to_the_model_not_merely_named():
    """The prompt asked for "a JSON object matching the response contract" and never sent the contract.
    The model invented id/type/description/priority, and per-item validation dropped five real findings
    on 2026-09-28. Naming a schema is not the same as showing it."""
    import prompt as PR
    msg = PR.build_user_message({"from": "2026-01-01T00:00:00Z", "to": "2026-01-02T00:00:00Z"},
                                {"clickhouse": "some rows"})
    for field in PR.ITEM_SCHEMA["required"]:
        assert field in msg, f"contract field {field!r} never reaches the model"
    assert "additionalProperties" in msg, "the rule that discarded five findings is not stated"


def test_the_contract_in_the_prompt_is_the_one_used_for_validation():
    """Rendered from the same object, so it cannot drift from what validate_batch enforces."""
    import json as _json, prompt as PR
    msg = PR.build_user_message({"from": "a", "to": "b"}, {"x": "y"})
    assert _json.dumps(PR.RESPONSE_SCHEMA, indent=1, sort_keys=True) in msg


# --- publishing through the platform's own chain -----------------------------------------------

class _FakeApi:
    def __init__(self): self.created = []
    def create_namespaced_custom_object(self, group, version, ns, plural, body):
        self.created.append((group, version, ns, plural, body)); return body


def test_a_proposal_becomes_a_builderpublish_claim_not_a_github_call():
    """Publishing is a claim to the chain portal-builder and blueprint-builder already use. The service
    holds no GitHub credential any more; git-provider does."""
    api = _FakeApi()
    prop = _prop("replicas: 3\n", repo="krateo-platformops/monitoring", path="alerts/x.yaml")
    prop["fingerprint"] = P.fingerprint(prop)
    prop["title"] = "Alert on x"
    out = publish.create_publish_claim(api, prop, "rr-1", version="v1-8-46")

    (group, version, ns, plural, body) = api.created[0]
    assert (group, plural, version) == ("composition.krateo.io", "builderpublishes", "v1-8-46")
    spec = body["spec"]
    assert spec["builder"] == "review", "a review proposal must not be labelled as a person's blueprint"
    assert spec["repository"]["create"] is False, "a proposal targets a repo that already exists"
    assert spec["target"] == {"namespace": "krateo-platformops", "repo": "monitoring"}
    assert spec["files"] == [{"path": "alerts/x.yaml", "content": "replicas: 3\n"}]
    assert spec["pullRequest"]["create"] is True
    assert out["name"] == spec["name"] == f"review-{prop['fingerprint'][:12]}"


def test_the_claim_name_is_stable_so_the_same_suggestion_reasserts_one_claim():
    """Level-based chain: night two re-asserts the same claim rather than opening a second PR."""
    api = _FakeApi()
    prop = _prop("replicas: 3\n"); prop["fingerprint"] = P.fingerprint(prop); prop["title"] = "t"
    a = publish.create_publish_claim(api, prop, "rr-1", version="v1-8-46")
    b = publish.create_publish_claim(api, prop, "rr-2", version="v1-8-46")
    assert a["name"] == b["name"]


def test_a_malformed_target_repo_fails_loudly_rather_than_publishing_somewhere_odd():
    api = _FakeApi()
    prop = _prop("x: 1\n", repo="not-an-owner-slash-name")
    prop["fingerprint"] = P.fingerprint(prop); prop["title"] = "t"
    with pytest.raises(ValueError):
        publish.create_publish_claim(api, prop, "rr-1", version="v1-8-46")


def test_publish_holds_no_github_surface_any_more():
    """Structural, because the point of the change is the absence of a credential path."""
    import pathlib
    src = pathlib.Path("publish.py").read_text()
    for gone in ("import requests", "GITHUB_TOKEN", "api.github.com", "base64"):
        assert gone not in src, f"{gone!r} still reachable from publish.py"


def test_the_publish_version_is_a_served_one_never_the_storage_version():
    """On 057 the BuilderPublish CRD carries `vacuum` as storage:true / served:false, with no spec
    schema. Preferring storage — the reflex — returns a version the apiserver will not serve, and every
    claim fails with "no matches for kind". This asserts the instrument, because the first version of
    this function picked vacuum."""
    import types as _t
    def crd(vs):
        return _t.SimpleNamespace(spec=_t.SimpleNamespace(versions=[
            _t.SimpleNamespace(name=n, served=s, storage=st) for n, s, st in vs]))
    import kubernetes.client as _kc
    class _FakeExt:
        def __init__(self, vs): self._vs = vs
        def read_custom_resource_definition(self, name): return crd(self._vs)
    orig = _kc.ApiextensionsV1Api
    try:
        _kc.ApiextensionsV1Api = lambda *a, **k: _FakeExt([("vacuum", False, True), ("v1-8-46", True, False)])
        assert publish.publish_version() == "v1-8-46"
        _kc.ApiextensionsV1Api = lambda *a, **k: _FakeExt(
            [("vacuum", False, True), ("v1-8-44", True, False), ("v1-8-46", True, False)])
        assert publish.publish_version() == "v1-8-46", "newest served version, not list order"
    finally:
        _kc.ApiextensionsV1Api = orig


# --- the run tells the truth about its own evidence ---------------------------------------------

def test_an_unwindowed_query_is_refused_rather_than_run(monkeypatch):
    """The window is a safety control: spans older than the collector's JWT redaction can still carry
    live credentials, so an unbounded scan is a disclosure risk, not just a slow query."""
    import evidence as E
    monkeypatch.setattr(E, "CLICKHOUSE_URL", "http://clickhouse.invalid")
    called = []
    monkeypatch.setattr(E, "requests", types.SimpleNamespace(
        post=lambda *a, **k: called.append(k) or (_ for _ in ()).throw(AssertionError("must not run"))))
    body, stats = E.clickhouse({"unbounded": "SELECT 1 FROM otel_logs"},
                               {"from": "A", "to": "B"})
    assert called == [], "an unwindowed query must never reach ClickHouse"
    assert stats["ok"] is False and "refused" in stats["error"]


def test_truncation_is_recorded_on_the_run_not_only_marked_in_the_corpus():
    import evidence as E
    stats = {}
    out = E._cap("x" * (E.MAX_CHARS + 500), stats)
    assert stats["truncated"] is True
    assert stats["droppedChars"] == 500
    assert "truncated at" in out, "the model should still be told its evidence was cut"


def test_an_untruncated_source_records_nothing():
    import evidence as E
    stats = {}
    E._cap("short", stats)
    assert "truncated" not in stats


def test_the_denylist_covers_the_families_it_was_missing():
    """THE FIXTURES ARE ASSEMBLED FROM FRAGMENTS, not written out, and each carries a gitleaks:allow.

    Writing them literally is what a test for a secret scanner naturally looks like, and it failed CI
    the first time for exactly the right reason: Gitleaks scans this repository and these strings are
    shaped like credentials. They are invented, and none is real — but "trust me, it is fake" is not
    something a scanner can check, and switching the scanner off for this path would trade a real
    control for a test. Fragments plus a per-line allow keeps the scan intact and the intent legible."""
    cases = [
        ("gl" + "pat-" + "a" * 24, "<REDACTED-GITLAB-PAT>"),                      # gitleaks:allow
        ("xo" + "xb-" + "1" * 12 + "-" + "abcdefghijkl", "<REDACTED-SLACK-TOKEN>"),  # gitleaks:allow
        ("AI" + "za" + "B" * 35, "<REDACTED-GOOGLE-API-KEY>"),                    # gitleaks:allow
        ("api" + "_key=" + "abcd1234efgh", "<REDACTED>"),                         # gitleaks:allow
        ("client" + "_secret: " + "verysecretvalue123", "<REDACTED>"),            # gitleaks:allow
    ]
    for raw, marker in cases:
        assert marker in P.redact(raw), f"{raw[:20]!r} survived redaction"
    secret = "s3cret" + "pw"                                                      # gitleaks:allow
    url = P.redact(f"postgres://user:{secret}@db.internal:5432/x")
    assert secret not in url and "db.internal" in url, "redact the password, keep the host readable"


# --- the window bound ClickHouse can actually index ---------------------------------------------

def test_the_sql_window_is_a_plain_datetime_not_iso():
    """Measured on 057: the ISO literal the run records takes 167s against a 120s read timeout, because
    ClickHouse cannot range-prune a DateTime64 column compared to '...T...+00:00'. The plain form takes
    15.7s. This is the whole of issue #20."""
    import evidence as E
    assert E._ch_time("2026-09-27T14:17:43.745807+00:00") == "2026-09-27 14:17:43"
    assert E._ch_time("2026-09-27T14:17:43+00:00") == "2026-09-27 14:17:43"
    assert E._ch_time("2026-09-27T14:17:43") == "2026-09-27 14:17:43"


def test_an_unparseable_window_is_passed_through_rather_than_guessed():
    import evidence as E
    assert E._ch_time("not-a-time") == "not-a-time"


def test_the_substituted_query_carries_the_plain_form(monkeypatch):
    import evidence as E
    seen = {}
    class _R:
        status_code = 200; text = "a\nb"
        def raise_for_status(self): pass
    def fake_post(url, data=None, **k):
        seen["sql"] = data; return _R()
    monkeypatch.setattr(E, "CLICKHOUSE_URL", "http://ch.invalid")
    monkeypatch.setattr(E, "requests", types.SimpleNamespace(post=fake_post))
    E.clickhouse({"q": "SELECT 1 WHERE Timestamp BETWEEN '{from}' AND '{to}' LIMIT 1"},
                 {"from": "2026-09-27T14:17:43.745807+00:00", "to": "2026-09-28T14:17:43.745807+00:00"})
    assert "2026-09-27 14:17:43" in seen["sql"], seen["sql"]
    assert "T14:17:43.745807" not in seen["sql"]


def test_a_naive_window_bound_is_not_shifted_by_the_machines_timezone():
    """astimezone() on a naive datetime assumes LOCAL time. The first version of _ch_time did that and
    slid the window by the host's offset — two hours on the machine it was written on. A window that is
    quietly wrong is worse than the slow query this function exists to fix."""
    import evidence as E
    assert E._ch_time("2026-09-27T14:17:43") == "2026-09-27 14:17:43"
    assert E._ch_time("2026-09-27T14:17:43.500000") == "2026-09-27 14:17:43"


def test_an_offset_window_bound_is_converted_to_utc():
    import evidence as E
    assert E._ch_time("2026-09-27T16:17:43+02:00") == "2026-09-27 14:17:43"


def test_the_contract_no_longer_asks_the_model_for_a_query():
    """The field existed to make a proposal checkable and was the one field the model invented — the
    first real proposals cited SQL with no window clause that matched nothing this service ran. The
    service records what it issued; a paraphrase beside it is worse than its absence."""
    import prompt as PR
    ev = PR.ITEM_SCHEMA["properties"]["evidence"]["items"]
    assert "query" not in ev["properties"], "the model can still author a query"
    assert ev["additionalProperties"] is False, "without this the model could add it back anyway"
    msg = PR.build_user_message({"from": "a", "to": "b"}, {"clickhouse": "rows"})
    assert "Carry the query that produced it" not in msg


# --- kagent sessions from Postgres ------------------------------------------------------------------
# The API implementation this replaced could only ever return the caller's own sessions, of which this
# service has none, so it reported `empty` with a note every night. These assert the properties that
# make the replacement safe, not that it returns rows — which needs a database.
def test_kagent_sessions_refuses_without_credentials():
    """Not-configured is an ERROR, not a quiet skip: it must show up as degradation on the run."""
    import importlib, evidence
    importlib.reload(evidence)
    evidence.KAGENT_DB_USER = ""
    evidence.KAGENT_DB_PASSWORD = ""
    body, stats = evidence.kagent_sessions({"from": "2026-01-01 00:00:00", "to": "2026-01-02 00:00:00"})
    assert body is None
    assert stats["ok"] is False and "not configured" in stats["error"]


def test_kagent_sessions_never_emits_user_ids():
    """The corpus reaches a model and then a pull request body, so identities must not be in it.

    Asserted against the SQL rather than a result set: the query selects count(DISTINCT user_id) and
    must never select user_id itself. If someone adds it for 'a bit more context', this fails."""
    from evidence import SESSION_SQL
    assert "count(DISTINCT user_id)" in SESSION_SQL
    assert "user_id" not in SESSION_SQL.replace("count(DISTINCT user_id)", "")


def test_kagent_sessions_query_excludes_soft_deleted():
    """kagent soft-deletes. Without this the source returns sessions users deleted."""
    from evidence import SESSION_SQL
    assert "deleted_at IS NULL" in SESSION_SQL


def test_kagent_sessions_query_reads_only_the_session_table():
    """The grant is the real enforcement, but the query must not even ask for content tables."""
    from evidence import SESSION_SQL as sql
    for forbidden in ("event", "task", "feedback", "lg_checkpoint"):
        assert f"FROM {forbidden}" not in sql and f"JOIN {forbidden}" not in sql
