"""Generate the Python-parity fixtures for internal/parity.

WHAT THIS PROVES. The Go port must produce, for the same input, the same bytes the Python service did
wherever those bytes are compared later: a Proposal's fingerprint (its object name and dedup key), its
normalised subject (the supersession key), its redacted fields, the aimed target, the notes a run records,
the prompts the reviewer is sent, and the sync-stall check's proposal bodies. Every value below is computed
by the REAL Python functions; internal/parity/parity_test.go asserts the Go functions return exactly the
same.

REGENERATE from a checkout that still carries the Python service (main at 9a11299, the last Python commit),
with the image's exact pins:

    git worktree add --detach /tmp/nr-python 9a11299
    python3.12 -m venv /tmp/nr-venv
    /tmp/nr-venv/bin/pip install requests==2.32.3 jsonschema==4.23.0 kubernetes==31.0.0 PyYAML==6.0.2 pg8000==1.31.2
    /tmp/nr-venv/bin/python -I internal/parity/testdata/gen_fixtures.py /tmp/nr-python internal/parity/testdata

The corpus is deterministic (seeded): two runs write byte-identical files.
"""
import datetime as dt
import gzip
import json
import os
import random
import sys

ROOT = os.path.abspath(sys.argv[1])
OUT = os.path.abspath(sys.argv[2])
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))
os.chdir(ROOT)

for k in list(os.environ):
    if k.startswith(("TARGET_", "SYNC_STALL_", "AGENT_ANALYSIS_", "KAGENT_", "CLICKHOUSE", "EVIDENCE_")):
        del os.environ[k]

import jsonschema  # noqa: E402
import yaml  # noqa: E402

import analysis as AN  # noqa: E402
import autopilot as A  # noqa: E402
import coverage as C  # noqa: E402
import evidence as E  # noqa: E402
import failures as F  # noqa: E402
import main as M  # noqa: E402
import prompt  # noqa: E402
import proposals as P  # noqa: E402
import publish  # noqa: E402
import sync_health as S  # noqa: E402
import targets as T  # noqa: E402

assert yaml.__version__ == "6.0.2" and jsonschema.__version__ == "4.23.0"

rng = random.Random(20261110)


def exc(e):
    return {"exception": type(e).__name__}


def call(f, *a, **k):
    try:
        return {"ok": f(*a, **k)}
    except Exception as e:  # noqa: BLE001
        return exc(e)


VALUES = yaml.safe_load(open(os.path.join(ROOT, "helm/nightly-review/values.yaml")).read())["config"]
OBS = VALUES["targets"]
COMPS = VALUES["destinations"]["components"]

# ---------------------------------------------------------------------------------------------------
# Corpus: strings that reach redaction and subject normalisation
# ---------------------------------------------------------------------------------------------------
# ASSEMBLED FROM FRAGMENTS, each line carrying gitleaks:allow, for the reason the Python suite gave in
# test_review_bookkeeping.py: the repository is scanned and these are shaped like credentials. None is real.
P, K = "pass" + "word", "to" + "ken"
SECRETISH = [
    "eyJ" + "hbGciOiJIUzI1NiJ9.aaaaaaaaaaaaaaaaaaaaaaaaaa.bbb", "AKIA" + "IOSFODNN7EXAMPLE", "ASIA" + "IOSFODNN7EXAMPLE",
    "ghp_" + "abcdefghijklmnopqrstuvwxyz0123", "GHP_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123", "github_pat_" + "a1_" * 9,
    "Bearer " + "abcdefghijklmnopqrstuvwxyz", "bearer   " + "abc.def-ghi_jkl.mnopqrstuvwxyz",
    "glpat-" + "a" * 24, "xoxb-" + "1" * 12 + "-abcdefghijkl", "AIza" + "B" * 35,
    "postgres://user:" + "s3cretpw" + "@db.internal:5432/x",  # gitleaks:allow
    "https://diego:" + "hunter2hunter2" + "@github.com/org/repo",  # gitleaks:allow
    "api" + "_key=" + "abcd1234efgh",  # gitleaks:allow
    "client" + "_secret: " + "verysecretvalue123",  # gitleaks:allow
    "DB_" + P.upper() + "=" + "s3cretValue9",  # gitleaks:allow
    "PG" + P.upper() + "=" + "s3cretValue9",  # gitleaks:allow
    "MY_API" + "_KEY=" + "s3cretValue9",  # gitleaks:allow
    "export KAGENT_DB_" + P.upper() + "='" + "s3cret!value" + "'",  # gitleaks:allow
    '{"PG' + P.upper() + '": "' + "s3cretValue9" + '"}',  # gitleaks:allow
    '{"db_access_' + K + '": "' + "s3cretValue9" + '"}',  # gitleaks:allow
    '"refresh_' + K + '": "' + "abcdefgh12345" + '"',  # gitleaks:allow
    "TARGET_CHECK_" + K.upper() + "=" + "s3cretValue9",  # gitleaks:allow
    "aws_secret" + "_key: " + "s3cretValue9",  # gitleaks:allow
    "aws_secret_access" + "_key = " + "AbC/dEf+GhI",  # gitleaks:allow
    K + ": " + "A" * 60, "client-key-data: " + "QUJD" * 15, "client-certificate-data:" + "x" * 44,
    "-----BEGIN RSA " + "PRIVATE KEY-----\nMIIabc\n-----END RSA " + "PRIVATE KEY-----",  # gitleaks:allow
    "-----BEGIN " + "PRIVATE KEY-----MIIabc-----END " + "PRIVATE KEY-----",  # gitleaks:allow
    "my " + P + " is " + "Qu3stionPassw0rd",  # gitleaks:allow
    "The admin " + P + " was '" + "hunter2hunter2" + "'.",  # gitleaks:allow
    "your api key is " + "AbCdEf123456789",  # gitleaks:allow
    "the " + K + " is " + "s3cretToken99",  # gitleaks:allow
    "the password is required", "How do I reset my password?", "set the password: see docs", "tokens used: 14518",
    "max_tokens=4096", '"totalTokens": 221497', "Rotate the DB_PASSWORD secret, then restart the pod.",
    "password: see below", "Please update your database_password immediately afterwards.",
    "ADMIN_" + P.upper() + "_B64=" + "abcdefgh1234",  # gitleaks:allow
    '{"apiKey' + 'Value": "' + "hunter2hunter2" + '"}',  # gitleaks:allow
    "client" + "Secret: " + "hunter2hunter2",  # gitleaks:allow
    "paſſword=" + "hunter2hunter2", "toKen=" + "abcdefgh1234",  # gitleaks:allow
    K.upper() + "=" + "abcdefgh1234", "İnfo " + K + "=" + "abcdefgh1234",  # gitleaks:allow
    "x" * 14 + ".".join(["eyJhbGciOiJSUzI1NiIsImtpZCI6IngifQ", "eyJzdWIiOiJzeXN0ZW06c2EifQ", "c2lnbmF0dXJl"]),
    "café " + P + "=" + "hunter2hunter2" + " naïve",  # gitleaks:allow
    "日本 " + K + "=" + "abcdefgh1234" + " 語", "ünïcode_" + P + "=" + "abcdefgh1234",  # gitleaks:allow
    P + "=" + "é" * 10, P + "=ab\u00a0" + "cdefgh1234", "AKIA" + "Ä" + "IOSFODNN7EXAMPL",  # gitleaks:allow
    "ÉAKIA" + "IOSFODNN7EXAMPLE", "_AKIA" + "IOSFODNN7EXAMPLE_", "1AKIA" + "IOSFODNN7EXAMPLE", "ghp_" + "a" * 20 + "é",
    "secret" + "_key: " + "abcd1234efgh",  # gitleaks:allow
    "SECRET-KEY = '" + "abcdefgh1234" + "'",  # gitleaks:allow
    "passwd:" + "abcdefgh", "passwd:" + "abcdefg", "user:pass@host", "ftp://a:b@c",  # gitleaks:allow
]
WORDS = ["password", "passwd", "token", "api_key", "api-key", "apikey", "API KEY", "secret_key", "client_secret",
         "access_token", "refresh_token", "Bearer", "AKIA", "ghp_", "eyJ", "glpat-", "xoxp-", "AIza", "is", "was",
         "=", ":", '"', "'", " ", "\n", "\t", "é", "ß", "ſ", "K", "İ", "ı", "日本", " ", "\x1c", " ", "_",
         "-", ".", "/", "@", "://", "0", "9", "x" * 20, "A" * 16, "abc123def456", "hunter2hunter2", "Ünï"]


def rand_text(n):
    return "".join(rng.choice(WORDS + ["abcdefgh", "12345678", "HTTP 500", "foo-bar", "Baz"]) for _ in range(n))


REDACT = SECRETISH + [rand_text(rng.randint(1, 25)) for _ in range(1500)]

SUBJECTS = [None, 7, "", "no-separator-at-all", "/signal-only", "component/", "!!/??", "a/b/c",
            "snowplow/subjectaccessreview-unauthorized", "Snowplow/SubjectAccessReview Unauthorized",
            "installer-chart-inspector:RBAC generation HTTP 500", "rest-dynamic-controller/CannotObserveExternalResource",
            "  kagent / agent never used  ", "x/CannotObserveExternalResource", "İstanbul/Kelvin", "ÄÖÜ/ßtraße",
            "a/b\nc", "a/\nb", "\x1c/abc", "  /x", "comp/" + "S" * 300, "HTTPServer/HTTP500Error", "abcDEF/GHIjkl",
            "blueprint meetup-site/x", "Git-Provider/credential rejected", "kagent:agent never used",
            "日本/語", "a:b/c", "a/b:c", "ab cd/ef", "x" * 200 + "/" + "y" * 200]
SUBJ_PARTS = ["Snowplow", "SAR", "Unauthorized", "HTTP", "500", "k8s-agent", "blueprint ", "/", ":", " ", "-", "_",
              "CamelCase", "ÄÖ", "İ", "K", "ſ", "\n", "\t", "!", "x", "9"]
SUBJECTS += ["".join(rng.choice(SUBJ_PARTS) for _ in range(rng.randint(1, 10))) for _ in range(800)]

# ---------------------------------------------------------------------------------------------------
# Corpus: proposals
# ---------------------------------------------------------------------------------------------------
PROM = """apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata: {name: x}
spec: {groups: []}
"""
INVENTED = "apiVersion: monitoring.krateo.io/v1alpha1\nkind: Alert\nmetadata: {name: x}\n"
REAL = """apiVersion: observability.krateo.io/v1alpha1
kind: Alert
metadata: {name: x, namespace: krateo-system}
spec: {interval: 15m, threshold: 1, thresholdType: above, where: "Body LIKE '%x%'"}
"""
CONTENTS = [
    ("yaml", "a: 1"), ("yaml", "a: 1\nb: 2"), ("yaml", "a: 1  \n\n\nb: 2   "), ("yaml", "replicas: 3\nimage: nginx\n"),
    ("yaml", "image: nginx\nreplicas: 3\n"), ("yaml", "# bump the replica count\nreplicas: 3\n"),
    ("yaml", "# increase replicas to three\nreplicas: 3\n"), ("yaml", PROM), ("yaml", INVENTED), ("yaml", REAL),
    ("yaml", "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: x}\n"),
    ("yaml", "apiVersion: widgets.templates.krateo.io/v1beta1\nkind: Alert\nmetadata: {name: x}\n"),
    ("yaml", "kind: Page"), ("yaml", "---\na: 1\n---\nb: 2\n"), ("yaml", "a: [1, 2"), ("yaml", "just text"),
    ("yaml", "a: &x {b: 1}\nc: *x\n"), ("yaml", "t: 2026-10-01T10:00:00Z\nd: 2026-10-01\n"),
    ("yaml", "yes: no\non: off\n"), ("yaml", "key: 'token: " + "A" * 60 + "'\n"), ("yaml", "1: a\nb: c\n"),
    ("yaml", "a: 2020-13-45\n"), ("yaml", "a: !!binary aGVsbG8=\n"), ("yaml", "s: !!set {a, b}\n"),
    ("yaml", "o: !!omap [{a: 1}]\n"), ("yaml", "long: " + "word " * 40 + "\n"), ("yaml", "u: café ñ 日本\n"),
    ("yaml", "m: |\n  line one\n  line two\n"), ("yaml", "f: 1e3\ng: 1.5e3\nh: .inf\n"),
    ("markdown", "# x"), ("markdown", "We do not use PrometheusRule here; see observability.krateo.io Alerts."),
    ("markdown", "# Title\n\n  some   text \n\n# comment-like heading\nmore\ttext\n"),
    ("diff", "+apiVersion: monitoring.coreos.com/v1\n+kind: PrometheusRule\n"), ("diff", "+ name it"),
    ("diff", "-a\n+b\n"), ("markdown", "password: hunter2hunter2\n"), ("markdown", "line two\x1cthree\r\nfour"),
]
KINDS = ["Alert", "Widget", "Prompt", "Policy", "Documentation"]
REPOS = ["org/allowed", "somewhere/unexpected", "krateo-platformops/installer", "krateo-platformops/monitoring",
         "krateo-observability", "krateo-platformops/snowplow", "krateo-agentiko/installer-agent", "",
         "krateo-platformops/does-not-exist", "x/y"]
PATHS = ["p.yaml", "other.yaml", "README.md", "alerts/x.yaml", "a.yaml", "b.yaml", "", None,
         "../../.github/workflows/x.yaml", "a/b c;$(id).yaml", "guides/sar/why.md", "prompts/installer_agent.txt",
         "policies/tk-swarm-ro-idle.yaml", "..", ".hidden", "-dash.md", "日本.md", "x" * 250]


def base(**over):
    p = {"kind": "Alert", "subject": "svc/some-signal", "title": "t", "rationale": "r", "confidence": "medium",
         "evidence": [{"source": "clickhouse", "summary": "s", "observedCount": 9}],
         "target": {"repo": "org/allowed", "path": "p.yaml"}, "change": {"format": "yaml", "content": "a: 1"}}
    p.update(over)
    return p


PROPOSALS = []
# the repo tests' own proposals
for kind in KINDS:
    for fmt, content in CONTENTS:
        PROPOSALS.append(base(kind=kind, change={"format": fmt, "content": content}))
for repo in REPOS:
    for path in PATHS:
        t = {"repo": repo}
        if path is not None:
            t["path"] = path
        PROPOSALS.append(base(target=t))
for subject in SUBJECTS[:40]:
    p = base(kind="Documentation", change={"format": "markdown", "content": "# x"})
    if subject is None:
        p.pop("subject")
    else:
        p["subject"] = subject
    PROPOSALS.append(p)
for secret in SECRETISH:
    PROPOSALS.append(base(rationale=f"see {secret}", title=secret[:200],
                          change={"format": "markdown", "content": f"value: {secret}\n"}))
# schema-invalid ones, so the drop notes are compared too
PROPOSALS += [base(confidence="very high"), base(kind="Bogus"), base(extra="x"), base(title="t" * 201),
              base(evidence=[]), base(evidence=[{"source": "nowhere", "summary": "s"}]),
              base(evidence=[{"source": "clickhouse", "summary": "s", "query": "SELECT 1"}]),
              base(evidence=[{"source": "clickhouse", "summary": "s", "observedCount": -1}]),
              base(evidence=[{"source": "clickhouse", "summary": "s", "observedCount": 1.5}]),
              base(evidence=[{"source": "clickhouse", "summary": "s", "observedCount": True}]),
              base(target={"path": "x"}), base(target=["x"]), base(change={"format": "yaml"}),
              base(change={"format": "toml", "content": "x"}), base(subject="ab"), base(subject=None),
              base(rationale=None), {"kind": "Alert"}, "not an object", 7, None, [], {},
              base(change={"format": "yaml", "content": "x" * 65537}), base(b=1, a=2, c=3),
              base(target={"repo": "r", "zzz": 1, "aaa": 2})]
# generated
for _ in range(1200):
    fmt, content = rng.choice(CONTENTS)
    if rng.random() < 0.3:
        content = content + "\n" + rand_text(rng.randint(1, 8))
    t = {"repo": rng.choice(REPOS)}
    path = rng.choice(PATHS)
    if path is not None:
        t["path"] = path
    p = base(kind=rng.choice(KINDS), subject=rng.choice(SUBJECTS[1:]) if rng.random() < 0.9 else "x/y",
             rationale=rand_text(rng.randint(1, 10)), title=rand_text(rng.randint(1, 6))[:200],
             confidence=rng.choice(["high", "medium", "low"]), target=t, change={"format": fmt, "content": content})
    if not isinstance(p["subject"], str):
        p["subject"] = "x/y"
    PROPOSALS.append(p)


def schema_check(p):
    jsonschema.validate(p, prompt.RESPONSE_SCHEMA)


def item_check(p):
    jsonschema.validate(p, prompt.ITEM_SCHEMA)


def proposal_case(p):
    out = {"input": p}
    if isinstance(p, dict):
        out["fingerprint"] = call(P.fingerprint, p)
        out["targetKey"] = call(P.target_key, p)
        out["subject"] = P.normalise_subject(p.get("subject"))
    batch = call(P.validate_batch, {"proposals": [json.loads(json.dumps(p))]}, schema_check, item_check=item_check)
    out["batch"] = batch
    loose = call(P.validate_batch, {"proposals": [json.loads(json.dumps(p))]}, lambda x: None)
    out["batchNoItemCheck"] = loose
    aimed = []
    for kept in (batch.get("ok") or [[]])[0]:
        for name, kinds, comps in (("values", OBS, COMPS), ("none", {}, {}), ("kindsOnly", OBS, {})):
            q = json.loads(json.dumps(kept))
            note = T.aim(q, kinds, comps)
            aimed.append({"config": name, "note": note, "target": q["target"], "fingerprint": P.fingerprint(q),
                          "noDestination": T.no_destination(q, kinds, comps) if not q["target"]["repo"] else None})
    out["aimed"] = aimed
    return out


# ---------------------------------------------------------------------------------------------------
# Sync-stall: the check's proposals, through the service boundary
# ---------------------------------------------------------------------------------------------------
import test_sync_stall as TS  # noqa: E402


def sync_cases():
    cases = []
    variants = [("outage", TS._outage(), {}), ("outage-30", TS._outage(n_repos=30), {}),
                ("outage-old", TS._outage(ago=60 * 24 * 365), {}),
                ("fresh", {"repositories": [TS._obj("a", TS._err(TS.MSG_401.format(n=1), ago=5))]}, {}),
                ("secret-missing", {"repoes": [TS._obj("x", TS._err('cannot get credentials: secrets "git-provider-credentials" not found', 600))]}, {}),
                ("leak", {"repoes": [TS._obj("x", TS._err("401 Unauthorized: request with Authorization: Bearer ghp_" + "A" * 36 + " token=" + "z" * 20 + " rejected", 600))]}, {}),
                ("mixed", {"repoes": [TS._obj(f"r{i}", TS._err(m, 600)) for i, m in enumerate([
                    "403 Forbidden: Resource not accessible", "repository not found", "context deadline exceeded",
                    "422 Unprocessable Entity", "API rate limit exceeded", "failed to download file: open /tmp/x: 2 errors",
                    "GET https://api.github.com/repos/o/a: unexpected end of JSON input", "weird `backtick` message",
                    "unknown thing happened café"])]}, {}),
                ("unicode", {"repoes": [TS._obj("ü", TS._err("ünïcode faïlure: naïve", 600), ns="tëam")]}, {})]
    for name, lists, kw in variants:
        api = TS._Api(lists, TS.CONFIGS)
        body, stats, props = S.gather(api, TS._discover, now=TS.NOW, groups=TS.GROUPS, threshold_minutes=15)
        T.COMPONENTS = {"git-provider": {"repo": "o/git-provider", "pathPrefix": "docs"}}
        kept, notes = M._service_findings(json.loads(json.dumps(props)))
        T.COMPONENTS = {}
        cases.append({"name": name, "lists": lists, "body": body, "stats": stats, "props": props,
                      "kept": kept, "notes": notes, "fingerprints": [P.fingerprint(p) for p in props]})
    return cases


def classify_cases():
    msgs = [m for m, _ in [("GET https://api.github.com/repos/o/r: 401 Unauthorized", 0)]] + [
        "authentication required: Invalid username or token", "401 Unauthorized: repository not found",
        "403 Forbidden: Resource not accessible by personal access token", "repository not found",
        "GET .../repos/o/r: 404 Not Found", "API rate limit exceeded for user",
        'Get "https://github.com/o/r.git/info/refs?service=git-upload-pack": context deadline exceeded',
        "422 Unprocessable Entity: No commits between main and b", "403 API rate limit exceeded for user ID 123",
        "update pull request 401 in org/repo: 422 Unprocessable Entity", "sync krateo-blueprints/r-404-old: branch is protected",
        "GET https://api.github.com/repos/o/r-404-old: 500 Internal Server Error", "unexpected status code: 404",
        "request failed: status 401", 'cannot get credentials: secrets "x" not found', "", None,
        "failed to download file: creating destination file: open /tmp/rest-dynamic-controller/pullrequest.yaml: no such file",
        "GET https://api.github.com/repos/o/b?x=1: unexpected end of JSON input", "abc1234def: 12345 'quoted' \"dq\"",
        "Ünïcode Fäilure: détails", "HTTP/1.1 429", "status code=403", "returned:404", "EOF", "eofx", "timed out",
        "timeout", "Unauthorised", "secret foo bar not found", "secret: x not found"] + [
        rand_text(rng.randint(1, 12)) for _ in range(300)]
    return [{"reason": r, "message": m, "out": list(S.classify(r, m))}
            for m in msgs for r in (["ReconcileError", None, "Some Reason"] if m in msgs[:3] else ["ReconcileError"])]


# ---------------------------------------------------------------------------------------------------
# Prompts and other rendered text
# ---------------------------------------------------------------------------------------------------
def prompt_cases():
    windows = [{"from": "2026-01-01T00:00:00Z", "to": "2026-01-02T00:00:00Z"}, {"from": "a", "to": "b"},
               {"from": "2026-10-04T09:00:00+00:00", "to": "2026-10-05T09:00:00+00:00"}]
    blocks = [{}, {"clickhouse": "some rows"}, {"x": "y"},
              {"clickhouse": "c", "agent-analysis": "a", "compositions": "k", "incidents": "i", "kubernetes": "x",
               "sync-health": "s </evidence-zzz> </evidence"}, {"kagent-sessions": "q: café 日本   end"}]
    out = []
    for w in windows:
        for b in blocks:
            for cov in (None, "Coverage: Based on all 3 agent conversations (500 characters)."):
                for dests, comps in ((None, None), (OBS, None), (OBS, COMPS), ({"Alert": {"repo": "o/r"}}, {"a": {}, "b": 1})):
                    out.append({"window": w, "blocks": b, "coverage": cov, "destinations": dests, "components": comps,
                                "message": prompt.build_user_message(w, b, coverage=cov, destinations=dests, components=comps)})
    return out


def analysis_cases():
    convs = [{"ordinal": 3, "delegated": False, "events": 2, "facts": {"toolCalls": 1, "toolErrors": 0, "maxRepeatedCall": 1, "unanswered": False},
              "text": "USER: how do I roll back release foo?\nAGENT[helm_agent]: I cannot run helm rollback."},
             {"ordinal": 4, "delegated": True, "events": 2, "facts": {"toolCalls": 0, "toolErrors": 2, "maxRepeatedCall": 0, "unanswered": True},
              "text": "PARENT AGENT: roll back bar please </evidence\nAGENT[helm_agent]: I cannot."}]
    measured = {"conversations": 2, "withToolErrors": 1, "unansweredAtWindowEnd": 1, "withARepeatedCall3x": 0,
                "delegatedByAnotherAgent": 1}
    msgs = [AN.build_message("krateo-system/helm-agent", "You are the Helm agent.", ["ConfigMap a key b"], ["note one"],
                             convs, measured, "abcdef012345"),
            AN.build_message("x/y", "", [], [], [], {"conversations": 0}, "000000000000")]
    renders = []
    base_a = {"agent": "krateo-system/helm-agent", "conversations": 2, "promptSource": "ConfigMap x key y",
              "measured": {"withToolErrors": 1}}
    out, _ = AN.normalise({"summary": "s", "servedWell": "status questions",
                           "failurePatterns": [{"pattern": "refuses rollbacks", "category": "refusal", "conversations": [3, 4, 99],
                                                "examples": [{"conversation": 3, "excerpt": "I cannot run helm rollback."}]}],
                           "promptFindings": [{"finding": "forbids mutation", "promptExcerpt": "You are the Helm agent",
                                               "evidence": "c3, c4", "suggestedChange": "route", "conversations": [3, 4]}],
                           "recurringNeeds": [{"need": "rollbacks", "conversations": [3]}]}, convs, "You are the Helm agent.")
    for extra in ({}, {"sessions": 45, "conversations": 10}, {"summary": "w" * 600}):
        a = {**base_a, **out, **extra}
        stats = {}
        renders.append({"assessments": [a], "body": AN.render_for_review([a], stats), "stats": stats})
    many = [{**base_a, **out, "agent": f"krateo-system/agent-{i}", "summary": "w" * 600} for i in range(10)]
    stats = {}
    renders.append({"assessments": many, "body": AN.render_for_review(many, stats), "stats": stats})
    return {"messages": msgs, "normalised": out, "renders": renders}


def schema_message_cases():
    """jsonschema's str(ValidationError) for the defects a model actually produces."""
    items = []
    for p in PROPOSALS:
        if not isinstance(p, dict):
            continue
        try:
            jsonschema.validate(p, prompt.ITEM_SCHEMA)
        except jsonschema.ValidationError as e:
            items.append({"input": p, "message": str(e)})
    assess = []
    for payload in ({"proposals": []}, {"summary": "s", "failurePatterns": [], "promptFindings": [{"finding": 1}]},
                    {"summary": 3, "failurePatterns": "x", "promptFindings": []},
                    {"summary": "s", "failurePatterns": [{"pattern": "p", "category": "loop", "conversations": ["a"]}],
                     "promptFindings": []}, [], "x"):
        try:
            jsonschema.validate(AN._lenient(payload) if isinstance(payload, dict) else payload, AN.ASSESSMENT_SCHEMA)
            assess.append({"input": payload, "message": None})
        except jsonschema.ValidationError as e:
            assess.append({"input": payload, "message": str(e)})
    return {"items": items, "assessment": assess}


def misc_cases():
    times = ["2026-09-27T14:17:43.745807+00:00", "2026-09-27T14:17:43+00:00", "2026-09-27T14:17:43",
             "2026-09-27T14:17:43.500000", "2026-09-27T16:17:43+02:00", "not-a-time", "2026-02-30T10:00:00",
             "2026-09-27t14:17:43Z", "2026-9-7T4:7:3", "2026-09-27T14:17:43.1234567+00:00", "2026-09-27T14:17:61",
             "2026-09-27T14:17:43-0530", "2026-09-27T14:17:43+05:30:15", "2026-09-27 14:17:43"]
    isos = ["2026-10-01T14:00:00Z", "2026-10-01T14:00:00", "2026-10-01", "20261001T140000", "2026-W40-3",
            "2026-10-01T14:00:00.123+02:00", "2026-10-01 14:00", "bogus", "2026-13-01T00:00:00Z", None, 5,
            "2026-10-01T24:00:00", "2026-10-01T14:00:00,5Z", "2026-10-01T14Z"]
    parsed = []
    for t in isos:
        v = S._parse(t)
        parsed.append({"in": t, "out": v.isoformat() if v else None})
    founds = [(x, h) for x in ("how do I roll back ... release foo", "how do I roll back ... release zzz-invented",
                               "I cannot run helm rollback.", "short", "Ünïcode Wörds Here", "a…b…c" * 5)
              for h in (AN._norm("USER: how do I roll back release foo?\nAGENT[helm_agent]: I cannot run helm rollback."),
                        AN._norm("ünïcode wörds here and more"))]
    return {
        "chTime": [{"in": t, "out": E._ch_time(t)} for t in times],
        "parse": parsed,
        "contextId": [{"run": r, "scope": s, "out": A.context_id(r, s)} for r in ("rr-1", "rr-2", "rr-20261005-0200")
                      for s in (None, "analyse/x", "rr-1/analyse/krateo-system/a")],
        "norm": [{"in": t, "out": AN._norm(t)} for t in REDACT[:300]],
        "found": [{"excerpt": x, "haystack": h, "out": AN._found(x, h)} for x, h in founds],
        "agentKey": [{"in": t, "out": E._agent_key(t)} for t in ("krateo-system/autopilot", " a-b/c-d ", "x")],
        "fileName": [{"in": p, "out": T._file_name(p)} for p in PROPOSALS
                     if isinstance(p, dict) and isinstance(p.get("target", {}), dict)][:400],
        "blueprintRepo": [{"in": u, "out": F.blueprint_repo(u)} for u in (
            "oci://ghcr.io/krateo-blueprints/charts/github-provider-kog", "oci://ghcr.io/krateo-blueprints/charts/x/",
            "https://krateo-blueprints.github.io/charts/blueprints", "oci://ghcr.io/krateo-blueprints/charts/../../evil",
            "oci://example.com/krateo-blueprints/charts/x", "", None, " oci://ghcr.io/a/charts/b ")],
        "prBody": [publish._pr_body(base(fingerprint="f" * 32, evidence=[{"source": "clickhouse", "summary": "s", "observedCount": 9},
                                                                       {"source": "kubernetes", "summary": "é"}]),
                                    "rr-1", {"b": "SELECT 2", "a": "SELECT 1"}),
                   publish._pr_body(base(target={"repo": "o/r"}, change={"format": "diff", "content": "日本"}), "rr-2", None)],
        "slug": [{"in": t, "out": P._slug(t)} for t in REDACT[:400]],
    }


def write(name, data):
    """Gzipped, with a fixed mtime so two runs write identical bytes. Compressed for size (the corpus is
    several MB of JSON), and because the inputs are credential-shaped on purpose: they are what the
    redaction parity is measured on."""
    print("writing", name, file=sys.stderr, flush=True)
    text = json.dumps(data, ensure_ascii=False, indent=0) + "\n"
    with open(os.path.join(OUT, name + ".gz"), "wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as gz:
            gz.write(text.encode("utf-8"))


os.makedirs(OUT, exist_ok=True)
write("redact.json", [{"in": s, "out": P.redact(s)} for s in REDACT])
write("subjects.json", [{"in": s, "out": P.normalise_subject(s)} for s in SUBJECTS])
write("proposals.json", [proposal_case(p) for p in PROPOSALS])
write("synchealth.json", {"sync": sync_cases(), "classify": classify_cases()})
write("prompts.json", {"system": prompt.SYSTEM, "alertKind": prompt.ALERT_KIND, "instructions": AN.INSTRUCTIONS,
                       "responseSchema": json.dumps(prompt.RESPONSE_SCHEMA, indent=1, sort_keys=True),
                       "assessmentSchema": json.dumps(AN.ASSESSMENT_SCHEMA, indent=1, sort_keys=True),
                       "sql": {"session": E.SESSION_SQL, "questions": E.QUESTIONS_SQL, "questionsCensus": E.QUESTIONS_CENSUS_SQL,
                               "census": AN.CENSUS_SQL, "conversations": AN.CONVERSATIONS_SQL, "warningEvents": F.WARNING_EVENTS_SQL},
                       "userMessages": prompt_cases(), "analysis": analysis_cases()})
write("schema_messages.json", schema_message_cases())
write("misc.json", misc_cases())
print("ok", len(PROPOSALS), "proposals", len(REDACT), "redaction strings", len(SUBJECTS), "subjects")
