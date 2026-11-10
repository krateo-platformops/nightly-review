"""Generate the PyYAML parity fixtures for internal/pyyaml.

REGENERATE (from the repository root of a checkout that still has the Python service, i.e. main before the Go
port, or any commit that carries proposals.py), with the image's exact pins:

    python3.12 -m venv /tmp/nr-venv && /tmp/nr-venv/bin/pip install PyYAML==6.0.2
    /tmp/nr-venv/bin/python -I internal/pyyaml/testdata/gen_fixtures.py <path-to-python-checkout> \
        internal/pyyaml/testdata

Every input is run through the REAL proposals.normalise_body and proposals.fingerprint (imported from that
checkout), and through yaml.safe_load_all the way proposals.alert_kind_violation reads it. The Go tests assert
byte equality with what this records. The corpus is deterministic (seeded).
"""
import gzip
import hashlib
import json
import os
import random
import sys

ROOT = os.path.abspath(sys.argv[1])
OUT = os.path.abspath(sys.argv[2])
sys.path.insert(0, ROOT)

import yaml  # noqa: E402

import proposals as P  # noqa: E402

assert yaml.__version__ == "6.0.2", yaml.__version__


def call_like_the_service(content, fmt):
    """normalise_body at the stack depth the service calls it from (main -> validate_batch -> fingerprint),
    so RecursionError thresholds match."""
    def main():
        return validate_batch()

    def validate_batch():
        return fingerprint()

    def fingerprint():
        # The service's stack at this point is [<module>, main, validate_batch, fingerprint]: grant exactly the
        # frames this harness adds on top of that, so a RecursionError happens at the same nesting depth.
        extra = stack_depth() - 4
        old = sys.getrecursionlimit()
        sys.setrecursionlimit(1000 + extra)
        try:
            return P.normalise_body(content, fmt)
        finally:
            sys.setrecursionlimit(old)
    return main()


def stack_depth():
    n, f = 0, sys._getframe(1)
    while f is not None:
        n, f = n + 1, f.f_back
    return n


def load_all_like_the_service(content):
    """yaml.safe_load_all where alert_kind_violation calls it: [<module>, main, validate_batch,
    alert_kind_violation]."""
    def main():
        return validate_batch()

    def validate_batch():
        return alert_kind_violation()

    def alert_kind_violation():
        extra = stack_depth() - 4
        old = sys.getrecursionlimit()
        sys.setrecursionlimit(1000 + extra)
        try:
            return list(yaml.safe_load_all(content))
        finally:
            sys.setrecursionlimit(old)
    return main()


def unsortable_set(v, seen=None):
    """True when v holds a set whose members cannot be sorted: SafeRepresenter then emits them in Python's
    set iteration order, which is hash order — randomised per process for str — so Python itself does not
    reproduce its own output for it."""
    seen = seen if seen is not None else set()
    if id(v) in seen:
        return False
    seen.add(id(v))
    if isinstance(v, set):
        try:
            sorted(v)
        except TypeError:
            return True
        return False
    if isinstance(v, dict):
        return any(unsortable_set(k, seen) or unsortable_set(x, seen) for k, x in v.items())
    if isinstance(v, (list, tuple)):
        return any(unsortable_set(x, seen) for x in v)
    return False


def describe(v):
    if isinstance(v, bool):
        t = "bool"
    elif isinstance(v, int):
        t = "int"
    elif isinstance(v, float):
        t = "float"
    elif v is None:
        t = "none"
    elif isinstance(v, str):
        t = "str"
    elif isinstance(v, bytes):
        t = "bytes"
    elif isinstance(v, list):
        t = "list"
    elif isinstance(v, dict):
        t = "dict"
    elif isinstance(v, set):
        t = "set"
    else:
        t = type(v).__name__
    if t in ("list", "dict", "set"):
        return {"type": t}
    try:
        s = str(v)
    except Exception as exc:  # noqa: BLE001
        s = f"<str failed: {exc}>"
    return {"type": t, "str": s}


def sha(text):
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


def record(cid, category, content):
    rec = {"id": cid, "category": category, "content": content}
    compact = category in ("generated", "deep")
    try:
        loaded = yaml.safe_load(content)
        if unsortable_set(loaded):
            rec["unsortableSet"] = True
    except Exception:  # noqa: BLE001
        pass
    try:
        out = call_like_the_service(content, "yaml")
        if compact:
            rec["normalisedSha256"] = sha(out)
        else:
            rec["normalised"] = out
        prop = {"kind": "Alert", "target": {"repo": "o/r", "path": "p.yaml"},
                "change": {"format": "yaml", "content": content}}
        rec["fingerprint"] = P.fingerprint(prop)
    except RecursionError as exc:
        rec["error"] = {"type": "RecursionError", "msg": str(exc)}
    except Exception as exc:  # noqa: BLE001
        rec["error"] = {"type": type(exc).__name__, "msg": str(exc)}
    try:
        text = P.normalise_body(content, "markdown")
        if compact:
            rec["textSha256"] = sha(text)
        else:
            rec["text"] = text
    except Exception as exc:  # noqa: BLE001
        rec["text_error"] = type(exc).__name__
    try:
        docs = load_all_like_the_service(content)
        rec["docs"] = [describe(d) | ({"kind": describe(d.get("kind")), "apiVersion": describe(d.get("apiVersion"))}
                                      if isinstance(d, dict) else {}) for d in docs]
    except yaml.YAMLError:
        rec["docs_error"] = "YAMLError"
    except RecursionError:
        rec["docs_error"] = "RecursionError"
    except Exception as exc:  # noqa: BLE001
        rec["docs_error"] = type(exc).__name__
    return rec


# --- the corpus ---------------------------------------------------------------------------------------------

FIXED = []


def add(category, *contents):
    for c in contents:
        FIXED.append((category, c))


# The repository's own test strings.
add("repo-tests",
    "a: 1", "a: 1\nb: 2", "a: 1  \n\n\nb: 2   ", "# bump the replica count\nreplicas: 3\n",
    "# increase replicas to three\nreplicas: 3\n", "replicas: 3\nimage: nginx\n", "image: nginx\nreplicas: 3\n",
    "replicas: 4\n", "x: 1\n", "kind: Page", "+ name it", "# x",
    "apiVersion: monitoring.coreos.com/v1\nkind: PrometheusRule\nmetadata: {name: x}\nspec: {groups: []}\n",
    "apiVersion: monitoring.krateo.io/v1alpha1\nkind: Alert\nmetadata: {name: x}\n",
    "apiVersion: observability.krateo.io/v1alpha1\nkind: Alert\nmetadata: {name: x, namespace: krateo-system}\n"
    "spec: {interval: 15m, threshold: 1, thresholdType: above, where: \"Body LIKE '%x%'\"}\n",
    "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: x}\n",
    "apiVersion: widgets.templates.krateo.io/v1beta1\nkind: Alert\nmetadata: {name: x}\n",
    "+apiVersion: monitoring.coreos.com/v1\n+kind: PrometheusRule\n",
    "We do not use PrometheusRule here; see observability.krateo.io Alerts.",
    "# x\n\nSome markdown\n\n- a list\n- of things\n\n```yaml\na: 1\n```\n")

# Realistic manifests.
add("k8s", """apiVersion: observability.krateo.io/v1alpha1
kind: Alert
metadata:
  name: snowplow-sar-unauthorized
  namespace: krateo-system
spec:
  interval: 15m
  threshold: 1
  thresholdType: above
  where: >-
    ResourceAttributes['telemetry.source'] = 'k8s-events'
      AND JSONExtractString(Body, 'object', 'reason') = 'BackOff'
  displayName: "Snowplow: SubjectAccessReview unauthorized"
  message: |
    Snowplow cannot create SubjectAccessReviews.

    Check the ServiceAccount's ClusterRole: it needs `create` on
    `subjectaccessreviews.authorization.k8s.io`.
""", """apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  labels: {app: web, tier: "frontend"}
  annotations:
    krateo.io/nav-path: /dashboard
    description: a very long annotation value that keeps going well past the eighty column mark so the emitter must fold it somewhere sensible
spec:
  replicas: 3
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
        - name: web
          image: nginx:1.27
          ports:
            - containerPort: 80
          env:
            - name: ENABLED
              value: "true"
            - name: COUNT
              value: "012"
            - name: RATIO
              value: '1.5'
            - name: EMPTY
              value: ""
          resources:
            requests: {cpu: 100m, memory: 128Mi}
            limits: {cpu: "1", memory: 1Gi}
""", """apiVersion: v1
kind: ConfigMap
metadata:
  name: prompts
data:
  k8s_agent: |
    You are the Kubernetes agent.
      Indented line.

    Trailing blank lines follow.


  folded: >
    one
    two

    three
  keep: |+
    kept

  strip: |-
    stripped
  json: '{"a": 1, "b": [1, 2]}'
""", """# Helm values
image:
  repository: ghcr.io/krateo-platformops/nightly-review
  tag: ""
  pullPolicy: IfNotPresent
schedule: "0 2 * * *"
dryRun: true
windowHours: 24
config:
  targets:
    Alert: {repo: krateo-platformops/observability, pathPrefix: charts/krateo-observability/templates}
  agentAnalysis:
    maxAgents: 8
    excludeAgents: ["*-bench"]
resources: {}
tolerations: []
nodeSelector: ~
on: yes
off: no
""", """---
apiVersion: v1
kind: Namespace
metadata: {name: a}
---
apiVersion: v1
kind: Namespace
metadata: {name: b}
...
""", """apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: proposals.review.krateo.io
spec:
  group: review.krateo.io
  names: {kind: Proposal, plural: proposals}
  scope: Namespaced
  versions:
    - name: v1alpha1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          properties:
            spec:
              type: object
              x-kubernetes-preserve-unknown-fields: true
              properties:
                kind: {type: string, enum: [Alert, Widget, Prompt, Policy, Documentation]}
                confidence: {type: string, enum: [high, medium, low]}
""")

# Edge cases, one per line of thought.
EDGE = [
    # resolver classes
    "a: yes", "a: Yes", "a: YES", "a: yEs", "a: on", "a: Off", "a: n", "a: y", "a: true", "a: True", "a: tRUE",
    "a: ~", "a: null", "a: Null", "a: NULL", "a: nUll", "a:", "a: ''", 'a: ""',
    "a: 0", "a: -0", "a: +0", "a: 00", "a: 012", "a: 0o12", "a: 08", "a: 0b101", "a: 0b", "a: 0x1F", "a: 0x_1",
    "a: 1_000", "a: 190:20:30", "a: -1:30", "a: 1:60", "a: 12345678901234567890123", "a: -9223372036854775809",
    "a: 1.0", "a: 1.", "a: .5", "a: -.5", "a: 1e5", "a: 1.0e5", "a: 1.0e+5", "a: 1.0E-5", "a: 1_0.5_0",
    "a: 190:20:30.15", "a: .inf", "a: -.Inf", "a: +.INF", "a: .nan", "a: .NaN", "a: .NAN", "a: nan", "a: inf",
    "a: 1e400", "a: 1.0e+400", "a: 1.0e-400", "a: 0.1", "a: 100000000000000000.0", "a: 1234567890123456.0",
    "a: 12345678901234567.0", "a: 0.0001", "a: 0.00001", "a: 3.141592653589793238", "a: -0.0",
    "a: 2001-12-14", "a: 2001-12-14t21:59:43.10-05:00", "a: 2001-12-14 21:59:43.10 -5", "a: 2001-12-15T02:59:43.1Z",
    "a: 2001-12-15 2:59:43.10", "a: 2002-12-14", "a: 2002-1-5 1:00:00", "a: 2020-13-01", "a: 2020-02-30",
    "a: 2020-02-29", "a: 2021-02-29", "a: 0000-01-01", "a: 2020-01-01 24:00:00", "a: 2020-01-01 10:60:00",
    "a: 2020-01-01 10:00:60", "a: 2020-01-01 10:00:00 +24:00", "a: 2020-01-01 10:00:00 +23:59",
    "a: 2020-01-01 10:00:00 +05:99", "a: 2020-01-01 10:00:00.1234567", "a: 2020-01-01T10:00:00+00:00",
    "a: 2020-01-01 10:00:00Z", "a: 2020-01-01 10:00:00 Z", "a: 1999-12-31T23:59:59.999999Z",
    "a: <<", "a: =", "<<: {b: 1}\nc: 2", "<<: [{b: 1}, {b: 2, c: 3}]\nc: 4", "base: &b {x: 1, y: 2}\nd:\n  <<: *b\n  y: 3",
    "a: &x {b: 1}\nc: *x", "a: &x [1, 2]\nc: *x\nd: *x", "a: &x 2020-01-01\nb: *x", "a: &x !!binary aGVsbG8=\nb: *x",
    "&r [*r]", "a: &r {b: *r}", "- &a [1]\n- *a\n- &b {c: *a}\n- *b", "a: *undefined", "a: &x 1\nb: &x 2",
    "<<: 1", "<<: [1]", "- <<", "- =", "=: 1", "a: {=: 1}", "!!str {=: abc}",
    # explicit tags
    "a: !!str 1", "a: !!int 1", "a: !!int abc", "a: !!int ''", "a: !!int +", "a: !!int 0o17", "a: !!int 0x0x1f",
    "a: !!int 1:2", "a: !!int 08", "a: !!float 1", "a: !!float nan", "a: !!float abc", "a: !!float ' 1.5 '",
    "a: !!float infinity", "a: !!bool maybe", "a: !!bool YES", "a: !!null x", "a: !!null [1]",
    "a: !!timestamp foo", "a: !!timestamp 2020-01-01", "a: !!binary aGVsbG8=", "a: !!binary 'aGVsbG8'",
    "a: !!binary 'a'", "a: !!binary '!!!'", "a: !!binary ''", "a: !!binary é", "a: !!set {x, y, z}",
    "a: !!set {1, a}", "a: !!omap [{a: 1}, {b: 2}]", "a: !!omap [{a: 1, b: 2}]", "a: !!omap {a: 1}",
    "a: !!pairs [{a: 1}, {a: 2}]", "a: !!seq [1]", "a: !!map {b: 1}", "a: !!seq {b: 1}", "a: !custom x",
    "a: !<tag:yaml.org,2002:str> 5", "%TAG !e! tag:yaml.org,2002:\n---\na: !e!int 5", "a: ! 5", "a: !e!x 1",
    "%YAML 1.1\n---\na: 1", "%YAML 1.2\n---\na: 1", "%YAML 2.0\n---\na: 1", "%YAML 1.1\n%YAML 1.1\n---\na: 1",
    "%FOO bar\n---\na: 1",
    # keys
    "1: a\nb: c", "true: a\n1: b", "1: a\n1.0: b", "1: a\ntrue: b\n1.0: c", "null: a\nb: c", "~: a", "? [1]\n: a",
    "? {a: 1}\n: b", "2020-01-01: a\n2019-01-01: b", "2020-01-01 10:00:00Z: a\n2020-01-01 09:00:00Z: b",
    "2020-01-01: a\n2020-01-01 10:00:00: b", "2020-01-01 10:00:00: a\n2020-01-01 10:00:00Z: b",
    ".nan: a\n.nan: b", ".nan: a\n1: b\n0: c", "1: a\n.inf: b\n-.inf: c", "a: 1\na: 2", "b: 1\na: 2\nb: 3",
    "!!binary aGVsbG8=: a\n!!binary Ynll: b", "!!binary aGVsbG8=: a\nb: c",
    "? |\n  multi\n  line\n: v", "'a b': 1\n\"c\\nd\": 2", "? a\n? b", "x" * 130 + ": 1", "x" * 123 + ": 1",
    "x" * 122 + ": 1", "x" * 1100 + ": 1",
    # quoting and styles of str values
    "a: 'yes'", "a: '1.0'", "a: '012'", "a: '~'", "a: 'null'", "a: '2020-01-01'", "a: '<<'", "a: '='",
    "a: '!'", "a: '&'", "a: '*'", "a: '- x'", "a: '-x'", "a: '? x'", "a: ':x'", "a: 'x: y'", "a: 'x:y'",
    "a: 'x #y'", "a: 'x#y'", "a: '#x'", "a: ' x'", "a: 'x '", "a: '---'", "a: '...x'", "a: '%x'", "a: '@x'",
    "a: '`x'", "a: '{x'", "a: 'x}'", "a: '[x]'", "a: 'x, y'", "a: '|'", "a: '>'", "a: \"'\"", "a: '\"'",
    "a: 'it''s'", "a: \"tab\\there\"", "a: \"line\\nbreak\"", "a: \"trail\\n\"", "a: \"\\nlead\"", "a: \"a \\n b\"",
    "a: \"a\\n b\"", "a: \"a \\nb\"", "a: \"two\\n\\nbreaks\"", "a: \"cr\\rlf\"", "a: \"\\x00\\x07\\x1b\"",
    "a: \"\\u00e9\\u4e2d\\U0001F600\"", "a: \"\\u2028x\\u2029\"", "a: \"\\x85\\xa0\"", "a: \"\\ufeff\"",
    "a: \"\\ud800\"", "a: \"\\U00110000\"", "a: \"\\q\"", "a: \"\\/\"", "a: \"\\_\\N\\L\\P\\e\\a\\b\\v\\f\"",
    "a: é", "a: 中文", "a: emoji 😀", "a: \u00a0nbsp", "a: x\u2028y", "\ufeffa: 1", "a: 1\ufeff",
    "a: control\x07char", "a: del\x7fchar", "a: \x85", "a: tab\there", "a:\tb", "\ta: 1", "a:\n\tb: 1",
    "a: " + "word " * 30, "a: " + "w" * 100, "a: '" + "word " * 30 + "'", "a: \"" + "word\\n" * 10 + "\"",
    "a: \"" + "x" * 78 + " y\"", "a: \"" + "é" * 50 + " " + "é" * 50 + "\"", "a: \"" + "word " * 20 + "é\"",
    "a: \"" + "a" * 79 + "\\u00e9 " + "b" * 10 + "\"", "a: \"" + "a " * 60 + "\"", "a: '" + "a  " * 40 + "'",
    "a: \"" + " " * 100 + "\"", "a: \"x" + " " * 100 + "y\"", "a: \"" + "\\t" * 50 + "\"",
    "a: |\n  " + "long line " * 15 + "\n", "a: >\n  " + "folded " * 20 + "\n", "a: |\n   lead\n  ",
    "a: |2\n   two\n", "a: |0\n x", "a: |+\n\n", "a: >-\n  x\n\n  y\n", "a: |\n  x\n \n  y",
    # plain scalars with odd characters
    "a: x:y", "a: x: y", "a: http://example.com/a?b=c#d", "a: x #comment", "a: x#y", "a: -x", "a: - x",
    "a: ?x", "a: x?", "a: x,y", "a: [x, y]", "a: {x: y}", "a: [x, {y: z}, [1, 2]]", "a: {x: [1, 2], y: {z: 1}}",
    "a: [x\n  , y]", "a: [a, b, ]", "a: [,]", "a: {a, b}", "a: {? a : b}", "a: [? a : b]", "a: [a: b, c]",
    "a: b\n  c\n  d", "a: b\n\n  c", "- a\n- b\n-\n- - c\n  - d", "- a: 1\n  b: 2\n- c", "-\n  a: 1",
    "a:\n- 1\n- 2", "a:\n  - 1\n  - 2", "a:\n  b:\n    - c: [1]\n      d: {}\n", "[]", "{}", "a: []", "a: {}",
    "- []\n- {}", "a: [[], {}]", "- - - x", "[[[[[1]]]]]",
    # documents and markers
    "", " ", "\n", "# only a comment", "---", "--- a", "---\n...", "...", "--- !!map {}", "a: 1\n---\nb: 2",
    "a: 1\n...\n", "a: 1\n...\n---\nb: 2", "--- |\n  x", "a\n---\n: bad", "a: 1\n--- \nb", "--- [1]\n--- {}",
    "plain scalar", "'quoted scalar'", "1", "null", "- 1", "? a", ": b", "a: b: c", "a: [1, 2", "a: {b: 1",
    "a: 'unclosed", "a: \"unclosed", "a:\n  b: 1\n c: 2", "a:\n  - 1\n - 2", "- a\nb: 1", "a: 1\n- b",
    "a: @x", "a: `x", "{a: 1}}", "]", "a: &", "a: *", "a: & x", "a: !", "a: |x", "key: value\n  bad: indent",
    "a: b\nc", "a: [b]c", "a: 'b'c", "\"a\" b: 1", "a: !!str", "a: &x", "&x a: 1", "!!str &x a: 1",
    "a: \"multi\n  line\n\n  quoted\"", "a: 'multi\n  line'", "a: \"---\n\"", "a: 'x\n---\ny'",
    "a: b # comment\n# full line\nc: d  # another", "a: 1\r\nb: 2\r\n", "a: 1\rb: 2", "a: 1\x85b: 2",
    "a: 1\u2028b: 2", "a: 1\u2029b: 2", "a: 'x\u2028y'", "a: \"x\u2028y\"", "a: |\n  x\u2028  y\n",
    "a: 1\n\n\n", "a: 1\v", "a: 1\f", "a: 1\x1c", "a: 1\x1d\nb: 2", "line1\x1eline2", "a\u3000b: c",
    "a: b\u3000\u3000c", "a:\u00a0b", "  a: 1\n  b: 2", "a:   1", "a :1", "a : 1",
]
add("edge", *EDGE)


def flow_for_the_text_path():
    return ["# heading\n\n  indented   text\twith\ttabs  \n\n#not a comment? yes it is\n  # also\nend",
            "line\x0bwith vt\x0cand ff\x1cand fs\x1dgs\x1ers\x85nel\u2028ls\u2029ps\r\ncrlf\rcr",
            "\u3000ideographic space\u3000inside\u3000", "\x1f unit separator \x1f", "a\u00a0\u00a0b"]


add("text", *flow_for_the_text_path())

# Deep nesting around the RecursionError thresholds (kept a few levels away from the exact boundary).
for depth in (50, 200, 320, 326, 335, 340, 400, 480, 495, 520, 700):
    add("deep", "[" * depth + "1" + "]" * depth)
    add("deep", "{a: " * depth + "1" + "}" * depth)
    add("deep", "a: " + "[" * depth + "]" * depth)
for depth in (50, 200, 320, 340):
    add("deep", "".join(f"{'  ' * i}k{i}:\n" for i in range(depth)) + "  " * depth + "v\n")


# --- the seeded adversarial generator -------------------------------------------------------------------------

TOKENS = ["yes", "No", "ON", "off", "true", "False", "null", "~", "", " ", "0", "007", "0x1f", "0b11", "1_000",
          "1:30", "1.5", ".5", "1e3", "1.0e+3", ".inf", "-.inf", ".nan", "2020-01-01", "2020-01-01 10:00:00",
          "2020-1-1 1:00:00Z", "<<", "=", "!", "&", "*", "-", "- x", "?", ": ", "x: y", "#", " #x", "x #y",
          "[", "]", "{", "}", ",", "'", '"', "\\", "|", ">", "%", "@", "`", "---", "...", "\n", "\n\n", "\t",
          "\r", "\r\n", " lead", "trail ", "é", "中", "😀", "\u2028", "\u00a0", "\ufeff", "\x85", "\x00", "\x07",
          "\x1b", "\x7f", "word", "two words", "a" * 85, "word " * 20, "Snowplow", "kind", "apiVersion",
          "Alert", "observability.krateo.io/v1alpha1", "monitoring.coreos.com/v1", "PrometheusRule"]


def rand_scalar(rng):
    r = rng.random()
    if r < 0.45:
        return "".join(rng.choice(TOKENS) for _ in range(rng.randint(1, 3)))
    if r < 0.55:
        return rng.randint(-10**6, 10**6) if rng.random() < 0.8 else rng.randint(-10**30, 10**30)
    if r < 0.65:
        return rng.choice([0.0, -0.0, 1.5, 1e16, 1e-5, 123456.789, 1e300, float("inf"), -float("inf"),
                           float("nan"), 0.1, 2.5e-7, 1e22, 12345678901234567890.0, rng.random() * 10 ** rng.randint(-8, 20)])
    if r < 0.7:
        return rng.choice([True, False, None])
    if r < 0.75:
        import datetime as dt
        return rng.choice([dt.date(2020, 1, 2), dt.datetime(2020, 1, 2, 3, 4, 5),
                           dt.datetime(2020, 1, 2, 3, 4, 5, 6, tzinfo=dt.timezone.utc),
                           dt.datetime(2020, 1, 2, 3, 4, 5, tzinfo=dt.timezone(dt.timedelta(hours=-5, minutes=-30)))])
    if r < 0.78:
        return bytes(rng.randrange(256) for _ in range(rng.randint(0, 80)))
    return "".join(chr(rng.choice([rng.randint(0x20, 0x7e), rng.randint(0xa0, 0x2fff), rng.randint(0x1f600, 0x1f64f),
                                   0x0a, 0x09, 0x85, 0x2028])) for _ in range(rng.randint(0, 120)))


def rand_data(rng, depth=0):
    r = rng.random()
    if depth > 3 or r < 0.35:
        return rand_scalar(rng)
    if r < 0.65:
        d = {}
        for _ in range(rng.randint(0, 6)):
            k = rand_scalar(rng)
            if isinstance(k, (bytes,)) and rng.random() < 0.5:
                k = str(k)
            try:
                hash(k)
            except TypeError:
                k = str(k)
            d[k] = rand_data(rng, depth + 1)
        return d
    if r < 0.9:
        return [rand_data(rng, depth + 1) for _ in range(rng.randint(0, 5))]
    # Homogeneous, so sortable: an unsortable set is dumped in hash order, which would make this generator's
    # own output depend on PYTHONHASHSEED (and -I ignores that variable).
    kind = rng.choice([str, int])
    return set(x for x in (rand_scalar(rng) for _ in range(rng.randint(0, 4)))
               if isinstance(x, kind) and not isinstance(x, bool))


def holds_set(v):
    if isinstance(v, set):
        return True
    if isinstance(v, dict):
        return any(holds_set(x) for x in v.values())
    if isinstance(v, list):
        return any(holds_set(x) for x in v)
    return False


def generated(n, seed):
    rng = random.Random(seed)
    out = []
    while len(out) < n:
        data = rand_data(rng)
        style = rng.choice([{}, {"default_flow_style": True}, {"default_flow_style": None},
                            {"allow_unicode": True}, {"canonical": True}, {"width": 20}, {"indent": 4},
                            {"default_style": '"'}, {"default_style": "'"}, {"default_style": "|"},
                            {"explicit_start": True, "explicit_end": True}])
        try:
            # A set is dumped in iteration (hash) order unless its keys are sorted, so a document holding one is
            # always dumped sorted: the corpus must not depend on the process's hash seed.
            sort_keys = rng.random() < 0.3
            text = yaml.safe_dump(data, sort_keys=sort_keys or holds_set(data), **style)
        except Exception:  # noqa: BLE001
            continue
        if rng.random() < 0.3:
            # mutate: delete, duplicate or insert characters to produce near-valid and invalid YAML
            chars = list(text)
            for _ in range(rng.randint(1, 4)):
                if not chars:
                    break
                i = rng.randrange(len(chars))
                op = rng.random()
                if op < 0.4:
                    del chars[i]
                elif op < 0.7:
                    chars.insert(i, rng.choice([" ", "\n", ":", "-", "'", '"', "#", "&a", "*a", "!!int ", "\t",
                                                "[", "]", "{", "}", ",", "? ", "<<: ", "|", ">"]))
                else:
                    chars[i] = rng.choice(["\n", " ", "x", "é", "\u2028"])
            text = "".join(chars)
        if len(text) <= 1500:
            out.append(text)
    return out


RAW_TOKENS = TOKENS + ["key", "a b", "x:y", "x: y", "'q'", '"dq"', "'it''s'", '"esc\\n"', "[1, 2]", "{a: 1}",
                       "&anc", "*anc", "!!str", "!!int", "!!binary", "<<: *anc", "|", "|-", ">", ">+", "- item",
                       "? key", "# comment", "--- ", "...", "%YAML 1.1", "\t", "  ", "    ", "0o7", "+12", "-.5",
                       "12:30:45", "1_2.3_4", "2001-12-14t21:59:43.10-05:00", "~", "Null", "TRUE", "y", "n"]


SAFE_TOKENS = ["key", "name", "value", "a b", "x-y", "snake_case", "CamelCase", "yes", "No", "on", "off", "true",
               "False", "null", "~", "0", "007", "0x1f", "0b11", "1_000", "12:30", "1.5", ".5", "1e3", "1.0e+3",
               ".inf", "-.inf", ".nan", "2020-01-01", "2020-01-01 10:00:00", "2001-12-14t21:59:43.10-05:00",
               "'q'", '"dq"', "'it''s'", '"esc\\n"', "'1.0'", '"yes"', "é", "中文", "😀", "http://x.io/a?b=c",
               "x:y", "a.b/c", "-x", "word " * 18 + "end", "a" * 90, "'" + "w " * 45 + "'", "+12", "-.5", "1:2:3"]


def raw_documents(n, seed):
    """Hand-written-looking YAML: block structure, raw (unquoted) tokens, comments, block scalars, and line
    mutations — the shapes a model types, which PyYAML's dumper never produces."""
    rng = random.Random(seed)
    out = []
    while len(out) < n:
        lines = []
        indent = 0
        for _ in range(rng.randint(1, 12)):
            r = rng.random()
            pad = " " * indent
            tok = lambda: rng.choice(RAW_TOKENS if rng.random() < 0.15 else SAFE_TOKENS)  # noqa: E731
            if r < 0.35:
                lines.append(f"{pad}{tok()}: {tok()}")
            elif r < 0.5:
                lines.append(f"{pad}{tok()}:")
                indent = min(indent + rng.choice([2, 2, 4, 1, 3]), 12)
            elif r < 0.62:
                lines.append(f"{pad}- {tok()}")
            elif r < 0.7:
                lines.append(f"{pad}- {tok()}: {tok()}")
            elif r < 0.78:
                lines.append(f"{pad}{tok()}: |")
                for _ in range(rng.randint(1, 3)):
                    lines.append(f"{pad}  {tok()} {tok()}")
            elif r < 0.85:
                lines.append(f"{pad}# {tok()}")
            elif r < 0.9:
                indent = max(0, indent - rng.choice([2, 4]))
                lines.append(f"{' ' * indent}{tok()}: {tok()} {tok()}")
            elif r < 0.95:
                lines.append(f"{pad}{tok()}: [{tok()}, {tok()}]")
            else:
                lines.append(f"{pad}{tok()}: {{{tok()}: {tok()}}}")
        text = rng.choice(["\n", "\r\n", "\n"]).join(lines) + rng.choice(["", "\n", "\n\n", " "])
        if len(text) <= 1500:
            out.append(text)
    return out


def main():
    os.makedirs(OUT, exist_ok=True)
    fixed = [record(f"{cat}-{i}", cat, c) for i, (cat, c) in enumerate(FIXED)]
    gen = [record(f"gen-{i}", "generated", c) for i, c in enumerate(generated(5000, 20261110))]
    gen += [record(f"raw-{i}", "generated", c) for i, c in enumerate(raw_documents(3500, 1110))]
    # Gzipped with a fixed mtime, so two runs write identical bytes; the corpus is several MB of JSON.
    for name, text in (("pyyaml_fixed.json", json.dumps(fixed, ensure_ascii=True, indent=0)),
                       ("pyyaml_generated.json", json.dumps(gen, ensure_ascii=True, separators=(",", ":")))):
        with open(os.path.join(OUT, name + ".gz"), "wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as gz:
                gz.write(text.encode("utf-8"))
    cats = {}
    for r in fixed + gen:
        k = (r["category"], "error" if "error" in r else "ok")
        cats[k] = cats.get(k, 0) + 1
    print(json.dumps({f"{a}/{b}": n for (a, b), n in sorted(cats.items())}, indent=1))


if __name__ == "__main__":
    main()
