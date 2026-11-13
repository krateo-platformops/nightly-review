#!/usr/bin/env python3
"""Render test for the Agent's serviceAccountConfig (krateo-agent-lib >= 0.2.0).

usage: hack/test-sa-annotations.py <chart dir> [--prefix <values path>] [--sa-key-values <yaml>]

  --prefix         dotted values path that holds `serviceAccount` (default: top level)
  --sa-key-values  values YAML that turns on the chart's SA-key Secret mount, to check that both
                   blocks render together (default: none, the check is skipped)

Renders the chart with values FILES (never --set: `--set serviceAccount.annotations={}` parses as a
list) and asserts on the parsed YAML:
  - every Agent is kagent.dev/v1alpha2 (serviceAccountConfig exists only there; under v1alpha1 the
    apiserver prunes it silently);
  - serviceAccount absent, annotations null and annotations {} render NO serviceAccountConfig, and the
    output is byte-identical to the chart's defaults;
  - two annotations render exactly spec.declarative.deployment.serviceAccountConfig.annotations;
  - with the SA-key Secret also set, both the volumes and serviceAccountConfig render;
  - a non-string annotation value is rejected by values.schema.json.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

import yaml

WANT = {
    "iam.gke.io/gcp-service-account": "test-gsa@example-project.iam.gserviceaccount.com",
    "example.com/owner": "observability",
}


def nest(prefix, body):
    """Wrap a `serviceAccount:` YAML snippet under a dotted values path."""
    out = body
    for key in reversed([k for k in prefix.split(".") if k]):
        out = f"{key}:\n" + "".join(f"  {l}\n" for l in out.rstrip("\n").split("\n"))
    return out


def main(chart, prefix="", sakey=None):
    CASES = {
        "absent": nest(prefix, "serviceAccount: null\n"),
        "annotations-null": nest(prefix, "serviceAccount:\n  annotations: null\n"),
        "annotations-empty": nest(prefix, "serviceAccount:\n  annotations: {}\n"),
    }
    TWO = nest(prefix, "serviceAccount:\n  annotations:\n" + "".join(f"    {k}: {v}\n" for k, v in WANT.items()))
    NONSTRING = nest(prefix, "serviceAccount:\n  annotations:\n    example.com/flag: true\n")
    pairs = [("two-annotations", TWO)]
    if sakey:
        pairs.append(("two-annotations+sa-key", TWO + sakey))
    tmp = tempfile.mkdtemp()
    try:
        c = os.path.join(tmp, "chart")
        shutil.copytree(chart, c)
        p = os.path.join(c, "Chart.yaml")
        s = open(p).read()
        for ph in ("CHART_VERSION", "APP_VERSION", "SOURCE_REF"):
            s = s.replace(ph, "0.0.0")
        open(p, "w").write(s)
        # Charts that pull krateo-agent-lib at lint/release time (charts/ gitignored) need it built;
        # charts that vendor it already have charts/. Needs a registry login for a private repo.
        if "\ndependencies:" in s and not os.path.isdir(os.path.join(c, "charts")):
            r = subprocess.run(["helm", "dependency", "build", c], capture_output=True, text=True)
            if r.returncode != 0:
                sys.exit(f"helm dependency build failed:\n{r.stderr}")

        def render(values=None, check=True):
            cmd = ["helm", "template", "smoke", c]
            if values is not None:
                f = os.path.join(tmp, "values.yaml")
                open(f, "w").write(values)
                cmd += ["-f", f]
            r = subprocess.run(cmd, capture_output=True, text=True)
            if check and r.returncode != 0:
                sys.exit(f"helm template failed:\n{r.stderr}")
            return r

        def agents(out):
            return [d for d in yaml.safe_load_all(out) if d and d.get("kind") == "Agent"]

        def deployment(a):
            return ((a.get("spec") or {}).get("declarative") or {}).get("deployment") or {}

        fails = []
        default = render().stdout
        ags = agents(default)
        if not ags:
            fails.append("no Agent rendered")
        for a in ags:
            if a.get("apiVersion") != "kagent.dev/v1alpha2":
                fails.append(f"{a['metadata']['name']}: apiVersion {a.get('apiVersion')}, want kagent.dev/v1alpha2")
            if "serviceAccountConfig" in deployment(a):
                fails.append("defaults: serviceAccountConfig rendered, want none")
        for name, values in CASES.items():
            out = render(values).stdout
            if any("serviceAccountConfig" in deployment(a) for a in agents(out)):
                fails.append(f"{name}: serviceAccountConfig rendered, want none")
            if out != default:
                fails.append(f"{name}: output differs from the defaults' output")
        for name, values in pairs:
            out = render(values).stdout
            for a in agents(out):
                got = deployment(a).get("serviceAccountConfig")
                if got != {"annotations": WANT}:
                    fails.append(f"{name}: serviceAccountConfig = {got!r}")
                if name.endswith("sa-key") and not deployment(a).get("volumes"):
                    fails.append(f"{name}: SA-key volumes missing")
            # No whitespace-only line inside an Agent document beyond what the defaults have.
            blank = lambda t: sum(1 for l in t.split("\n") if l and not l.strip())
            if name == "two-annotations" and blank(out) != blank(default):
                fails.append(f"{name}: whitespace-only lines {blank(out)} vs defaults {blank(default)}")
        r = render(NONSTRING, check=False)
        if r.returncode == 0 or not re.search(r"want string", r.stderr):
            fails.append("non-string annotation value was not rejected by the schema")

        for f in fails:
            print("FAIL", f)
        print("PASS" if not fails else f"{len(fails)} failure(s)")
        return 1 if fails else 0
    finally:
        shutil.rmtree(tmp)


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(usage=__doc__)
    ap.add_argument("chart")
    ap.add_argument("--prefix", default="")
    ap.add_argument("--sa-key-values", default=None)
    a = ap.parse_args()
    sys.exit(main(a.chart, a.prefix, a.sa_key_values.replace("\\n", "\n") if a.sa_key_values else None))
