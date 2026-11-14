#!/usr/bin/env python3
"""Render test for how the CronJob reaches the reviewer (AUTOPILOT_A2A_URL / AUTOPILOT_A2A_HOST).

usage: hack/test-reviewer-path.py <chart dir>

A reviewer this chart creates is reached THROUGH THE AGENT GATEWAY: agentgateway-policies' NetworkPolicy
admits an agent pod's port only from the kagent controller and the gateway pods, so dialling the agent's
own Service works only on a cluster that does not enforce NetworkPolicy. The gateway routes by
`x-kagent-host`, which the binary sends from AUTOPILOT_A2A_HOST.

Renders the chart with values FILES and asserts on the CronJob's env:
  - defaults: the gateway's address in this release's namespace, and the host <reviewer.name>.<namespace>;
  - reviewer.gateway overrides reach the URL; the host still names the reviewer in the release namespace;
  - reviewer.gateway: null falls back to the defaults (no render failure);
  - an explicit config.reviewerA2aUrl wins and sends NO host, so no routing header;
  - reviewer.create false with the deprecated alias dials the alias, with no host;
  - the URL never points at the reviewer's own Service;
  - a non-integer port is rejected by values.schema.json.
"""
import os
import shutil
import subprocess
import sys
import tempfile

import yaml

NS = "krateo-system"


def main(chart):
    tmp = tempfile.mkdtemp()
    try:
        c = os.path.join(tmp, "chart")
        shutil.copytree(chart, c)
        p = os.path.join(c, "Chart.yaml")
        s = open(p).read()
        for ph in ("CHART_VERSION", "APP_VERSION", "SOURCE_REF"):
            s = s.replace(ph, "0.0.0")
        open(p, "w").write(s)

        def render(values, check=True):
            f = os.path.join(tmp, "values.yaml")
            open(f, "w").write(values)
            r = subprocess.run(["helm", "template", "smoke", c, "-n", NS, "-f", f], capture_output=True, text=True)
            if check and r.returncode != 0:
                sys.exit(f"helm template failed:\n{r.stderr}")
            return r

        def env(values):
            for d in yaml.safe_load_all(render(values).stdout):
                if d and d.get("kind") == "CronJob":
                    c0 = d["spec"]["jobTemplate"]["spec"]["template"]["spec"]["containers"][0]
                    return {e["name"]: e.get("value") for e in c0.get("env", []) if e["name"].startswith("AUTOPILOT_A2A")}
            sys.exit("no CronJob rendered")

        gw = f"http://krateo-agent-gateway.{NS}.svc:8080/"
        host = f"nightly-review-agent.{NS}"
        cases = [
            ("defaults", "{}\n", {"AUTOPILOT_A2A_URL": gw, "AUTOPILOT_A2A_HOST": host}),
            ("gateway overrides",
             "reviewer:\n  gateway:\n    service: gw\n    namespace: gw-ns\n    port: 9090\n",
             {"AUTOPILOT_A2A_URL": "http://gw.gw-ns.svc:9090/", "AUTOPILOT_A2A_HOST": host}),
            ("renamed reviewer", "reviewer:\n  name: rv\n",
             {"AUTOPILOT_A2A_URL": gw, "AUTOPILOT_A2A_HOST": f"rv.{NS}"}),
            ("gateway null", "reviewer:\n  gateway: null\n", {"AUTOPILOT_A2A_URL": gw, "AUTOPILOT_A2A_HOST": host}),
            ("explicit reviewerA2aUrl", "config:\n  reviewerA2aUrl: http://elsewhere.ns.svc:8080/\n",
             {"AUTOPILOT_A2A_URL": "http://elsewhere.ns.svc:8080/"}),
            ("create false + alias", "reviewer:\n  create: false\nconfig:\n  autopilotA2aUrl: http://alias.ns.svc:8080/\n",
             {"AUTOPILOT_A2A_URL": "http://alias.ns.svc:8080/"}),
        ]
        fails = []
        for name, values, want in cases:
            got = env(values)
            if got != want:
                fails.append(f"{name}: env {got!r}, want {want!r}")
            if "nightly-review-agent." in (got.get("AUTOPILOT_A2A_URL") or ""):
                fails.append(f"{name}: the URL dials the reviewer's own Service")
        r = render("reviewer:\n  gateway:\n    port: \"8080\"\n", check=False)
        if r.returncode == 0 or "want integer" not in r.stderr:
            fails.append("a string port was not rejected by the schema")

        for f in fails:
            print("FAIL", f)
        print("PASS" if not fails else f"{len(fails)} failure(s)")
        return 1 if fails else 0
    finally:
        shutil.rmtree(tmp)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1]))
