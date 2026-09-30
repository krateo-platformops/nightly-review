"""Does config.destinations.components still agree with what the installer installs?

WHY THIS EXISTS. The seeded map points each component at a repository verified on 2026-09-30. A map that
goes stale does not fail loudly: a component pointed at a real-but-wrong repository resolves RepoFound and
its proposal goes to the wrong place — quieter than the 404 this map replaced. So the installer's pins are
the reference, read from its main branch every run, and three things must hold:

  1. every pinned component has an entry, or a reviewed reason in drift/unmapped-components.yaml;
  2. an entry's organisation (and its prompt's) is the organisation the pins publish that component from —
     `repo: oci://ghcr.io/<org>/charts`, or the installer's default `ociRepo` when a pin has none;
  3. a component on the default registry is no exception to 1: a missing one is reported as such.

Only the ORGANISATION is compared: the pins name a chart registry, not a source repository, so nothing
finer can be checked against them. The allowlist is checked both ways — a reason for a component that also
has an entry, or that is no longer pinned, is an error too, because either means the review is stale.
"""
import pathlib
import re

import requests
import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
PINS_URL = "https://raw.githubusercontent.com/krateo-platformops/installer/main/chart/files/component-pins.yaml"
INSTALLER_VALUES_URL = "https://raw.githubusercontent.com/krateo-platformops/installer/main/chart/values.yaml"
ALLOWLIST = ROOT / "drift" / "unmapped-components.yaml"
VALUES = ROOT / "helm" / "nightly-review" / "values.yaml"

_OCI_ORG = re.compile(r"^oci://[^/]+/([^/]+)(?:/|$)")


def fetch(url):
    """The text at `url`, or an exception that says what was being fetched and why. NEVER A SKIP: a check
    that passes whenever GitHub is unreachable is a check that passes."""
    try:
        r = requests.get(url, timeout=30)
    except Exception as exc:                                  # noqa: BLE001
        raise RuntimeError(f"cannot fetch {url}: {type(exc).__name__}: {exc}. The drift check needs the "
                           f"installer's pins to compare against and does not pass without them.") from exc
    if r.status_code != 200:
        raise RuntimeError(f"cannot fetch {url}: HTTP {r.status_code}. The drift check needs the installer's "
                           f"pins to compare against and does not pass without them.")
    return r.text


def oci_org(repo):
    """oci://ghcr.io/krateo-agentiko/charts -> krateo-agentiko; None when it is not that shape."""
    m = _OCI_ORG.match(repo or "")
    return m.group(1) if m else None


def problems(pins, default_repo, components, unmapped):
    """Every disagreement, each as one line saying what to add or change. Empty means in step."""
    default_org = oci_org(default_repo)
    out = []
    if not default_org:
        out.append(f"installer chart/values.yaml ociRepo {default_repo!r} is not oci://<host>/<org>/...; "
                   f"cannot tell which organisation the default registry is")
    pinned = {}
    for pin in pins:
        name = pin.get("name")
        if name:
            pinned[name] = pin
    for name, pin in pinned.items():
        on_default = not pin.get("repo")
        org = default_org if on_default else oci_org(pin["repo"])
        entry = components.get(name)
        if entry is None:
            if name not in unmapped:
                where = "the default registry" if on_default else pin["repo"]
                out.append(f"{name} (published from {where}) has no destination: add "
                           f"config.destinations.components.{name} to helm/nightly-review/values.yaml "
                           f"(a repository in {org}, verified with `gh api repos/<owner>/<name>`), or add "
                           f"`{name}: <reason>` to drift/unmapped-components.yaml")
            continue
        if name in unmapped:
            out.append(f"{name} has a destination AND a reason to be unmapped: remove it from "
                       f"drift/unmapped-components.yaml")
        for field, repo in (("repo", entry.get("repo")), ("prompt.repo", (entry.get("prompt") or {}).get("repo"))):
            if repo and org and repo.partition("/")[0] != org:
                out.append(f"config.destinations.components.{name}.{field} is {repo}, but the installer publishes "
                           f"{name} from {org}: fix the entry, or the pin")
    for name, reason in unmapped.items():
        if name not in pinned:
            out.append(f"{name} is in drift/unmapped-components.yaml but the installer no longer pins it: "
                       f"remove the line")
        if not (isinstance(reason, str) and reason.strip()):
            out.append(f"{name} is in drift/unmapped-components.yaml without a reason: say why it is unmapped")
    return out


def load_local():
    components = yaml.safe_load(VALUES.read_text())["config"]["destinations"]["components"]
    unmapped = (yaml.safe_load(ALLOWLIST.read_text()) or {}).get("unmapped") or {}
    return components, unmapped


def load_installer():
    pins = (yaml.safe_load(fetch(PINS_URL)) or {}).get("components") or []
    default_repo = (yaml.safe_load(fetch(INSTALLER_VALUES_URL)) or {}).get("ociRepo")
    if not pins:
        raise RuntimeError(f"{PINS_URL} has no `components`: the pins moved or changed shape; update PINS_URL")
    return pins, default_repo
