"""The live drift check. Run by .github/workflows/drift.yaml on every pull request, every push to main and
daily — daily because the thing that drifts is the INSTALLER, and a new pin there opens no pull request here.
It needs the network and FAILS without it; tests/ holds the offline tests of the logic."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import destinations_drift as D


def test_every_pinned_component_has_a_destination_or_a_reviewed_reason_and_the_right_org():
    pins, default_repo = D.load_installer()
    components, unmapped = D.load_local()
    found = D.problems(pins, default_repo, components, unmapped)
    assert not found, ("config.destinations.components has drifted from krateo-platformops/installer "
                       "chart/files/component-pins.yaml:\n  - " + "\n  - ".join(found))


def test_every_not_pinned_exception_has_a_reason_and_no_destination():
    found = D.not_pinned_problems()
    assert not found, "drift/unmapped-components.yaml notPinned:\n  - " + "\n  - ".join(found)
