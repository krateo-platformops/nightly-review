//go:build drift

package drift

// The live drift check (drift/test_destinations_drift.py). Run by .github/workflows/drift.yaml on every
// pull request, every push to main and daily — daily because the thing that drifts is the INSTALLER, and
// a new pin there opens no pull request here. It needs the network and FAILS without it; drift_test.go
// holds the offline tests of the logic.

import (
	"strings"
	"testing"
)

func TestEveryPinnedComponentHasADestinationOrAReviewedReasonAndTheRightOrg(t *testing.T) {
	pins, defaultRepo, err := LoadInstaller()
	if err != nil {
		t.Fatal(err)
	}
	components, unmapped, err := LoadLocal()
	if err != nil {
		t.Fatal(err)
	}
	if found := Problems(pins, defaultRepo, components, unmapped); len(found) != 0 {
		t.Fatal("config.destinations.components has drifted from krateo-platformops/installer chart/files/component-pins.yaml:\n  - " +
			strings.Join(found, "\n  - "))
	}
}

func TestEveryNotPinnedExceptionHasAReasonAndNoDestination(t *testing.T) {
	found, err := NotPinnedProblems()
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 {
		t.Fatal("drift/unmapped-components.yaml notPinned:\n  - " + strings.Join(found, "\n  - "))
	}
}
