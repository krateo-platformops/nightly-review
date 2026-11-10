// Command nightly-review is one nightly platform self-review: it gathers the night's evidence, asks the
// tool-less reviewer for structured proposals, validates and redacts them, and records them as Proposal
// objects on a ReviewRun. It runs once and exits. The schedule lives in the CronJob, not in a loop inside
// the process, so a run that wedges is visible as a Job that never completed rather than a pod that
// looks healthy.
package main

import (
	"context"
	"os"

	"github.com/krateo-platformops/nightly-review/internal/review"
)

func main() {
	os.Exit(review.Main(context.Background()))
}
