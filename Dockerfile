# Build environment
# -----------------
FROM --platform=$BUILDPLATFORM golang:1.26-bookworm AS builder
LABEL stage=builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src

COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

COPY main.go main.go
COPY internal/ internal/

# Build. Deliberately few dependencies: this binary assembles a corpus and hands it to a model, and every
# extra module is more code with access to that corpus before it is redacted. lib/pq rather than a cgo
# driver: pure Go, so no libpq and a static binary, for the one read-only database this service queries.
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /bin/nightly-review main.go

# Deployment environment
# ----------------------
FROM gcr.io/distroless/static:nonroot

COPY --from=builder /bin/nightly-review /bin/nightly-review

USER 65532:65532

# Runs once and exits. The schedule lives in the CronJob, not in a loop inside the process, so a run
# that wedges is visible as a Job that never completed rather than a pod that looks healthy.
ENTRYPOINT ["/bin/nightly-review"]
