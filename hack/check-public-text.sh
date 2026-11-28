#!/usr/bin/env bash
# This repository is public. Its text must not carry internal planning ids (e.g. D3, X5, A0, C8, T2),
# references to private repositories or their paths (Diego, 2026-11-16; scrub forward, history kept).
set -euo pipefail
cd "$(dirname "$0")/.."
PATTERN='\b(D[0-9]{1,2}[a-z]?|X[1-5]|A[0-4]|B[1-5]|C[2-8]|S[1-9]|S10|T[0-5]|U[1-3])\b|krateo-acmp|\bacmp\b|assembly/slo|\.work/'
ALLOW='^$'  # no allowed exceptions in this repository
# Planted control first: the pattern must catch a known leak, or a silent regex failure reads as clean.
printf 'decided in D3 for X5, see krateo-acmp\n' | perl -e 'my $p = shift; while (<STDIN>) { exit 0 if /$p/ } exit 1' "$PATTERN" || { echo "check-public-text: the pattern caught nothing in its planted control"; exit 2; }
# git grep's status is read on its own, not through `|| true`: under pipefail that turned an ERROR
# (not a repository, bad pattern, unreadable index) into an empty hit list, i.e. "clean".
# 0 = matches, 1 = none, anything else = git grep failed.
rc=0
raw=$(git grep -n -I -P "$PATTERN" -- . ':!go.sum' ':!hack/check-public-text.sh') || rc=$?
if [ "$rc" -gt 1 ]; then
  echo "check-public-text: git grep failed (exit $rc); refusing to call that clean"; exit 2
fi
hits=""
if [ "$rc" -eq 0 ]; then
  hits=$(printf '%s\n' "$raw" | grep -v -E "$ALLOW" || true)
fi
if [ -n "$hits" ]; then
  echo "check-public-text: internal ids or private references in a public repository:"; echo "$hits"; exit 1
fi
echo "check-public-text: clean"
