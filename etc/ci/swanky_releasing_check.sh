#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# We intentionally don't enable the 'x' option to avoid leaking our job token.

TMP="$(mktemp -d)"
trap "rm -rf $TMP" EXIT
git clone --depth 1 https://gitlab-ci-token:${CI_JOB_TOKEN}@gitlab-ext.galois.com/crypto/swanky_releasing.git $TMP
export CI_MERGE_REQUEST_LABELS="${CI_MERGE_REQUEST_LABELS:-}"
"$TMP/check-swanky.sh"

