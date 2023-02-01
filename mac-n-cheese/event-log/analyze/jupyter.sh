#!/usr/bin/env nix-shell
#!nix-shell --pure ../../../etc/nix/mac-n-cheese-event-log-jupyter.nix -i bash
cd $(dirname "$0")
CARGO_TARGET_DIR="$PWD/../../../target/mac-n-cheese-event-log-jupyter"
export CARGO_TARGET_DIR=$(realpath "$CARGO_TARGET_DIR")
mkdir -p "$CARGO_TARGET_DIR"
exec jupyter lab "$@"
