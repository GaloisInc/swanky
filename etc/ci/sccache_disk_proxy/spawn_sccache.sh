#!/usr/bin/env nix-shell
#!nix-shell --pure -i bash ./shell.nix
set -euxo pipefail
export SWANKY_CACHE_DIR="$1"
exec start_sccache
