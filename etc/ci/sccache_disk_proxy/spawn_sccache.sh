#!/usr/bin/env nix-shell
#!nix-shell --pure --keep SCCACHE_ENDPOINT -i bash ./shell.nix
set -euxo pipefail
export SWANKY_CACHE_DIR="$1"
export SCCACHE_STARTUP_NOTIFY="$2"
exec start_sccache
