#!/usr/bin/env nix-shell
#!nix-shell --keep NIX_REMOTE --keep SWANKY_CACHE_DIR --keep TMPDIR --pure -i bash ../nix/ci.nix
source ./etc/ci/sccache_disk_proxy/env.sh
exec python3 ./etc/ci/main.py "$@"
