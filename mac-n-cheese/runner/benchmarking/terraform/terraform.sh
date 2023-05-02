#!/usr/bin/env nix-shell
#! nix-shell --pure -i bash ../../../../etc/nix/mac-n-cheese-benchmark.nix
exec terraform "$@"
