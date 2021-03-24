#!/usr/bin/env nix-shell
#!nix-shell --pure -i bash default.nix
set -e -x
cd $(dirname "$0")
black *.py
isort --profile=black *.py
