#!/usr/bin/env bash
exec cc "$@" --fuse-ld=$(command -v mold)
