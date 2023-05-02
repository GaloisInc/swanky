#!/usr/bin/env bash
exec cc "$@" --fuse-ld=lld
