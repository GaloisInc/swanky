#!/usr/bin/env python3
# This wrapper is invoked via the RUSTC_WRAPPER environment variable.
# USAGE: ./rustc.py rustc <args>
# It exists to let us customize the arguments to rustc in a way that Cargo
# won't let us do easily.
#
# 1. We want to apply `--deny warnings' to just the code that lives in Swanky. We don't want to
#    --deny warnings on dependencies, since they may have warnings.
# 2. We want to tell rust to use lld as the linker in CI (since it's faster). It's not easy for us
#    to _add_ rustflags using Cargo's options without overwriting the existing flags (see
#    https://github.com/rust-lang/cargo/issues/5376).
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
args = sys.argv[1:]

# Apply --deny warnings to just _our_ code
rs_files_in_args = [arg for arg in args if ".rs" in arg]
if len(rs_files_in_args) > 0:
    assert (
        len(rs_files_in_args) == 1
    ), f"{repr(rs_files_in_args)} contains more than one entry for {repr(args)}"
    rs_file = Path(rs_files_in_args[0])
    if rs_file.resolve().is_relative_to(ROOT):
        # only deny warnings for swanky code
        args += ["--deny", "warnings"]

# Use lld as the linker.
args += ["-Clinker=clang", "-Clinker-flavor=gcc", "-Clink-arg=-fuse-ld=lld"]

# Execute sccache to cache the output of rustc
os.execvp("sccache", ["sccache"] + args)
