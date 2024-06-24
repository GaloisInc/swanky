#!/usr/bin/env python3
# This wrapper is invoked via the RUSTC_WRAPPER environment variable.
# USAGE: ./rustc.py rustc <args>
# It exists to let us customize the arguments to rustc in a way that Cargo
# won't let us do easily.
#
# 1. We want to apply `--deny warnings' to just the code that lives in Swanky. We don't want to
#    --deny warnings on dependencies, since they may have warnings.
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

os.execvp(args[0], args)
