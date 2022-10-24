#!/usr/bin/env python3
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
args = sys.argv[1:]
rs_files_in_args = [arg for arg in args if ".rs" in arg]
if len(rs_files_in_args) > 0:
    assert (
        len(rs_files_in_args) == 1
    ), f"{repr(rs_files_in_args)} contains more than one entry for {repr(args)}"
    rs_file = Path(rs_files_in_args[0])
    if rs_file.resolve().is_relative_to(ROOT):
        # only deny warnings for swanky code
        args += ["--deny", "warnings"]
os.execvp("sccache", ["sccache"] + args)
