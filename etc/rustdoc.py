#!/usr/bin/env python3
"""
This is a wrapper around `cargo doc` which sets some additional parameters. As a result, it accepts
all the same options as `cargo doc`.

In order to run this script, you need to have python3 installed, along with the toml package.
"""

import os
import shlex
import shutil
import sys
from pathlib import Path

import toml

ROOT = Path(__file__).resolve().parent.parent
cargo_config = toml.loads((ROOT / ".cargo/config").read_text())

flags = cargo_config.get("""target.'cfg(target_arch = "x86_64")'""", dict()).get(
    "rustflags", []
)
flags += ["--html-in-header", str(ROOT / "etc/rustdoc-html-header.html")]
os.environ["RUSTDOCFLAGS"] = " ".join(shlex.quote(flag) for flag in flags)
cargo = shutil.which("cargo")
if cargo is None:
    raise Exception("Cargo was not found!")
os.execv(cargo, [cargo, "doc"] + sys.argv[1:])
