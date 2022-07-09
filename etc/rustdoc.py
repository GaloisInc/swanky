#!/usr/bin/env python3
"""
This is a wrapper around `cargo doc` which sets some additional parameters. As a result, it accepts
all the same options as `cargo doc`.

In order to run this script, you need to have python3 installed, along with either the toml package,
or the Nix package manager.
"""

import shutil
import shlex
import os
import sys
from pathlib import Path
try:
    import toml
except ImportError:
    nix_shell = shutil.which("nix-shell")
    dont_recurse = 'DONT_RECURSE_RUSTDOC_PY'
    if nix_shell and dont_recurse not in os.environ:
        # We don't want to use the nix-shell shebang, since that'll add a hard dependency on nix.
        os.environ[dont_recurse] = '1'
        cmd = ["python3", os.path.abspath(__file__)] + sys.argv[1:]
        os.execv(nix_shell, [
            nix_shell,
            # INTENTIONALLY impure
            "-p",
            "python3.withPackages (py: [py.toml])",
            "--run",
            " ".join(shlex.quote(arg) for arg in cmd),
        ])
    else:
        raise Exception(
            "This script requires either the `toml` python package, or the Nix package manager"
        )

ROOT = Path(__file__).resolve().parent.parent
cargo_config = toml.loads((ROOT / '.cargo/config').read_text())

flags = cargo_config.get("""target.'cfg(target_arch = "x86_64")'""", dict()).get('rustflags', [])
flags += ["--html-in-header", str(ROOT / 'etc/rustdoc-html-header.html')]
os.environ["RUSTDOCFLAGS"] = " ".join(shlex.quote(flag) for flag in flags)
cargo = shutil.which('cargo')
if cargo is None:
    raise Exception("Cargo was not found!")
os.execv(cargo, [cargo, "doc"] + sys.argv[1:])

