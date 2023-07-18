#!/usr/bin/env python3
USAGE = """
USAGE: etc/new-crate.py swanky-foo swanky-baz

This will add new swanky crates, register them, and set them up with our preferred settings.
"""

import sys
from pathlib import Path
from string import Template

ROOT = Path(__file__).resolve().parent.parent

_TOML_TEMPLATE = Template(
    """
[package]
name = "$crate"
authors.workspace = true
edition.workspace = true
license.workspace = true
publish.workspace = true
version.workspace = true

[dependencies]
# my_dependency.workspace = true
""".strip()
    + "\n"
)

if __name__ == "__main__":
    if len(sys.argv) == 1:
        print(USAGE)
        sys.exit(1)
    for crate in sys.argv[1:]:
        if not crate.startswith("swanky-"):
            print(f"{repr(crate)} doesn't start with 'swanky-'")
            sys.exit(1)
        dst = ROOT / "crates" / crate.replace("swanky-", "", 1)
        if dst.exists():
            print(f"{dst} already exists. Skipping.")
        dst.mkdir()
        (dst / "Cargo.toml").write_text(_TOML_TEMPLATE.safe_substitute(crate=crate))
        (dst / "src").mkdir()
        (dst / "src" / "lib.rs").write_text("")
        cargo_toml_path = ROOT / "Cargo.toml"
        cargo_toml = cargo_toml_path.read_text()
        lines = cargo_toml.split("\n")
        assert "# BEGIN OUR CRATES" in lines
        assert "# END OUR CRATES" in lines
        begin_idx = lines.index("# BEGIN OUR CRATES")
        end_idx = lines.index("# END OUR CRATES")
        path = dst.relative_to(ROOT)
        lines = (
            lines[0 : begin_idx + 1]
            + sorted(
                lines[begin_idx + 1 : end_idx] + [f'{crate} = {{ path = "{path}" }}']
            )
            + lines[end_idx:]
        )
        cargo_toml = "\n".join(lines)
        cargo_toml_path.write_text(cargo_toml)
