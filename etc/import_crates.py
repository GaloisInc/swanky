import json
import subprocess
import tomllib
from collections import defaultdict
from pathlib import Path

import rich_click as click

from etc import ROOT


@click.command()
def import_crates() -> None:
    """
    Add missing crate dependencies to Cargo.toml

    This command will run cargo to determine what crate dependencies are missing, and then add them
    to the Cargo.toml file.
    """
    dependency_map = {
        dep.replace("-", "_"): dep
        for dep in tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"][
            "dependencies"
        ]
    }
    # We might not see all errors in a single cargo invocation, so we keep running cargo until
    # we stop seeing errors we can address.
    keep_running = True
    while keep_running:
        keep_running = False
        for cargo_arg, section in [
            ("--lib", "dependencies"),
            ("--all-targets", "dev-dependencies"),
        ]:
            out = subprocess.run(
                ["cargo", "check", "--workspace", "--message-format=json", cargo_arg],
                cwd=ROOT,
                check=False,
                stdout=subprocess.PIPE,
            )
            missing_imports = defaultdict(set)
            for line in out.stdout.decode("utf-8").split("\n"):
                line = line.strip()
                if line == "":
                    continue
                data = json.loads(line)
                if "manifest_path" not in data:
                    continue
                if not Path(data["manifest_path"]).is_relative_to(ROOT):
                    continue
                message = data.get("message", {})
                # E0432 is unresolved import and E0433 is undeclared crate or module
                if (message.get("code") or {}).get("code", "") not in [
                    "E0432",
                    "E0433",
                ]:
                    continue
                missing_import = message["message"].split("`")[1]
                if missing_import is not None:
                    crate = dependency_map.get(missing_import)
                    if crate:
                        missing_imports[Path(data["manifest_path"])].add(crate)
            for toml_path, deps_set in missing_imports.items():
                deps = list(deps_set)
                deps.sort()
                deps.reverse()
                lines = toml_path.read_text().split("\n")
                try:
                    deps_idx = lines.index(f"[{section}]")
                except ValueError:
                    lines.append(f"[{section}]")
                    deps_idx = len(lines)
                for dep in deps:
                    lines.insert(deps_idx + 1, f"{dep}.workspace = true")
                toml_path.write_text("\n".join(lines))
                print(f"New {section} ({sorted(deps)}) added to {toml_path}")
                keep_running = True
