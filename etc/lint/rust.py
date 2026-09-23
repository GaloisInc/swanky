import ctypes
import difflib
import functools
import itertools
import json
import os
import subprocess
import threading
from collections import defaultdict
from pathlib import Path
from typing import Any, List, Optional

import rich
import rich.panel
import rich.syntax
import rich.text
import rich_click as click
import toml
import tree_sitter

from etc import ROOT
from etc.lint import LintResult
from etc.rust import CrateDir, crate_path


def list_cargo_toml_files() -> List[Path]:
    """
    Return Cargo.toml files for crates in Swanky

    This won't return ROOT/Cargo.toml
    """
    return [
        ROOT / x
        for x in subprocess.check_output(
            ["git", "ls-files", "--cached", "--others"], cwd=str(ROOT)
        )
        .decode("ascii")
        .strip()
        .split("\n")
        if x.endswith("Cargo.toml") and ROOT / x != ROOT / "Cargo.toml"
    ]


def check_cargo_lock(ctx: click.Context) -> LintResult:
    """Check Cargo.lock is up-to-date"""
    if (
        subprocess.call(
            ["cargo", "metadata", "--format-version=1", "--locked"],
            stdout=subprocess.DEVNULL,
            cwd=ROOT,
        )
        != 0
    ):
        rich.print("Cargo.lock isn't up to date. Run `cargo check` to fix this.")
        return LintResult.FAILURE
    return LintResult.SUCCESS


def check_core_dependencies(ctx: click.Context) -> LintResult:
    """Check that core crates don't depend on edge crates"""
    try:
        metadata = json.loads(
            subprocess.check_output(
                ["cargo", "metadata", "--format-version=1", "--locked"],
                cwd=ROOT,
            )
        )
    except subprocess.SubprocessError:
        rich.print("`cargo metadata` failed. Is Cargo.lock up-to-date?")
        return LintResult.FAILURE
    edge_crates = set()
    core_crates = set()
    for member in metadata["workspace_members"]:
        is_edge = "/edge/" in member
        is_core = "/core/" in member
        assert is_core ^ is_edge
        if is_edge:
            edge_crates.add(member)
        else:
            core_crates.add(member)
    result = LintResult.SUCCESS
    for node in metadata["resolve"]["nodes"]:
        if node["id"] in core_crates:
            edge_deps = [dep for dep in node["dependencies"] if dep in edge_crates]
            if len(edge_deps) > 0:
                result = LintResult.FAILURE
                rich.print(
                    f"Core crate {repr(node['id'])} has edge dependencies: "
                    + repr(edge_deps)
                )
    return result


def root_cargo_toml() -> Any:
    return toml.loads((ROOT / "Cargo.toml").read_text())


def crates_in_manifest() -> List[Path]:
    return list(
        itertools.chain.from_iterable(
            ROOT.glob(member) for member in root_cargo_toml()["workspace"]["members"]
        )
    )


def crates_in_manifest_are_sorted(ctx: click.Context) -> LintResult:
    """Check that all workspace members are sorted."""
    members = root_cargo_toml()["workspace"]["members"]
    sorted_members = sorted(members)
    if sorted_members != members:
        rich.print("workspace members in /Cargo.toml aren't sorted!")
        rich.get_console().print(
            rich.syntax.Syntax(
                "\n".join(difflib.unified_diff(members, sorted_members, lineterm="")),
                "diff",
            )
        )
        return LintResult.FAILURE
    else:
        return LintResult.SUCCESS


def crates_enumerated_in_workspace(ctx: click.Context) -> LintResult:
    """Check that all crates in Swanky are listed in the workspace"""
    crates_in_manifest_cargo_tomls = set(
        crate / "Cargo.toml" for crate in crates_in_manifest()
    )
    cargo_toml_files = set(list_cargo_toml_files())
    if cargo_toml_files != crates_in_manifest_cargo_tomls:
        rich.print(
            "The following crates aren't listed in /Cargo.toml as a workspace member"
        )
        for cargo_toml in cargo_toml_files - crates_in_manifest_cargo_tomls:
            rich.print(f"- {cargo_toml.parent.relative_to(ROOT)}")
        return LintResult.FAILURE
    else:
        return LintResult.SUCCESS


def workspace_members_are_defined_in_workspace(ctx: click.Context) -> LintResult:
    """Check that all crates in Swanky are defined as workspace dependencies"""
    missing = (
        set(
            toml.loads((crate / "Cargo.toml").read_text())["package"]["name"]
            for crate in crates_in_manifest()
        )
        - root_cargo_toml()["workspace"]["dependencies"].keys()
    )
    if len(missing) > 0:
        rich.print(
            "The following crates aren't listed in the '#BEGIN OUR CRATES' section:"
        )
        for x in sorted(list(missing)):
            rich.print(f"- {x}")
        return LintResult.FAILURE
    else:
        return LintResult.SUCCESS


MISNAMED_CRATES = {
    "diet-mac-and-cheese",
    "humidor",
    "inferno",
    "keyed_arena",
    "fancy-analyzer",
    "fancy-circuits",
    "fancy-garbling",
    "fancy-plaintext",
    "fancy-traits",
    "mac-n-cheese-compiler",
    "mac-n-cheese-event-log",
    "mac-n-cheese-inspector",
    "mac-n-cheese-ir",
    "mac-n-cheese-runner",
    "mac-n-cheese-sieve-parser",
    "mac-n-cheese-vole",
    "mac-n-cheese-wire-map",
    "popsicle",
    "schmivitz",
    "simple-arith-circuit",
    "vectoreyes",
    "web-mac-n-cheese-wasm",
    "web-mac-n-cheese-websocket",
    "zkv",
}


def check_crate_paths(ctx: click.Context) -> LintResult:
    """
    Check that crate names match their paths

    For example:
    swanky-cool-crate: ./edge/cool-crate, ./edge/cool/crate (both valid)

    If ./edge/cool exists (and isn't a crate), then we _require_ that cool-crate live under
    that directory.
    """
    result = LintResult.SUCCESS
    for cargo_toml in list_cargo_toml_files():
        name = toml.loads(cargo_toml.read_text())["package"]["name"]
        if name in MISNAMED_CRATES:
            continue

        def report_error(err: str) -> None:
            nonlocal result
            result = LintResult.FAILURE
            rich.print(f"[bold][underline]{name}[/underline][/bold] is misnamed: {err}")

        if not name.startswith("swanky-"):
            report_error("does not start with 'swanky-'")
            continue
        expected_paths = [
            crate_path(name, CrateDir.CORE),
            crate_path(name, CrateDir.EDGE),
        ]
        if cargo_toml.parent not in expected_paths:
            expected_paths_str = ", ".join(
                str(p.relative_to(ROOT)) for p in expected_paths
            )
            report_error(
                f"Expected at one of {expected_paths_str}, "
                + f"not {cargo_toml.parent.relative_to(ROOT)}"
            )
    return result


def validate_crate_manifests(ctx: click.Context) -> LintResult:
    """Validate crate manifests to ensure they adhere to workspace rules."""
    any_errors = False
    inherited_keys = set(root_cargo_toml()["workspace"]["package"].keys())
    for crate in crates_in_manifest():
        crate_toml = (crate / "Cargo.toml").relative_to(ROOT)
        data = toml.loads((crate / "Cargo.toml").read_text())
        if data.get("lints", dict()).get("workspace", False) != True:
            any_errors = True
            print(f"{crate_toml} is missing:")
            rich.get_console().print(
                rich.syntax.Syntax("[lints]\nworkspace = true", "toml")
            )
        missing_workspace_keys = inherited_keys - set(
            k
            for k, v in data["package"].items()
            if isinstance(v, dict) and v.get("workspace") == True
        )
        if len(missing_workspace_keys) > 0:
            any_errors = True
            rich.print(
                f"[bold][underline]{crate_toml}[/underline] missing workspace package keys[/bold]"
            )
            rich.print("Add the following to the TOML file to resolve the problem:")
            rich.get_console().print(
                rich.syntax.Syntax(
                    "[package]\n"
                    + "\n".join(
                        f"{k}.workspace = true"
                        for k in sorted(list(missing_workspace_keys))
                    ),
                    "toml",
                )
            )
            rich.print("")
        deps_needing_workspace = defaultdict(lambda: set())
        sections = []
        for section in ["dependencies", "dev-dependencies", "build-dependencies"]:
            sections.append((section, data.get(section, dict())))
            for target_name, target in data.get("target", dict()).items():
                sections.append(
                    (f"target.'{target_name}'.section", target.get(section, dict()))
                )
        for section, section_contents in sections:
            for k, v in section_contents.items():
                if (not isinstance(v, dict)) or v.get("workspace") != True:
                    deps_needing_workspace[section].add(k)
        if len(deps_needing_workspace) > 0:
            code = ""
            for section, deps in deps_needing_workspace.items():
                code += f"[{section}]\n"
                for dep in sorted(list(deps)):
                    code += f"{dep}.workspace = true\n"
            rich.print(
                f"[bold][underline]{crate_toml}[/underline] isn't using a workspace dependency[/bold]"
            )
            rich.print("Here are the keys that should change:")
            rich.get_console().print(rich.syntax.Syntax(code, "toml"))
            rich.print("")
            any_errors = True
    return LintResult.FAILURE if any_errors else LintResult.SUCCESS


def cargo_deny(ctx: click.Context) -> LintResult:
    """
    Check that we only use liberally-licensed dependencies
    """
    if (
        subprocess.call(
            [
                "cargo",
                "deny",
                "--workspace",
                "--offline",
                "check",
                "--config",
                str(ROOT / "etc/deny.toml"),
                "bans",
                "licenses",
                "sources",
            ],
            cwd=ROOT,
        )
        != 0
    ):
        return LintResult.FAILURE
    else:
        return LintResult.SUCCESS


# As of this writing, these libraries don't require documentation.
LIBS_NOT_YET_DOCUMENTED = {
    "edge/field-fft/src/lib.rs",
    "edge/diet-mac-and-cheese/web-mac-and-cheese/wasm/src/lib.rs",
    "edge/diet-mac-and-cheese/web-mac-and-cheese/websocket/src/lib.rs",
    "edge/sieve-ir-parser/src/lib.rs",
    "edge/keyed_arena/src/lib.rs",
    "edge/mac-n-cheese/event-log/src/lib.rs",
    "edge/mac-n-cheese/ir/src/lib.rs",
    "edge/mac-n-cheese/sieve-parser/src/lib.rs",
    "edge/mac-n-cheese/vole/src/lib.rs",
    "edge/mac-n-cheese/wire-map/src/lib.rs",
}


_MISSING_DOCS_QUERY = """
(source_file
    (inner_attribute_item (attribute
        (identifier) @deny
        (#eq? @deny "deny")
        arguments: (token_tree
            (identifier) @lint_name
            (#eq? @lint_name "missing_docs")
        )
    )))
"""


@functools.cache
def _tree_sitter_rust_language() -> tree_sitter.Language:
    so_paths = []
    for entry in os.environ["buildInputs"].split():
        if "tree-sitter-rust" in entry:
            so_paths.append(entry)
    if len(so_paths) != 1:
        raise Exception(
            f"Unexpected tree sitter rust grammar candidate list {repr(so_paths)}"
        )
    lib = ctypes.cdll.LoadLibrary(os.path.join(so_paths[0], "parser"))
    getter_function = lib.tree_sitter_rust
    getter_function.restype = ctypes.c_void_p
    return tree_sitter.Language(getter_function())


_MISSING_DOCS_QUERY_OBJ: Optional["tree_sitter.Query"] = None
_MISSING_DOCS_PARSER: Optional["tree_sitter.Parser"] = None
_MISSING_DOCS_QUERY_LOCK = threading.Lock()


def _contains_deny_missing_docs(code: bytes) -> bool:
    global _MISSING_DOCS_QUERY_LOCK
    global _MISSING_DOCS_QUERY_OBJ
    global _MISSING_DOCS_PARSER
    with _MISSING_DOCS_QUERY_LOCK:
        if _MISSING_DOCS_QUERY_OBJ is None:
            lang = _tree_sitter_rust_language()
            _MISSING_DOCS_PARSER = tree_sitter.Parser(lang)
            _MISSING_DOCS_QUERY_OBJ = lang.query(_MISSING_DOCS_QUERY)
        assert _MISSING_DOCS_PARSER is not None
        return (
            len(
                tree_sitter.QueryCursor(_MISSING_DOCS_QUERY_OBJ).captures(
                    _MISSING_DOCS_PARSER.parse(code).root_node
                )
            )
            != 0
        )


def require_deny_missing_docs(ctx: click.Context) -> LintResult:
    """
    Require #![deny(missing_docs)] for all of our crates.
    """

    non_compliant = []
    for crate in crates_in_manifest():
        lib_rs = crate / "src/lib.rs"
        if not lib_rs.exists():
            continue
        if str(lib_rs.relative_to(ROOT)) in LIBS_NOT_YET_DOCUMENTED:
            continue
        if not _contains_deny_missing_docs(lib_rs.read_bytes()):
            non_compliant.append(lib_rs.relative_to(ROOT))
    non_compliant.sort()
    if len(non_compliant) > 0:
        print("The following files are missing a '#![deny(missing_docs)]' directive:")
        for x in non_compliant:
            print(f"- {x}")
        return LintResult.FAILURE
    else:
        return LintResult.SUCCESS
