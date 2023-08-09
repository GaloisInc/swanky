#!/usr/bin/env nix-shell
#!nix-shell --keep NIX_REMOTE --keep SWANKY_CACHE_DIR --keep TMPDIR --pure -i python3 ../nix/ci.nix

import atexit
import base64
import contextlib
import enum
import itertools
import os
import shutil
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from hashlib import sha256
from pathlib import Path
from typing import Dict, List
from uuid import uuid4

import toml
import typer

ROOT = Path(__file__).resolve().parent.parent.parent
CARGO_CONFIG_FILE = ROOT / ".cargo/config"

app = typer.Typer()


def restore_cargo_config():
    subprocess.check_call(["git", "checkout", ".cargo/config"], cwd=str(ROOT))


def pretty_check_call(
    args, help_on_failure: str = "", extra_env: Dict[str, str] = {}, stdout=None
):
    rc = subprocess.call(args, cwd=str(ROOT), env=os.environ | extra_env, stdout=stdout)
    if rc != 0:
        typer.secho(f"ERROR: Command {args} failed with {rc}", fg=typer.colors.RED)
        if help_on_failure:
            typer.secho(help_on_failure)
        raise typer.Exit(code=1)


gitlab_ci_section_stack = []


@contextlib.contextmanager
def gitlab_ci_section(name: str):
    "While this context is active, render the output under a collapsable section"
    global gitlab_ci_section_stack
    ident = uuid4()
    gitlab_ci_section_stack.append(name)
    sys.stdout.write(f"\x1b[0Ksection_start:{int(time.time())}:{ident}\r\x1b[0K")
    typer.secho(" > ".join(gitlab_ci_section_stack), underline=True, bold=True)
    sys.stdout.flush()
    try:
        yield
    finally:
        gitlab_ci_section_stack.pop()
        sys.stdout.write(f"\x1b[0Ksection_end:{int(time.time())}:{ident}\r\x1b[0K\n")
        sys.stdout.flush()


def build_and_test(
    features: List[str], force_haswell: bool = False, cache_test_output: bool = False
):
    with gitlab_ci_section(
        f"build_and_run_test(features={features}, "
        "force_haswell={force_haswell}, "
        "cache_test_output={cache_test_output})"
    ):
        restore_cargo_config()
        if force_haswell:
            flags = [
                "-C",
                "target-cpu=haswell",
                "-C",
                "target-feature=+aes",
                "--cfg",
                'vectoreyes_target_cpu="haswell"',
            ]
            CARGO_CONFIG_FILE.write_text(
                toml.dumps(
                    {
                        "build": {
                            "rustflags": flags,
                            "rustdocflags": flags,
                        }
                    }
                )
            )
        if len(features) > 0:
            features_args = ["--features", ",".join(features)]
        else:
            features_args = []
        with gitlab_ci_section("cargo build"):
            pretty_check_call(
                ["cargo", "build", "--workspace", "--all-targets", "--verbose"]
                + features_args
            )
        with gitlab_ci_section("doctests"):
            # Doctests currently don't use the cargo runner :(
            pretty_check_call(
                ["cargo", "test", "--workspace", "--doc", "--verbose"] + features_args
            )
        with gitlab_ci_section("tests"):
            pretty_check_call(
                [
                    "cargo",
                    "nextest",
                    "run",
                    "--no-fail-fast",
                    "--workspace",
                    "--verbose",
                ]
                + features_args,
                extra_env={
                    "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER": str(
                        ROOT / "etc/ci/wrappers/caching_test_runner.py"
                    ),
                },
            )


@app.command()
def ci(nightly: bool = False):
    os.environ["CARGO_INCREMENTAL"] = "0"
    os.environ["PROPTEST_CASES"] = "256"
    os.environ["NIX_PATH"] = f"nixpkgs={ROOT}/etc/nix/pkgs.nix"
    drv_path = (
        subprocess.check_output(
            ["nix-instantiate", "--no-gc-warning", str(ROOT / "etc/nix/ci.nix")]
        )
        .decode("ascii")
        .strip()
    )
    nix_cache_key = (
        base64.urlsafe_b64encode(
            sha256(
                drv_path.encode("ascii") + b"\n" + Path(drv_path).read_bytes()
            ).digest()
        )
        .decode("ascii")
        .replace("=", "")
    )  # strip off the padding
    base_cache_dir = Path(os.environ["SWANKY_CACHE_DIR"])
    if not base_cache_dir.exists():
        raise Exception(f"{base_cache_dir} does not exist")
    swanky_cache_dir = base_cache_dir / nix_cache_key
    swanky_cache_dir.mkdir(exist_ok=True)
    os.environ["RUST_BACKTRACE"] = "1"
    # When this process exits, stdin will be closed, and it'll (hopefully) clean up the subprocess.
    # This only happens once, so we're not gonna worry about a zombie.
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        is_ready = tmp / "sccache-ready"
        sccache_server = subprocess.Popen(
            [
                str(ROOT / "etc/ci/sccache_disk_proxy/spawn_sccache.sh"),
                str(swanky_cache_dir),
                str(is_ready),
            ],
            stdin=subprocess.PIPE,
        )
        atexit.register(sccache_server.terminate)
        # This timeout is long since nix might need to build things.
        for i in range(60_000):
            if is_ready.exists():
                break
            time.sleep(1)
        else:
            raise Exception("sccache never spawned")
    os.environ["RUSTC_WRAPPER"] = str(ROOT / "etc/ci/wrappers/rustc.py")
    os.environ["CC"] = str(ROOT / "etc/ci/wrappers/cc.sh")
    os.environ["CXX"] = str(ROOT / "etc/ci/wrappers/cxx.sh")
    os.environ["CARGO_HOME"] = str(swanky_cache_dir / "cargo-home")
    os.environ["SWANKY_CACHE_DIR"] = str(swanky_cache_dir)
    os.environ["CARGO_TARGET_X86_64_UNKNOWN_LINUX_LINKER"] = str(
        ROOT / "etc/ci/wrappers/linker.sh"
    )
    if shutil.which("flatc"):
        # By ensuring that flatc isn't in PATH, it will make sure that flatbuffers files have been
        # correctly checked into the repo.
        raise Exception("flatc SHOULD NOT be in the CI PATH.")
    # Check the Cargo.lock file FIRST so that tools don't have a chance to update it before we can
    # check it.
    with gitlab_ci_section("Check Cargo.lock is up-to-date"):
        pretty_check_call(
            ["cargo", "metadata", "--format-version=1", "--locked"],
            stdout=subprocess.DEVNULL,
            help_on_failure="To fix this, run `cargo update`",
        )
    with gitlab_ci_section("Code Formatting"):
        pretty_check_call(
            ["cargo", "fmt", "--", "--check"],
            help_on_failure="To fix this, try running `cargo fmt`",
        )
        pretty_check_call(["black", ".", "--check"])
        pretty_check_call(
            ["isort", "--profile", "black", "--check"]
            + [
                x
                for x in subprocess.check_output(["git", "ls-files"], cwd=str(ROOT))
                .decode("ascii")
                .strip()
                .split("\n")
                if x.endswith(".py")
            ]
        )
    with gitlab_ci_section("Check flatbuffer version matches"):
        flatbuffers_version = toml.loads((ROOT / "Cargo.toml").read_text())[
            "workspace"
        ]["dependencies"]["flatbuffers"]
        flatc_ver_path = "crates/flatbuffer-build/src/flatc-ver.txt"
        actual_flatc_ver = (ROOT / flatc_ver_path).read_text().strip()
        expected_flatc_ver = f"flatc version {flatbuffers_version}"
        if actual_flatc_ver != expected_flatc_ver:
            typer.secho(
                f"ERROR: {flatc_ver_path} contains {repr(actual_flatc_ver)}, which doesn't match "
                + f"{repr(expected_flatc_ver)}, as set in /Cargo.toml",
                fg=typer.colors.RED,
            )
            raise typer.Exit(code=1)
    with gitlab_ci_section("Check Cargo.toml files"):
        any_errors = False
        cargo_toml_files = [
            ROOT / x
            for x in subprocess.check_output(["git", "ls-files"], cwd=str(ROOT))
            .decode("ascii")
            .strip()
            .split("\n")
            if x.endswith("Cargo.toml")
        ]
        root_cargo_toml = toml.loads((ROOT / "Cargo.toml").read_text())
        crates_in_manifest = list(
            itertools.chain.from_iterable(
                ROOT.glob(member) for member in root_cargo_toml["workspace"]["members"]
            )
        )
        crates_in_manifest_cargo_tomls = set(
            crate / "Cargo.toml" for crate in crates_in_manifest
        )
        for path in cargo_toml_files:
            data = toml.loads(path.read_text())
            if "workspace" in data:
                continue
            if path not in crates_in_manifest_cargo_tomls:
                any_errors = True
                typer.secho(
                    f"ERROR: {path} is not listed as a cargo workspace member",
                    fg=typer.colors.RED,
                )
            missing_workspace_keys = set(
                root_cargo_toml["workspace"]["package"].keys()
            ) - set(
                k
                for k, v in data["package"].items()
                if isinstance(v, dict) and v.get("workspace") == True
            )
            if len(missing_workspace_keys) > 0:
                typer.secho(
                    f"ERROR: {path} missing workspace package keys", fg=typer.colors.RED
                )
                typer.secho(
                    f"Add the following to {path} (in the [package] section) to resolve the problem "
                    "(and remove any duplicate keys)"
                )
                for k in sorted(list(missing_workspace_keys)):
                    typer.secho(f"    {k}.workspace = true")
                any_errors = True
            deps_needing_workspace = defaultdict(lambda: set())
            # TODO: this list of sections isn't complete, since these also exist in target-specific sections.
            for section in ["dependencies", "dev-dependencies", "build-dependencies"]:
                for k, v in data.get(section, dict()).items():
                    if (not isinstance(v, dict)) or v.get("workspace") != True:
                        deps_needing_workspace[section].add(k)
            if len(deps_needing_workspace) > 0:
                any_errors = True
                typer.secho(
                    f"ERROR: {path} isn't using a workspace dependency",
                    fg=typer.colors.RED,
                )
                typer.secho("Below are keys that should change.")
                for section, deps in deps_needing_workspace.items():
                    typer.secho(f"    [{section}]")
                    for dep in sorted(list(deps)):
                        typer.secho(f"    {dep}.workspace = true")
                typer.secho(
                    "See https://gist.github.com/kriogenia/ea08d190ea8a008bbcceb17ebeb90676 as an"
                    " example of how to specify feature flags on the dependencies, if you'd like."
                )
                typer.secho("")
        if any_errors:
            raise typer.Exit(code=1)
    with gitlab_ci_section("Checking Dependencies (with cargo-deny)"):
        # Check dependencies with https://github.com/EmbarkStudios/cargo-deny
        # Check that we only use liberally-licensed dependencies.
        # On nightly, also check whether any of our dependencies are vulnerable.
        if nightly:
            subprocess.check_call(["cargo", "deny", "--workspace", "check"], cwd=ROOT)
        else:
            # These offline checks should run _after_ the Cargo.lock update above.
            for check in ["bans", "licenses"]:
                subprocess.check_call(
                    ["cargo", "deny", "--workspace", "--offline", "check", check],
                    cwd=ROOT,
                )
    with gitlab_ci_section("Code Generation"):

        def compute_cache_key():
            hashes = []
            for path in (
                subprocess.check_output(
                    [
                        "git",
                        "ls-files",
                        "vectoreyes/src/codegen",
                        "vectoreyes/src/generated",
                    ],
                    cwd=ROOT,
                )
                .strip()
                .decode("ascii")
                .split("\n")
            ):
                path = Path(path)
                hashes.append((str(path), sha256(path.read_bytes()).hexdigest()))
            hashes.sort()
            return sha256(
                "\n".join(f"{path} || {h}" for path, h in hashes).encode("ascii")
            ).hexdigest()

        cache_key = compute_cache_key()
        cache_key_file = swanky_cache_dir / "good-vectoreyes-codegen" / cache_key
        if not cache_key_file.exists():
            pretty_check_call([ROOT / "vectoreyes/src/codegen/generate.py"])
            if compute_cache_key() != cache_key:
                typer.secho(
                    "ERROR: Re-run `vectoreyes/src/codegen/generate.py`",
                    fg=typer.colors.RED,
                )
                raise typer.Exit(code=1)
            cache_key_file.parent.mkdir(exist_ok=True)
            cache_key_file.write_text("")
    with gitlab_ci_section("Functionality Tests"):
        if nightly:
            for force_haswell in [True, False]:
                build_and_test(features=[], force_haswell=force_haswell)
                build_and_test(features=["serde"], force_haswell=force_haswell)
            with gitlab_ci_section("Test vectoreyes scalar against itself"):
                CARGO_CONFIG_FILE.unlink()
                pretty_check_call(["cargo", "test", "-p", "vectoreyes", "--verbose"])
        else:
            build_and_test(features=["serde"], cache_test_output=True)


if __name__ == "__main__":
    import logging

    import rich.traceback
    from rich.logging import RichHandler

    rich.traceback.install(show_locals=True)

    logging.basicConfig(
        level="NOTSET",
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True)],
    )
    app()
