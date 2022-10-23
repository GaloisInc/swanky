#!/usr/bin/env nix-shell
#!nix-shell --keep NIX_REMOTE --keep TMPDIR --pure -i python3 ../etc/nix/ci.nix

import base64
import contextlib
import enum
import os
import subprocess
import sys
import time
from hashlib import sha256
from pathlib import Path
from typing import List
from uuid import uuid4

import toml
import typer

ROOT = Path(__file__).resolve().parent.parent.parent
CARGO_CONFIG_FILE = ROOT / ".cargo/config"

app = typer.Typer()


def restore_cargo_config():
    subprocess.check_call(["git", "checkout", ".cargo/config"], cwd=str(ROOT))


def pretty_check_call(args, help_on_failure: str = ""):
    rc = subprocess.call(args, cwd=str(ROOT))
    if rc != 0:
        typer.secho(f"Command {args} failed with {rc}", fg=typer.colors.RED)
        if help_on_failure:
            print(help_on_failure)
        raise typer.Exit(code=1)


@contextlib.contextmanager
def gitlab_ci_section(name: str):
    ident = uuid4()
    sys.stdout.write(
        f"\x1b[0Ksection_start:{int(time.time())}:{ident}\r\x1b[0K{name}\n"
    )
    sys.stdout.flush()
    try:
        yield
    finally:
        sys.stdout.write(f"\x1b[0Ksection_end:{int(time.time())}:{ident}\r\x1b[0K\n")
        sys.stdout.flush()


def build_and_test(features: List[str], force_haswell: bool = False):
    with gitlab_ci_section(
        f"build_and_run_test(features={features}, force_haswell={force_haswell})"
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
                ["cargo", "build", "--workspace", "--all-targets"] + features_args
            )
        with gitlab_ci_section("doctests"):
            pretty_check_call(["cargo", "test", "--workspace", "--doc"] + features_args)
        with gitlab_ci_section("tests"):
            pretty_check_call(
                ["cargo", "nextest", "run", "--no-fail-fast", "--workspace"]
                + features_args
            )


@app.command()
def ci(nightly: bool = False):
    os.environ["CARGO_INCREMENTAL"] = "0"
    os.environ["PROPTEST_CASES"] = "256"
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
    base_cache_dir = Path("/var/lib/swanky-sccache/")
    if not base_cache_dir.exists():
        raise Exception(f"{base_cache_dir} does not exist")
    swanky_cache_dir = base_cache_dir / nix_cache_key
    swanky_cache_dir.mkdir(exist_ok=True)
    os.environ["RUST_BACKTRACE"] = "1"
    subprocess.check_call(
        [
            str(ROOT / "etc/ci/sccache_disk_proxy/spawn_sccache.sh"),
            str(swanky_cache_dir),
        ]
    )
    os.environ["RUSTC_WRAPPER"] = str(ROOT / "etc/ci/wrappers/rustc.py")
    os.environ["CC"] = str(ROOT / "etc/ci/wrappers/cc.sh")
    os.environ["CXX"] = str(ROOT / "etc/ci/wrappers/cxx.sh")
    os.environ["CARGO_HOME"] = str(swanky_cache_dir / "cargo-home")
    with gitlab_ci_section("Code Formatting"):
        pretty_check_call(
            ["cargo", "fmt", "--", "--check"],
            help_on_failure="To fix this, try running `cargo fmt`",
        )
        pretty_check_call(["black", ".", "--check"])
        pretty_check_call(["isort", ".", "--profile", "black", "--gitignore"])
    with gitlab_ci_section("Code Generation"):

        def compute_cache_key():
            queue = [
                ROOT / "vectoreyes" / "src" / "codegen",
                ROOT / "vectoreyes" / "src" / "generated",
            ]
            visited = set()
            hashes = []
            while len(queue) > 0:
                path = queue.pop()
                if path in visited:
                    continue
                visited.add(path)
                if path.is_dir():
                    for entry in path.iterdir():
                        queue.append(entry)
                else:
                    hashes.append((str(path), sha256(path.read_bytes()).hexdigest()))
            hashes.sort()
            return sha256(
                "\n".join(f"{path} || h" for path, h in hashes).encode("ascii")
            ).hexdigest()

        cache_key = compute_cache_key()
        cache_key_file = swanky_cache_dir / "good-vectoreyes-codegen" / cache_key
        if not cache_key_file.exists():
            pretty_check_call([ROOT / "vectoreyes/src/codegen/generate.py"])
            if compute_cache_key() != cache_key:
                print("Re-run `vectoreyes/src/codegen/generate.py`")
                raise typer.Exit(code=1)
            cache_key_file.write_text("")
    with gitlab_ci_section("Functionality Tests"):
        if nightly:
            for force_haswell in [True, False]:
                build_and_test(features=[], force_haswell=force_haswell)
                build_and_test(features=["serde"], force_haswell=force_haswell)
            with gitlab_ci_section("Test vectoreyes scalar against itself"):
                CARGO_CONFIG_FILE.unlink()
                pretty_check_call(["cargo", "test", "-p", "vectoreyes"])
        else:
            build_and_test(features=["serde"])


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
