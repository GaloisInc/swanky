import json
import os
import platform
import shlex
import socket
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List

import click
import rich
import rich.panel
import rich.syntax

from etc import NIX_CACHE_KEY, ROOT
from etc.lint.cmd import lint

CI_EXTRA_ENV = "CI_EXTRA_ENV"
"""ClickContext.obj[CI_EXTRA_ENV] is a dictionary of environment variables to apply CI settings"""


def test_rust(
    ctx: click.Context,
    features: List[str],
    force_haswell: bool,
    cache_test_output: bool,
) -> None:
    """
    Test rust code

    ctx: the click Context of the current command
    features: which Cargo features should be enabled for the test
    force_haswell: if True, force a build for the haswell CPU (to test a different AES latency)
    cache_test_output: if True, then try to re-use the output of previous unit-tests
    """
    if len(features) > 0:
        features_args = ["--features", ",".join(features)]
    else:
        features_args = []
    # tag is a helper for generating the header for this output
    tag = lambda flag, msg: f" {msg}" if flag else ""
    rich.get_console().rule(
        "Test Rust%s%s features=%r"
        % (
            tag(force_haswell, "force_haswell"),
            tag(cache_test_output, "cache_test_output"),
            features,
        )
    )
    env = dict(os.environ) | ctx.obj[CI_EXTRA_ENV]
    if force_haswell:
        if platform.machine() not in ("AMD64", "x86_64"):
            raise click.UsageError(
                f"The host machine is {platform.machine()}, and so can't run haswell code."
            )
        flags = " ".join(
            [
                "-C target-cpu=haswell",
                "-C target-feature=+aes",
                '--cfg vectoreyes_target_cpu="haswell"',
            ]
        )
        env |= {"RUSTFLAGS": flags, "RUSTDOCFLAGS": flags}

    def run(cmd: List[str], extra_env: Dict[str, str] = dict()) -> None:
        "Run cmd with env|extra_env as the environment, with nice error reporting"
        if (
            subprocess.call(
                cmd, stdin=subprocess.DEVNULL, env=env | extra_env, cwd=ROOT
            )
            != 0
        ):
            raise click.ClickException("Command failed: " + " ".join(cmd))

    run(["cargo", "build", "--workspace", "--all-targets", "--verbose"] + features_args)
    if cache_test_output:
        # Doctests currently don't use the cargo runner :(
        if "SWANKY_CACHE_DIR" not in env:
            raise click.UsageError("--cache-dir not set, but caching is requested.")
        run(["cargo", "test", "--workspace", "--doc", "--verbose"] + features_args)
        run(
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
    else:
        run(["cargo", "test", "--workspace", "--verbose"] + features_args)


@click.group()
@click.option(
    "--cache-dir",
    help="[Usually for CI use] path to cache Swanky artifacts",
    type=click.Path(path_type=Path),
    required=True,
)
@click.pass_context
def ci(ctx: click.Context, cache_dir: Path) -> None:
    """Commands used by CI system (you probably don't want to invoke them manually)"""
    # Set up the environment for cach
    cache_dir = cache_dir / ctx.obj[NIX_CACHE_KEY]
    extra_env = {
        "RUST_BACKTRACE": "1",
        "PROPTEST_CASES": "256",
        "SWANKY_FLATBUFFER_DO_NOT_GENERATE": "1",
        "CARGO_INCREMENTAL": "0",
        "RUSTC_WRAPPER": str(ROOT / "etc/ci/wrappers/rustc.py"),
        "CC": str(ROOT / "etc/ci/wrappers/cc.sh"),
        "CXX": str(ROOT / "etc/ci/wrappers/cxx.sh"),
        "CARGO_HOME": str(cache_dir / "cargo-home"),
        "SWANKY_CACHE_DIR": str(cache_dir),
    }
    cache_dir.mkdir(exist_ok=True, parents=True)
    for entry in shlex.split((ROOT / "etc/ci/sccache_disk_proxy/env.sh").read_text()):
        if entry == "export":
            continue
        k, v = entry.split("=")
        extra_env[k] = v
    ctx.obj[CI_EXTRA_ENV] = extra_env
    # Start sccache!
    sccache_cache_dir = cache_dir / "sccache"
    sccache_cache_dir.mkdir(exist_ok=True, parents=True)
    # When this process exits, stdin will be closed, and it'll clean up the subprocess.
    # This only happens once, so we're not gonna worry about a zombie.
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        # sccache signals readyness by writing some bytes to a unix domain socket.
        sccache_ready_path = tmp / "rdy"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sccache_ready_sock:
            sccache_ready_sock.bind(str(sccache_ready_path))
            sccache_ready_sock.listen(1)
            sccache_server = subprocess.Popen(
                [
                    str(ROOT / "etc/ci/sccache_disk_proxy/spawn_sccache.sh"),
                    str(sccache_cache_dir),
                    str(sccache_ready_path),
                ],
                stdin=subprocess.PIPE,
            )
            # Closing stdin will shut everything down (see sccache_disk_proxy/shell.nix)
            ctx.call_on_close(sccache_server.stdin.close)
            rich.print("Waiting for sccache to start...")
            conn, _ = sccache_ready_sock.accept()
            try:
                # Read all the bytes that sccache wants to give in its readyness message
                while True:
                    if not conn.recv(1024):
                        break
            finally:
                conn.close()
            rich.print("sccache started!")


@ci.command()
@click.pass_context
def nightly(ctx: click.Context):
    """Run the nightly CI tests"""
    ctx.invoke(lint)
    test_rust(ctx, features=["serde"], force_haswell=False, cache_test_output=False)
    test_rust(ctx, features=[], force_haswell=False, cache_test_output=False)
    test_rust(ctx, features=["serde"], force_haswell=True, cache_test_output=False)


@ci.command()
@click.pass_context
def quick(ctx: click.Context):
    """Run the quick (non-nightly) CI tests"""
    ctx.invoke(lint)
    test_rust(ctx, features=["serde"], force_haswell=False, cache_test_output=True)
