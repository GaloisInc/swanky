import os
import platform
import subprocess
from pathlib import Path
from typing import Callable, Dict, List

import click
import rich
import rich.panel
import rich.syntax

from etc import NIX_CACHE_KEY, ROOT
from etc.ci.target_dir_cache import pack_target_dir, unpack_target_dir
from etc.lint.cmd import lint


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
    tag: Callable[[bool, str], str] = lambda flag, msg: f" {msg}" if flag else ""
    rich.get_console().rule(
        "Test Rust%s%s features=%r"
        % (
            tag(force_haswell, "force_haswell"),
            tag(cache_test_output, "cache_test_output"),
            features,
        )
    )
    env = dict(os.environ)
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

    run(
        ["cargo", "clippy", "--workspace", "--all-targets", "--verbose"]
        + features_args
        + ["--", "-Dwarnings"]
    )
    run(
        ["cargo", "doc", "--workspace", "--no-deps", "--verbose"] + features_args,
        extra_env={"RUSTDOCFLAGS": "-D warnings"},
    )
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


def non_rust_tests(ctx: click.Context) -> None:
    ctx.invoke(lint)
    if subprocess.call(["pytest"], stdin=subprocess.DEVNULL, cwd=ROOT) != 0:
        raise click.ClickException("Pytest failed")


@click.group()
def ci() -> None:
    """Commands used by CI system (you probably don't want to invoke them manually)"""
    os.environ.update(
        {
            "RUST_BACKTRACE": "1",
            "PROPTEST_CASES": "256",
            "SWANKY_FLATBUFFER_DO_NOT_GENERATE": "1",
            "RUSTC_WRAPPER": str(ROOT / "etc/ci/wrappers/rustc.py"),
        }
    )


@ci.command()
@click.pass_context
def nightly(ctx: click.Context) -> None:
    """Run the nightly CI tests"""
    os.environ["CARGO_INCREMENTAL"] = "0"
    non_rust_tests(ctx)
    test_rust(ctx, features=["serde"], force_haswell=False, cache_test_output=False)
    test_rust(ctx, features=[], force_haswell=False, cache_test_output=False)
    test_rust(ctx, features=["serde"], force_haswell=True, cache_test_output=False)


@ci.command()
@click.option(
    "--cache-dir",
    help="[Usually for CI use] path to cache Swanky artifacts",
    type=click.Path(path_type=Path),
    required=True,
)
@click.pass_context
def quick(ctx: click.Context, cache_dir: Path) -> None:
    """Run the quick (non-nightly) CI tests"""
    cache_dir = cache_dir / ctx.obj[NIX_CACHE_KEY]
    cache_dir.mkdir(exist_ok=True, parents=True)
    os.environ.update(
        {
            "CARGO_HOME": str(cache_dir / "cargo-home"),
            "SWANKY_CACHE_DIR": str(cache_dir),
            "CARGO_INCREMENTAL": "1",
        }
    )
    try:
        unpack_target_dir(cache_dir)
        non_rust_tests(ctx)
        test_rust(ctx, features=["serde"], force_haswell=False, cache_test_output=True)
    finally:
        pack_target_dir(cache_dir)
