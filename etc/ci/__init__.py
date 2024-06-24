import itertools
import os
import platform
import shlex
import subprocess
from base64 import urlsafe_b64encode
from dataclasses import dataclass
from hashlib import blake2b
from pathlib import Path
from uuid import uuid4

import click
import rich
import rich.panel
import rich.syntax

from etc import NIX_CACHE_KEY, ROOT
from etc.ci.target_dir_cache import pack_target_dir, unpack_target_dir
from etc.lint.cmd import lint


def _nix_build(ctx: click.Context, name: str, args: list[str]) -> Path:
    """
    Run nix-build, with args, and return the path to the output nix derivation.

    This path will be cached using a cache key based on name, as well as the hash of the etc/nix
    directory.
    """
    # Add a suffix to the name to avoid the glob below matching too much if names share a common
    # prefix.
    cache_key = str(ctx.obj[NIX_CACHE_KEY]) + "_" + name + "-_-"
    cache_dst = ROOT / "target/nix-env-cache" / cache_key
    if not cache_dst.exists():
        subprocess.check_call(
            [
                "nix-build",
                "--out-link",
                str(cache_dst),
            ]
            + args
        )
    # Sometimes nix appends a suffix to what's supposed to be the destination
    candidates = list(cache_dst.parent.glob(f"{cache_dst.name}*"))
    assert len(candidates) == 1
    return candidates[0]


def _write_wrapper_script(name: str, script: str) -> Path:
    """
    Return a path to an executable bash script containing script.

    This function will add the shebang.

    name is just used for debugging purposes, and doesn't need to be unique.
    """
    script = f"#!/usr/bin/env bash\n{script}\n"
    script_path = (
        ROOT
        / "target/nix-env-cache"
        / urlsafe_b64encode(blake2b(script.encode("utf-8")).digest()).decode("ascii")[
            0:32
        ]
    )
    if not script_path.exists():
        # Atomically write the file
        tmp = script_path.with_suffix(f".tmp-{uuid4()}")
        try:
            tmp.write_text(script)
            tmp.chmod(0o775)
            tmp.rename(script_path)
        finally:
            tmp.unlink(missing_ok=True)
    return script_path


def _linker(target: str) -> str:
    """What linker should we use for a given target?"""
    return "mold" if "linux" in target else "lld"


@dataclass(frozen=True)
class _CrossCompile:
    """Cross-compilation configuration settings."""

    target_arch: str
    """What architecture should be targeted?"""
    target_cpu: str
    """Which microarchitecture should be targeted?"""
    expected_vectoreyes_backend: str
    """Which vectoreyes baceknd should we assert is used?"""

    def user_mode_emulator(self, ctx: click.Context) -> Path:
        """
        Return the path to a script that can be used to emulate executables built for this target.
        """
        qemu_bin = (
            _nix_build(
                ctx,
                "qemu",
                [
                    str(ROOT / "etc/nix/pkgs.nix"),
                    "-A",
                    "qemu",
                ],
            )
            / "bin"
            / f"qemu-{self.target_arch}"
        ).resolve()
        return _write_wrapper_script(
            "qemu",
            f'exec {shlex.quote(str(qemu_bin))} -cpu {shlex.quote(self.target_cpu)} "$@"',
        )

    @property
    def target(self) -> str:
        """The triple for this cross-compilation target."""
        return f"{self.target_arch}-unknown-linux-musl"

    def update_env(
        self, ctx: click.Context, env: dict[str, str], cargo_args: list[str]
    ) -> None:
        """
        Update environment variables and cargo arguments for cross compilation.
        """
        if platform.system() != "Linux":
            raise Exception("cross-compiling and testing only works on linux")
        # By default, cargo makes a subdirectory inside of target/ for each target you're compiling
        # for, to make sure that they don't conflict. However, this doesn't apply to build scripts which
        # can be re-compiled with slightly different flags for each target. Because cargo will
        # only cache one copy of each build script, it'll end up recompiling the script (even on a
        # clean build).
        #
        # To fix this, we give a subdirectory of the target directory for _all_ of our
        # cross-compilation needs.
        env["CARGO_TARGET_DIR"] = os.path.join(
            env["CARGO_TARGET_DIR"], f"swanky-{self.target}"
        )
        cargo_args.append(f"--target={self.target}")
        # The environment for running cross-compiled targets.
        cargo_runner_env = {
            _cargo_target_runner_env_var(self.target): str(
                self.user_mode_emulator(ctx)
            ),
        }
        # A raw clang that nix hasn't wrapped to link against the host's libc (which would be bad
        # for cross-compilation).
        clang_unwrapped = _nix_build(
            ctx,
            "clang_unwrapped",
            [str(ROOT / "etc/nix/llvm.nix"), "-A", "clang-unwrapped"],
        )
        env[f"CC_{self.target}"] = str(clang_unwrapped / "bin/clang")
        env[f"CXX_{self.target}"] = str(clang_unwrapped / "bin/clang++")
        musl_headers = _nix_build(
            ctx,
            f"musl_headers-{self.target}",
            [str(ROOT / "etc/nix/musl-headers.nix"), "--argstr", "target", self.target],
        )
        # We need to get clang's include directory to add files like arm_neon.h to the include path
        # To find this directory, we just search through the clang install.
        clang_include_candidates = list(
            itertools.chain.from_iterable(
                [base / dir for dir in dirs if dir == "include"]
                for base, dirs, _ in _nix_build(
                    ctx,
                    "clang_includes",
                    [str(ROOT / "etc/nix/llvm.nix"), "-A", "libclang.lib"],
                )
                .resolve()
                .walk()
            )
        )
        if len(clang_include_candidates) != 1:
            raise Exception("Could not find clang include directory")
        clang_include = clang_include_candidates[0]
        env[f"CFLAGS_{self.target}"] = (
            env.get("CFLAGS", "")
            + " -nostdinc"
            + f" --sysroot={musl_headers.resolve()}"
            + f" -isystem {musl_headers.resolve()}/include"
            + f" -isystem {clang_include}"
            + f" --target={self.target}"
            + f" -mcpu={self.target_cpu}"
        )
        # Override the usual flags which target the host CPU
        env["RUSTFLAGS"] = " ".join(
            [
                f"-Ctarget-cpu={self.target_cpu}",
                "-Clinker-flavor=gcc",
                f"-Clinker={clang_unwrapped}/bin/clang",
                f"-Clink-arg=--target={self.target}",
                f"-Clink-arg=-fuse-ld={_linker(self.target)}",
            ]
        )
        # Check that the expected vectoreyes backend matches what's actualy in use
        vectoreyes_backend = (
            subprocess.check_output(
                ["cargo", "run", "--verbose", "--example", "vectoreyes_print_backend"]
                + cargo_args,
                stdin=subprocess.DEVNULL,
                env=env | cargo_runner_env,
            )
            .decode("utf-8")
            .strip()
        )
        if vectoreyes_backend != self.expected_vectoreyes_backend:
            raise click.ClickException(
                f"{repr(self)} lead to unexpected vectoreyes backend {repr(vectoreyes_backend)}"
            )
        # Check that the version of musl that rust ships matches the version of musl that we got
        # headers for.
        rust_musl_version = (
            subprocess.check_output(
                ["cargo", "run", "--verbose", "--example", "print_musl_version"]
                + cargo_args,
                stdin=subprocess.DEVNULL,
                env=env | cargo_runner_env,
            )
            .decode("utf-8")
            .strip()
        )
        musl_headers_version = (musl_headers / "version.txt").read_text().strip()
        if musl_headers_version != rust_musl_version:
            raise click.ClickException(
                f"Rust has musl version {rust_musl_version}, which doesn't match the "
                + f"sysroot {musl_headers_version}"
            )


_NEON = _CrossCompile(
    target_arch="aarch64", target_cpu="neoverse-v1", expected_vectoreyes_backend="Neon"
)


def _cargo_target_runner_env_var(target: str) -> str:
    """What's the cargo environment variable for the runner for a particular target triple?"""
    return "CARGO_TARGET_" + target.upper().replace("-", "_") + "_RUNNER"

def test_rust(
    ctx: click.Context,
    cargo_args: list[str],
    cache_test_output: bool,
) -> None:
    """
    Test rust code

    ctx: the click Context of the current command
    cargo_args: extra arguments to pass to cargo, for example, to enable features.
    cache_test_output: if True, then try to re-use the output of previous unit-tests
    """
    host_triple = (
        subprocess.check_output(["rustc", "-Vv"])
        .decode("utf-8")
        .split("host:")[1]
        .split()[0]
    )
    rich.get_console().rule(
        f"Test Rust cargo_args={repr(cargo_args)} cache_test_output={cache_test_output}"
    )
    env = dict(os.environ)

    def run(cmd: list[str], extra_env: dict[str, str] = dict()) -> None:
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
        + cargo_args
        + ["--", "-Dwarnings"]
    )
    run(
        ["cargo", "doc", "--workspace", "--no-deps", "--verbose"] + cargo_args,
        extra_env={"RUSTDOCFLAGS": "-D warnings"},
    )
    run(["cargo", "build", "--workspace", "--all-targets", "--verbose"] + cargo_args)
    if cache_test_output:
        # Doctests currently don't use the cargo runner :(
        if "SWANKY_CACHE_DIR" not in env:
            raise click.UsageError("--cache-dir not set, but caching is requested.")
        run(["cargo", "test", "--workspace", "--doc", "--verbose"] + cargo_args)
        run(
            [
                "cargo",
                "nextest",
                "run",
                "--no-fail-fast",
                "--workspace",
                "--verbose",
            ]
            + cargo_args,
            extra_env={
                "CARGO_TARGET_"
                + host_triple.upper().replace("-", "_")
                + "_RUNNER": str(ROOT / "etc/ci/wrappers/caching_test_runner.py"),
            },
        )
    else:
        run(["cargo", "test", "--workspace", "--verbose"] + cargo_args)


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
            "CARGO_INCREMENTAL": "0",
        }
    )


@ci.command()
@click.pass_context
def nightly(ctx: click.Context) -> None:
    """Run the nightly CI tests"""
    non_rust_tests(ctx)
    test_rust(ctx, cargo_args=["--features=serde"], cache_test_output=False)
    test_rust(ctx, cargo_args=[], cache_test_output=False)


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
    cache_dir = (
        cache_dir
        / urlsafe_b64encode(
            blake2b(
                (
                    ctx.obj[NIX_CACHE_KEY]
                    + "\n"
                    + (ROOT / "etc" / "ci" / "wrappers" / "rustc.py").read_text()
                ).encode("utf-8")
            ).digest()
        ).decode("ascii")[0:32]
    )
    cache_dir.mkdir(exist_ok=True, parents=True)
    os.environ.update(
        {
            "CARGO_HOME": str(cache_dir / "cargo-home"),
            "SWANKY_CACHE_DIR": str(cache_dir),
        }
    )
    try:
        unpack_target_dir(cache_dir)
        non_rust_tests(ctx)
        test_rust(ctx, cargo_args=["--features=serde"], cache_test_output=True)
    finally:
        pack_target_dir(cache_dir)
