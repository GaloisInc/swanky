import os
import subprocess
from pathlib import Path
from random import Random
from shutil import rmtree

from .target_dir_cache import _pack_target_dir_manifest, _unpack_target_dir_manifest

_BUILD_RS = """
use std::io::Write;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let mut log = std::fs::OpenOptions::new()
        .append(true)
        .open("./build-log.txt").unwrap();
    writeln!(&mut log, "build").unwrap();
}
"""


def test_target_dir_caching(tmp_path: Path) -> None:
    """
    In order to test our caching system, we make a little rust crate with a build.rs script which
    writes to a file each time it's invoked. This lets us know when cargo has triggered a rebuild.
    """

    rng = Random(b"an arbitrary, yet deterministic, seed")

    def mangle_mtime(path: Path) -> None:
        """Set the mtime of path to a random time."""
        # We pick a random timestamp between the time this comment was written and one year prior
        # to that, to get an arbitrary range.
        random_mtime_ns = rng.randint(1686688238538024000, 1718224208060678000)
        os.utime(path, ns=(random_mtime_ns, random_mtime_ns))

    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    subprocess.check_call(["cargo", "new", "--bin", "target_test_bin"], cwd=tmp_path)
    src = tmp_path / "target_test_bin"
    target = src / "target"
    build_rs = src / "build.rs"
    build_rs.write_text(_BUILD_RS)
    build_log = src / "build-log.txt"
    build_log.write_text("")
    manifest_dst = tmp_path / "manifest"
    last_build_count = 0

    def cargo_build() -> None:
        subprocess.check_call(
            ["cargo", "build", "--verbose"],
            cwd=src,
            # We need to set CARGO_TARGET_DIR since CI will override it.
            env=os.environ | {"CARGO_TARGET_DIR": str(target)},
        )

    def build_count_delta() -> int:
        """Returns the number of rebuilds since the last time this function was called."""
        nonlocal last_build_count
        current_build_count = len(build_log.read_text().split())
        delta = current_build_count - last_build_count
        last_build_count = current_build_count
        return delta

    assert build_count_delta() == 0
    cargo_build()
    # A clean rebuild should invoke the build script
    assert build_count_delta() == 1
    # build_count_delta() should be working properly; two calls in a row shouldn't report any new
    # builds.
    assert build_count_delta() == 0
    cargo_build()
    # Before we mess with anything, cargo shouldn't rebuild anything if everything's clean.
    assert build_count_delta() == 0
    _pack_target_dir_manifest(
        cache_dir=cache_dir,
        manifest_dst=manifest_dst,
        root=src,
        input_files=[build_rs],
    )
    rmtree(target)
    mangle_mtime(build_rs)
    _unpack_target_dir_manifest(
        cache_dir=cache_dir, manifest_path=manifest_dst, root=src
    )
    cargo_build()
    # Cargo shouldn't rebuild since nothing changed.
    assert build_count_delta() == 0
    rmtree(target)
    with build_rs.open("a") as f:
        f.write("\n// changed source file!! the cache is now invalid!\n")
    _unpack_target_dir_manifest(
        cache_dir=cache_dir, manifest_path=manifest_dst, root=src
    )
    cargo_build()
    # Cargo should rebuild since build.rs changed.
    assert build_count_delta() == 1
