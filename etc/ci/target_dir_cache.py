import base64
import ctypes
import itertools
import logging
import os
import shutil
import stat
import subprocess
import sys
import threading
import time
from functools import partial
from pathlib import Path
from typing import Callable, Iterable, List, Optional, TypedDict, TypeVar, cast
from uuid import uuid4

import cbor2

from etc import ROOT
from etc.ci.xattr_hash import cached_blake2b, set_cached_blake2b

_logger = logging.getLogger(__name__)

_T = TypeVar("_T")
_U = TypeVar("_U")


def _parallel_for(f: Callable[[_T], None], lst: Iterable[_T]) -> None:
    """
    Call f on the elements of lst in an arbitrary order, in parallel.

    NOTE: because of Python's Global Interpreter Lock (GIL), running code in parallel threads is
    only helpful for operations where Python releases the GIL (e.g. I/O operations or hashing).
    """
    queue = list(lst)
    total_count = len(queue)
    lock = threading.Lock()

    def background() -> None:
        while True:
            with lock:
                if len(queue) == 0:
                    return
                elif len(queue) % 1024 == 0:
                    _logger.info(f"Progress: {total_count - len(queue)}/{total_count}")
                entry = queue.pop()
            f(entry)

    threads = [threading.Thread(target=background) for _ in range(os.cpu_count() or 4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()


def _parallel_map(f: Callable[[_T], _U], lst: Iterable[_T]) -> List[_U]:
    """
    Perform a parallel map. Order is not preserved.
    """
    output = []
    lock = threading.Lock()

    def wrapper(t: _T) -> None:
        out = f(t)
        with lock:
            output.append(out)

    _parallel_for(wrapper, lst)
    return output


# Some filesystems can slow down if a single folder has too many files, so we make a few
# directories to use as a prefix, so that no one folder grows too large.
def _target_dir_manifest(cache_dir: Path, rev: str) -> Path:
    """For a given git revision, what's the path to the manifest for its output."""
    return cache_dir / "manifest" / rev[0:2] / rev[2:4] / rev


def _target_dir_data(cache_dir: Path, hash: bytes) -> Path:
    """For a given blake2b hash, what's the path to where its preimage is stored."""
    hash_str = base64.urlsafe_b64encode(hash).decode("ascii")
    return cache_dir / "data" / hash_str[0:2] / hash_str[2:4] / hash_str


class _FileInfo(TypedDict):
    """A fingerprint of a file"""

    path: str
    mtime_ns: int
    executable: bool
    blake2b: bytes


class _TargetManifest(TypedDict):
    """
    A snapshot of the state of a swanky checkout.

    inputs is a list of fingerprints of non gitignored files
    outputs is a list of fingerprints of the target directory
    """

    inputs: List[_FileInfo]
    outputs: List[_FileInfo]


def _file_info(path: Path, root: Path) -> _FileInfo:
    """
    Fingerprint a file

    This function only supports regular files.
    """
    s = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(s.st_mode):
        raise Exception(f"{repr(path)} is not a file")
    return dict(
        path=str(path.relative_to(root)),
        mtime_ns=s.st_mtime_ns,
        blake2b=cached_blake2b(path),
        executable=stat.S_IMODE(s.st_mode) & 0o111 != 0,
    )


_macos_clonefile: Optional[Callable[[bytes, bytes], int]] = None
"""The clonefile() function on macos."""

if sys.platform == "darwin":

    def _populate_macos_clonefile() -> Callable[[bytes, bytes], int]:
        # Python doesn't directly expose clonefile on macos, so we use ctypes/libffi to access it.
        libSystem = ctypes.cdll.LoadLibrary("libSystem.B.dylib")
        clonefile = libSystem.clonefile
        return cast(
            Callable[[bytes, bytes], int],
            lambda src, dst: clonefile(src, dst, 0),
        )

    _macos_clonefile = _populate_macos_clonefile()


def _copy_file(src_p: Path, dst_p: Path) -> None:
    """
    Copy the contents of src_p to dst_p

    This function will try to perform a logical copy, if the filesystem supports it, rather than
    reading all the bytes in and then writing them back out.
    """
    if (
        _macos_clonefile is not None
        and _macos_clonefile(str(src_p).encode("utf-8"), str(dst_p).encode("utf-8"))
        == 0
    ):
        return
    with dst_p.open("wb") as dst:
        with src_p.open("rb") as src:
            try:
                # We want to try to use copy_file_range() but only on Linux. copy_file_range() will
                # occasionally fail. As a result, we have fallback implementation.
                if sys.platform != "linux":
                    raise Exception("copy_file_range() is only for linux")
                src_len = src.seek(0, os.SEEK_END)
                src.seek(0, os.SEEK_SET)
                while src_len > 0:
                    n = os.copy_file_range(src.fileno(), dst.fileno(), src_len)
                    src_len -= n
                    if n == 0:
                        raise Exception("Premature EOF")
            except Exception:
                _logger.exception("Cannot copy_file_range(%r, %r)", src_p, dst_p)
                # Fallback to a physical copy.
                dst.truncate(0)
                src.seek(0, os.SEEK_SET)
                shutil.copyfileobj(src, dst)


def unpack_target_dir(cache_dir: Path) -> None:
    """
    If there's a cached target directory, that we can base this CI run on, then unpack it.

    If a suitable cached target directory has been found, then after this function has been called,
    the target directory will be populated to match previous CI run (in file contents and mtime).
    Inputs (non gitignored files) will have their mtimes updates. Inputs whose hashes match the
    hash from the cached run will use the mtime of the previous run. Inputs whose hashes don't
    match will use the current time as their mtime (so as to spoil any caches).
    """
    # Working from the current commit backwards, we see if any parent commit has a cached CI run
    # that we can use.
    git_log = (
        subprocess.check_output(["git", "log", "--pretty=format:%H"])
        .decode("ascii")
        .split()
    )
    for rev in git_log:
        manifest_path = _target_dir_manifest(cache_dir, rev)
        if not manifest_path.exists():
            continue
        _unpack_target_dir_manifest(cache_dir, manifest_path, ROOT)
        break
    else:
        _logger.warn("Unable to find git commit as basis target dir")


def _unpack_target_dir_manifest(
    cache_dir: Path, manifest_path: Path, root: Path
) -> None:
    with manifest_path.open("rb") as f:
        manifest: _TargetManifest = cbor2.load(f)
    # Step 1: if the inputs match the hashed version, then reset their mtimes to their old
    # values. Otherwise, set the mtime to "now." While cargo compares equality of the mtime,
    # value, other systems may do relational comparison of mtime values, and we want to
    # make sure that we don't mess with those. So, for any files which don't match, we set
    # their mtimes to now.
    now = time.time_ns()
    _logger.info("Processing inputs")

    def process_input(entry: _FileInfo) -> None:
        path = root / entry["path"]
        if not path.is_file():
            return
        mtime_ns = (
            entry["mtime_ns"] if cached_blake2b(path) == entry["blake2b"] else now
        )
        os.utime(path, ns=(mtime_ns, mtime_ns))

    _parallel_for(process_input, manifest["inputs"])

    # Step 2: copy all outputs in, set their mtimes, and then set their cached xattr hash
    # to the hash in the manifest.
    _logger.info("Processing outputs")

    def process_output(entry: _FileInfo) -> None:
        path = root / entry["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        _copy_file(_target_dir_data(cache_dir, entry["blake2b"]), path)
        if entry["executable"]:
            path.chmod(stat.S_IMODE(path.stat().st_mode) | 0o111)
        os.utime(path, ns=(entry["mtime_ns"], entry["mtime_ns"]))
        set_cached_blake2b(path, entry["blake2b"])

    _parallel_for(process_output, manifest["outputs"])


def pack_target_dir(cache_dir: Path) -> None:
    """
    Export the current repo state, so it can be unpacked later.

    Copy ./target to the cache, and add a manifest associated with the current git revision.
    """
    # The current git revision.
    rev = (
        subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT)
        .decode("ascii")
        .strip()
    )
    manifest_dst = _target_dir_manifest(cache_dir, rev)
    _pack_target_dir_manifest(
        cache_dir,
        manifest_dst,
        ROOT,
        input_files=(
            ROOT / line
            for line in subprocess.check_output(["git", "ls-files"], cwd=ROOT)
            .decode("utf-8")
            .split("\n")
            if line != ""
        ),
    )


def _pack_target_dir_manifest(
    cache_dir: Path, manifest_dst: Path, root: Path, input_files: Iterable[Path]
) -> None:
    manifest_dst.parent.mkdir(exist_ok=True, parents=True)
    # We want to atomically write the manifest, since other jobs might be using the same cache dir.
    tmp_manifest = manifest_dst.parent / f".tmp-{uuid4()}"
    try:
        _logger.info("Hashing Inputs")
        # inputs is a list of fingerprints of non-gitignored files.
        inputs = _parallel_map(
            partial(_file_info, root=root),
            input_files,
        )
        _logger.info("Hashing+Copying Outputs")

        def process_output(path: Path) -> _FileInfo:
            output = _file_info(path, root=root)
            dst = _target_dir_data(cache_dir, output["blake2b"])
            if not dst.is_file():
                # If dst doesn't exist we ATOMICALLY copy it in.
                dst.parent.mkdir(exist_ok=True, parents=True)
                dst_tmp = dst.parent / f".tmp-{uuid4()}"
                try:
                    _copy_file(root / output["path"], dst_tmp)
                    dst_tmp.rename(dst)
                finally:
                    dst_tmp.unlink(missing_ok=True)
            return output

        nix_env_cache = root / "target" / "nix-env-cache"
        # This is a list of paths of files in target
        output_paths = filter(
            # We skip the nix-env-cache folder, since it contains symlinks, and it will be
            # recreated at the beginning of every CI run by ./swanky anyways.
            lambda path: not path.is_relative_to(nix_env_cache),
            itertools.chain.from_iterable(
                [root / file for file in files]
                for root, _, files in (root / "target").walk(follow_symlinks=False)
            ),
        )
        outputs = _parallel_map(process_output, output_paths)
        manifest: _TargetManifest = dict(
            inputs=inputs,
            outputs=outputs,
        )
        _logger.info("Copied outputs")
        with tmp_manifest.open("wb") as f:
            cbor2.dump(manifest, f)
        tmp_manifest.rename(manifest_dst)
    finally:
        tmp_manifest.unlink(missing_ok=True)
