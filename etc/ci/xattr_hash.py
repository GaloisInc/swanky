import os
import sys
from hashlib import sha256
from pathlib import Path
from typing import List

import cbor2
from xattr import getxattr, setxattr  # type: ignore

_ATTR_KEY = "user.caching_test_runner_hash_cache"


def _stat_data(path: Path) -> List[int]:
    """Return a key which should change if path ever changes."""
    # Based on https://apenwarr.ca/log/20181113
    stat = path.stat()
    return [
        stat.st_mtime_ns,
        stat.st_size,
        stat.st_ino,
        stat.st_mode,
        stat.st_uid,
        stat.st_gid,
    ]


def cached_hash(exe: Path) -> bytes:
    """
    Some of our test executables, especially with debug symbols, can be in the
    hundreds of megabytes. Constantly re-reading and hashing them can be slow.
    To avoid this, we set an xattr attribute on the binary with a cache of its
    hash. We use https://apenwarr.ca/log/20181113 to set the cache key for the
    hash.
    """
    stat_data = _stat_data(exe)
    try:
        raw_data = getxattr(exe, _ATTR_KEY)
    except:
        raw_data = None
    if raw_data is not None:
        # The xattr format is [blake2b hash, stat_data]
        cbor_hash, read_stat_data = cbor2.loads(raw_data)
        if read_stat_data == stat_data:
            assert isinstance(cbor_hash, bytes)
            return cbor_hash
    hash = sha256()
    with path.open("rb") as f:
        while True:
            # This is the recommended buffer size for blake hash functions.
            buf = f.read(16 * 1024)
            if len(buf) == 0:
                break
            hash.update(buf)
    out = hash.digest()
    set_cached_hash(path, out)
    return out


def set_cached_hash(path: Path, hash: bytes) -> None:
    """
    Populate the hash cache for path by saying that sha256(path)=hash
    """
    setxattr(path, _ATTR_KEY, cbor2.dumps((hash, _stat_data(path))))
