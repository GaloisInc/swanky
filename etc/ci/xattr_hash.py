import os
from hashlib import blake2b
from pathlib import Path

import cbor2
from xattr import getxattr, setxattr  # type: ignore

_ATTR_KEY = "user.swanky_blake2b_hash_cache_v1"


def _stat_data(path: Path) -> list[int]:
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


def cached_blake2b(path: Path) -> bytes:
    """
    Return the blake2b hash of path.

    This function will cache the result of the hash operation in the xattrs of path.
    """
    try:
        raw_data = getxattr(path, _ATTR_KEY)
    except:
        raw_data = None
    stat_data = _stat_data(path)
    if raw_data is not None:
        # The xattr format is [blake2b hash, stat_data]
        cbor_hash, read_stat_data = cbor2.loads(raw_data)
        assert isinstance(read_stat_data, list)
        if read_stat_data == stat_data:
            assert isinstance(cbor_hash, bytes)
            # If the previously stored hash is clean, then return it.
            return cbor_hash
    hash = blake2b()
    with path.open("rb") as f:
        while True:
            # This is the recommended buffer size for blake hash functions.
            buf = f.read(16 * 1024)
            if len(buf) == 0:
                break
            hash.update(buf)
    out = hash.digest()
    set_cached_blake2b(path, out)
    return out


def set_cached_blake2b(path: Path, hash: bytes) -> None:
    """
    Populate the blake2b cache for path by saying that blake2b(path)=hash
    """
    setxattr(path, _ATTR_KEY, cbor2.dumps((hash, _stat_data(path))))
