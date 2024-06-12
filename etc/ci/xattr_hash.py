import os
import sys
from hashlib import sha256
from pathlib import Path

import cbor2
from xattr import getxattr, setxattr  # type: ignore



def cached_hash(exe: Path) -> bytes:
    """
    Some of our test executables, especially with debug symbols, can be in the
    hundreds of megabytes. Constantly re-reading and hashing them can be slow.
    To avoid this, we set an xattr attribute on the binary with a cache of its
    hash. We use https://apenwarr.ca/log/20181113 to set the cache key for the
    hash.
    """
    stat = exe.stat()
    stat_data = [
        stat.st_mtime,
        stat.st_size,
        stat.st_ino,
        stat.st_mode,
        stat.st_uid,
        stat.st_gid,
    ]
    attr = "user.caching_test_runner_hash_cache"
    try:
        raw_data = getxattr(exe, attr)
    except:
        raw_data = None
    if raw_data is not None:
        cbor_hash, read_stat_data = cbor2.loads(raw_data)
        if read_stat_data == stat_data:
            assert isinstance(cbor_hash, bytes)
            return cbor_hash
    out = sha256(exe.read_bytes()).digest()
    setxattr(exe, attr, cbor2.dumps((out, stat_data)))
    return out
