#!/usr/bin/env python3
# This test runner will be invoked by cargo (or cargo-nextest) like:
#   target/debug/deps/some_thing-somehash --exact scuttlebutt::my_test::thing
# The goal of this runner is to _safely_ cache that execution, to avoid
# re-running a test if possible.
#
# Outputs of the test run are cached under a cache key created by hashing the
# contents of the binary along with its arguments. To help avoid the binary
# accessing files which aren't part of the cache key, the binary is run with a
# temporary directory as the working directory.
import datetime
import os
import subprocess
import sys
import tempfile
import threading
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

import cbor2

CACHE_DIR = Path(os.environ["SWANKY_CACHE_DIR"]) / "cached-tests-v1"
TEST_RESULTS = CACHE_DIR / "test-results"
TEST_RESULTS.mkdir(exist_ok=True, parents=True)

exe = Path(sys.argv[1])
args = sys.argv[2:]
assert exe.exists()


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
        raw_data = os.getxattr(exe, attr)
    except:
        raw_data = None
    if raw_data is not None:
        out, read_stat_data = cbor2.loads(raw_data)
        if read_stat_data == stat_data:
            return out
    out = sha256(exe.read_bytes()).digest()
    os.setxattr(exe, attr, cbor2.dumps((out, stat_data)))
    return out


exe_hash = cached_hash(exe)

test_output = (
    TEST_RESULTS
    / sha256("\n".join(args).encode("ascii") + b"\n@$@$||\n" + exe_hash).hexdigest()
)
if test_output.exists():
    data = cbor2.loads(test_output.read_bytes())
    sys.stderr.write(data["cache_info"])
    streams = {"out": sys.stdout.buffer, "err": sys.stderr.buffer}
    # We interleave stdout and stderr to try to minic the original execution.
    for stream_name, buf in data["output"]:
        stream = streams[stream_name]
        stream.write(buf)
        stream.flush()
else:
    data = {
        "cache_info": f"CACHE HIT {exe} at {datetime.datetime.now().isoformat()} with {args}\n",
    }
    lock = threading.Lock()
    output = []

    def reader(name, stream, dst):
        global lock
        global output
        while True:
            buf = stream.read(8192)
            if len(buf) == 0:
                return
            with lock:
                output.append([name, buf])
            dst.write(buf)
            dst.flush()

    print(f"TEST CACHE MISS {exe} with {args}", file=sys.stderr)
    with tempfile.TemporaryDirectory() as tmp:
        # try to sandbox by changing the cwd
        tmp = Path(tmp)
        # We use the this dir so that we can hard link
        proc = subprocess.Popen(
            [exe] + args,
            cwd=tmp,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
        )
        threads = [
            threading.Thread(
                target=lambda: reader("out", proc.stdout, sys.stdout.buffer),
                daemon=True,
            ),
            threading.Thread(
                target=lambda: reader("err", proc.stderr, sys.stderr.buffer),
                daemon=True,
            ),
        ]
        for thread in threads:
            thread.start()
        rc = proc.wait()
        for thread in threads:
            thread.join(5)
        if rc != 0:
            print(f"{exe} with {args} exited with {rc}", file=sys.stderr)
            sys.exit(1)
        with lock:
            data["output"] = output
            output = []  # avoid any race conditions
    test_output_tmp = test_output.with_suffix(f".{uuid4()}.tmp")
    test_output_tmp.write_bytes(cbor2.dumps(data))
    test_output_tmp.rename(test_output)
    print(f"SAVED TEST RUN {exe} with {args} rc=0", file=sys.stderr)
