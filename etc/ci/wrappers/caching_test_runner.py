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
from typing import IO, Optional
from uuid import uuid4

import cbor2

sys.path.append(str(Path(__file__).parent.parent.parent.parent))

from etc.ci.xattr_hash import cached_blake2b

CACHE_DIR = Path(os.environ["SWANKY_CACHE_DIR"]) / "cached-tests-v1"
TEST_RESULTS = CACHE_DIR / "test-results"
TEST_RESULTS.mkdir(exist_ok=True, parents=True)

exe = Path(sys.argv[1])
args = sys.argv[2:]
assert exe.exists()


exe_hash = cached_blake2b(exe)

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

    def reader(name: str, stream: Optional[IO[bytes]], dst: IO[bytes]) -> None:
        global lock
        global output
        assert stream is not None
        while True:
            buf = stream.read(8192)
            if len(buf) == 0:
                return
            with lock:
                output.append([name, buf])
            dst.write(buf)
            dst.flush()

    print(f"TEST CACHE MISS {exe} with {args}", file=sys.stderr)
    with tempfile.TemporaryDirectory() as tmp_str:
        # try to sandbox by changing the cwd
        tmp = Path(tmp_str)
        # We use the this dir so that we can hard link
        proc = subprocess.Popen(
            [str(exe)] + args,
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
