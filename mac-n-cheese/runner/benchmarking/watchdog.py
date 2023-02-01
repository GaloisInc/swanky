#!/usr/bin/env python3
import sys
from pathlib import Path
from subprocess import check_call
from time import sleep

COUNTER_PATH = Path("/run/mac-n-cheese-shutdown-watchdog")
counter_mtime = lambda: COUNTER_PATH.stat().st_mtime_ns
assert len(sys.argv) == 2

if sys.argv[1] == "daemon":
    with COUNTER_PATH.open("x") as f:
        f.write("x")
    print("Mac n'Cheese watchdog daemon started")
    while True:
        old = counter_mtime()
        sleep(60 * 60)  # 60 minutes
        new = counter_mtime()
        if old == new:
            break

    # While this is still racy, this will hopefully trigger an error if we try to feed the watchdog
    # after it's already been tripped.
    COUNTER_PATH.unlink()
    check_call(["systemctl", "poweroff"])
elif sys.argv[1] == "feed":
    if not COUNTER_PATH.exists():
        raise Exception("watchdog daemon isn't running")
    COUNTER_PATH.touch()
else:
    raise Exception("unknown command %r" % sys.argv[1])
