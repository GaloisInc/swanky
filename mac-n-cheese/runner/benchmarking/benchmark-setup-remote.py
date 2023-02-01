#!/usr/bin/env python3
# This should only be run on the EC2 instance

import json
import os
import shlex
from hashlib import sha256
from pathlib import Path
from shutil import rmtree
from subprocess import check_call, run
from textwrap import dedent

SWANKY_CACHE_DIR = Path("/home/ec2-user/swanky-cache-dir/")
CARGO_TARGET_DIR = Path(os.environ["CARGO_TARGET_DIR"])
REMOTE_SWANKY_ROOT = Path(os.environ["REMOTE_SWANKY_ROOT"])
REMOTE_COMPILATION_OUTPUT_LOCATION = Path(
    os.environ["REMOTE_COMPILATION_OUTPUT_LOCATION"]
)
INSTALL_FLAMEGRAPH = "INSTALL_FLAMEGRAPH" in os.environ
MEMORY_ALLOCATOR = os.environ.get("MEMORY_ALLOCATOR")
MAC_N_CHEESE_COMPILER_ARGS = os.environ.get("MAC_N_CHEESE_COMPILER_ARGS", "")
INSTALL_INTEL_TOOLS = "INSTALL_INTEL_TOOLS" in os.environ
DISABLE_EVENT_LOGS = "DISABLE_EVENT_LOGS" in os.environ

if __name__ == "__main__":
    SWANKY_CACHE_DIR.mkdir(exist_ok=True)
    os.environ["SWANKY_CACHE_DIR"] = str(SWANKY_CACHE_DIR)
    check_call(["sudo", "bash", "-c", "echo 0 > /proc/sys/kernel/kptr_restrict"])
    check_call(["sudo", "bash", "-c", "echo 0 > /proc/sys/kernel/yama/ptrace_scope"])
    check_call(["sudo", "bash", "-c", "echo -1 > /proc/sys/kernel/perf_event_paranoid"])
    if INSTALL_FLAMEGRAPH:
        if (Path.home() / ".cargo/bin/flamegraph").exists():
            print("Flamegraph already installed")
        else:
            print("Installing flamegraph")
            check_call(
                ["cargo", "install", "flamegraph"],
                cwd=str(REMOTE_SWANKY_ROOT),
            )
    if INSTALL_INTEL_TOOLS:
        kernel = os.uname().release
        # Intel expects to find the kernel source at `/usr/src/linux-RELEASE`, but
        # Amazon puts it at `/usr/src/kernels/RELEASE/`
        # dst = Path("/usr/src") / f"linux-{kernel}"
        # if not dst.exists():
        #    src = Path("/usr/src/kernels") / kernel
        #    assert src.exists(), str(src)
        #    dst.symlink_to(src)
        intel_tools_already_installed = Path.home() / ".intel-tools-already-installed"
        if not intel_tools_already_installed.exists():
            # We don't set this up via cloud-init, since we don't want to incur the cost if we
            # don't use the packages. In addition, we don't want cloudinit to fall flat if Intel's
            # yum repo dies (which has happened before).
            run(
                ["sudo", "bash", "-c", "cat > /etc/yum.repos.d/intel.repo"],
                input=dedent(
                    """\
                [oneAPI]
                name=intel
                baseurl=https://yum.repos.intel.com/oneapi
                enabled=1
                gpgcheck=1
                repo_gpgcheck=1
                gpgkey=https://yum.repos.intel.com/intel-gpg-keys/GPG-PUB-KEY-INTEL-SW-PRODUCTS.PUB
            """
                ).encode("ascii"),
                check=True,
            )
            check_call(
                [
                    "sudo",
                    "yum",
                    "install",
                    "-y",
                    "intel-oneapi-advisor",
                    "intel-oneapi-vtune",
                ]
            )
            intel_tools_already_installed.write_text("")
    cmd = ["cargo", "build", "--release", "-p", "mac-n-cheese-runner"]
    features = []
    no_default_features = False
    if MEMORY_ALLOCATOR:
        no_default_features = True
        if MEMORY_ALLOCATOR != "system":
            features.append(MEMORY_ALLOCATOR)
    if DISABLE_EVENT_LOGS:
        features.append("disable_event_log")
    if no_default_features:
        cmd.append("--no-default-features")
    if len(features) > 0:
        cmd.append("--features")
        cmd.append(",".join(features))
    print("Compiling mac-n-cheese-runner: %r" % cmd)
    check_call(
        cmd,
        cwd=str(REMOTE_SWANKY_ROOT),
    )
    print("Compiling mac-n-cheese-compiler")
    check_call(
        ["cargo", "build", "--release", "--bin", "mac-n-cheese-compiler"],
        cwd=str(REMOTE_SWANKY_ROOT),
    )
    bristol = REMOTE_SWANKY_ROOT / "mac-n-cheese/compiler/src/aes_128.txt"
    compilation_digest = REMOTE_COMPILATION_OUTPUT_LOCATION / "digest.txt"
    mac_n_cheese_compiler = CARGO_TARGET_DIR / "release" / "mac-n-cheese-compiler"
    mac_n_cheese_compiler_hash = sha256(
        MAC_N_CHEESE_COMPILER_ARGS.encode("ascii")
        + b"\n||\n"
        + b"\n||"
        + sha256(bristol.read_bytes()).digest()
        + b"||\n"
        + mac_n_cheese_compiler.read_bytes()
    ).hexdigest()
    print(f"MAC_N_CHEESE_COMPILER_ARGS: {repr(MAC_N_CHEESE_COMPILER_ARGS)}")
    if (
        compilation_digest.exists()
        and compilation_digest.read_text() == mac_n_cheese_compiler_hash
    ):
        print("Using cached mac n'cheese compilation.")
    else:
        rmtree(str(REMOTE_COMPILATION_OUTPUT_LOCATION), ignore_errors=True)
        tmp_dst = REMOTE_COMPILATION_OUTPUT_LOCATION.with_suffix(".tmp")
        rmtree(str(tmp_dst), ignore_errors=True)
        tmp_dst.mkdir()
        cmd = [str(mac_n_cheese_compiler)] + shlex.split(MAC_N_CHEESE_COMPILER_ARGS)
        print(f"Running the mac n'cheese compiler: {cmd}")
        # TODO: if the mac n'cheese compiler has other dependencies, add them to the hash
        check_call(
            ["time"] + cmd,
            cwd=str(tmp_dst),
        )
        tmp_dst.rename(REMOTE_COMPILATION_OUTPUT_LOCATION)
        compilation_digest.write_text(mac_n_cheese_compiler_hash)
