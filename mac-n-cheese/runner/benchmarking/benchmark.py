#!/usr/bin/env nix-shell
#! nix-shell --pure --keep SSH_AUTH_SOCK -i python3 ../../../etc/nix/mac-n-cheese-benchmark.nix
import contextlib
import functools
import json
import os
import platform
import shlex
import subprocess
import time
from collections import defaultdict, namedtuple
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Lock, Thread

import click

if platform.system() == "Darwin":
    SSH = "/usr/bin/ssh"
    SCP = "/usr/bin/scp"
else:
    SSH = "ssh"
    SCP = "scp"

BENCHMARKING_ROOT = Path(__file__).resolve().parent
SWANKY_ROOT = (
    subprocess.check_output(
        ["git", "rev-parse", "--show-toplevel"], cwd=str(BENCHMARKING_ROOT)
    )
    .strip()
    .decode("ascii")
)
assert SWANKY_ROOT != ""
SWANKY_ROOT = Path(SWANKY_ROOT)
assert SWANKY_ROOT.exists()
TEST_CERTS = BENCHMARKING_ROOT / "../test-certs"

REMOTE_SWANKY_ROOT = "/home/ec2-user/swanky/"
REMOTE_SWANKY_TARGET = "/home/ec2-user/swanky-target/"
REMOTE_LOG_FILE = "/home/ec2-user/mac-n-cheese.log"
REMOTE_DURATION_FILE = "/home/ec2-user/duration.txt"
REMOTE_FINISHED_NOTIFICATION_FILE = "/home/ec2-user/mac-n-cheese.setup.finished"
REMOTE_COMPILATION_OUTPUT_LOCATION = Path("/home/ec2-user/compiled-mac-n-cheese")
ROOT_CA = "/home/ec2-user/rootCA.crt"
TLS_CERT_AND_KEY = "/home/ec2-user/tls.pem"
EVENT_LOG = "/home/ec2-user/event-log.mclog"


class Server:
    def __init__(self, name, ip, host_key):
        # TODO: tmp_dir persists if an error occurs during init
        self.name = name
        self.ip = ip
        self.host_key = host_key
        self.ssh_master = None
        self.tmp_dir = TemporaryDirectory()
        self.tmp = Path(self.tmp_dir.name)
        self.lock = Lock()
        known_hosts = self.tmp / "known-hosts"
        known_hosts.write_text(f"{self.ip} {self.host_key}\n")
        self.base_ssh_cmd = [
            SSH,
            "-o",
            f"UserKnownHostsFile {known_hosts}",
            "-o",
            f"ControlPath {self.tmp / 'control-master'}",
            "-o",
            "ControlMaster auto",
            "-o",
            "ControlPersist 2m",
            "-o",
            "StrictHostKeyChecking yes",
            "-o",
            "SendEnv -LC_* -LANG*",
        ]
        while True:
            print(f"Attemping to connect to {ip}")
            if self.run(["true"], check=False).returncode == 0:
                break
            time.sleep(1)
        if not self.setup_finished():
            print("Waiting for machine setup to finish")
            view_logs = subprocess.Popen(
                self.ssh_cmd(["sudo", "tail", "-F", "/var/log/cloud-init-output.log"])
            )
            try:
                while not self.setup_finished():
                    time.sleep(1)
            finally:
                view_logs.terminate()
                view_logs.wait()
            print("Machine setup finished!")
        self.availability_zone = self.run(
            [
                "curl",
                "http://169.254.169.254/latest/meta-data/placement/availability-zone",
            ],
            stdout=subprocess.PIPE,
        ).stdout
        self._setup_watchdog()

    def _setup_watchdog(self):
        # If the watchdog has already been set up on this machine, then this shouldn't do anything.
        self.upload(BENCHMARKING_ROOT / "watchdog.py", "/home/ec2-user/watchdog.py")
        tmp_service = "/home/ec2-user/tmp_service"
        self.upload(
            BENCHMARKING_ROOT / "macncheese-watchdog.service",
            tmp_service,
        )
        self.run(
            [
                "sudo",
                "ln",
                "-f",
                tmp_service,
                "/etc/systemd/system/macncheese-watchdog.service",
            ]
        )
        self.run(["sudo", "systemctl", "daemon-reload"])
        self.run(["sudo", "systemctl", "start", "macncheese-watchdog.service"])
        # Technically, we should wait for the watchdog daemon to start, but we sleep for one minute
        # before trying to feed it, so we should be fine doing things the wrong way.
        Thread(target=lambda: self._watchdog_feeder(), daemon=True).start()

    def _watchdog_feeder(self):
        while True:
            time.sleep(60)  # one minute
            with self.lock:
                if not self.tmp.exists():
                    # the server was closed
                    return
                self.run(["sudo", "python3", "/home/ec2-user/watchdog.py", "feed"])

    def __str__(self):
        return f"{self.name} ({self.ip})"

    def setup_finished(self):
        return (
            self.run(
                ["test", "-f", "/home/ec2-user/.mnc-cloud-init-finished"],
                check=False,
                print_run=False,
            ).returncode
            == 0
        )

    def run(
        self,
        command,
        stdout=None,
        stderr=None,
        stdin=None,
        input=b"",
        check=True,
        print_run=True,
        env=dict(),
        cwd=None,
        source=[],
    ):
        if print_run:
            print(f"Running {repr(command)} env={env} cwd={cwd} on {self}")
        return subprocess.run(
            self.ssh_cmd(command, env=env, cwd=cwd, source=source),
            check=check,
            input=input,
            stdout=stdout,
            stderr=stderr,
            stdin=stdin,
            env=os.environ | {"LC_ALL": "en_US.utf-8", "LANG": "en_US.utf-8"},
        )

    def upload(self, src, dst):
        print(f"Uploading {src} to {self}:{dst}")
        subprocess.run(
            [SCP] + self.base_ssh_cmd[1:] + [str(src), f"ec2-user@{self.ip}:{dst}"],
            check=True,
            env=os.environ | {"LC_ALL": "en_US.utf-8", "LANG": "en_US.utf-8"},
        )

    def download(self, src, dst, compress=False):
        print(f"Downloading from {self}:{src} to {dst}")
        scp = [SCP]
        if compress:
            scp.append("-C")
        subprocess.run(
            scp + self.base_ssh_cmd[1:] + [f"ec2-user@{self.ip}:{src}", str(dst)],
            check=True,
            env=os.environ | {"LC_ALL": "en_US.utf-8", "LANG": "en_US.utf-8"},
        )

    def ssh_cmd(self, command, env=dict(), cwd=None, source=[]):
        shell_cmd = ""
        for k, v in env.items():
            shell_cmd += f"export {shlex.quote(k)}={shlex.quote(v)}; "
        if cwd is not None:
            shell_cmd += f"cd {cwd} && "
        for x in source:
            shell_cmd += f"source {shlex.quote(str(x))} ; "
        shell_cmd += " ".join(shlex.quote(x) for x in command)
        return self.base_ssh_cmd + [
            f"ec2-user@{self.ip}",
            shell_cmd,
        ]

    @contextlib.contextmanager
    def follow_file(self, path):
        sed_expr = f"s/^/[{self.name}] /"
        watch_log = subprocess.Popen(
            self.ssh_cmd(
                [
                    "sh",
                    "-c",
                    f"tail -F {shlex.quote(path)} | sed --unbuffered -e {shlex.quote(sed_expr)}",
                ]
            )
        )
        try:
            yield
        finally:
            watch_log.terminate()
            watch_log.kill()

    def close(self):
        with self.lock:
            self.tmp_dir.cleanup()


@contextlib.contextmanager
def get_servers():
    outputs = json.loads(
        subprocess.check_output(
            ["terraform", "output", "-json"],
            cwd=str(BENCHMARKING_ROOT / "terraform"),
        )
    )
    if (
        len(
            {
                "prover_public_ip",
                "prover_host_key",
                "verifier_public_ip",
                "verifier_host_key",
            }
            - set(outputs.keys())
        )
        > 0
    ):
        raise Exception("Terraform output is incomplete. Did `terraform apply` finish?")
    prover = Server(
        "prover",
        outputs["prover_public_ip"]["value"],
        outputs["prover_host_key"]["value"],
    )
    try:
        verifier = Server(
            "verifier",
            outputs["verifier_public_ip"]["value"],
            outputs["verifier_host_key"]["value"],
        )
        try:
            yield (prover, verifier)
        finally:
            verifier.close()
    finally:
        prover.close()


def path_with_trailing_slash(x):
    out = str(x)
    if out[-1] != "/":
        out += "/"
    return out


def rsync_code(server):
    print(f"rsyncing code to {server}")
    subprocess.check_call(
        [
            "rsync",
            "--rsh=" + " ".join(shlex.quote(x) for x in server.base_ssh_cmd),
            "--filter=:- .gitignore",
            "--exclude",
            ".git",
            "--exclude",
            "*.ipynb",
            "--exclude",
            ".DS_Store",
            "--archive",
            "--compress",
            "--delete",
            "--delete-excluded",
            "--executability",
            "--ignore-times",  # TODO: do we want this, or do we want -t?
            "--links",
            "--omit-dir-times",
            "--info=progress2",
            "--recursive",
            path_with_trailing_slash(SWANKY_ROOT),
            f"ec2-user@{server.ip}:{REMOTE_SWANKY_ROOT}",
        ]
    )


@contextlib.contextmanager
def run_in_background_via_tmux(server, args, env=dict(), source=[], cwd=None):
    env = dict(env)
    env["RUST_BACKTRACE"] = "1"
    env["MIMALLOC_PAGE_RESET"] = "0"
    env["MIMALLOC_RESERVE_HUGE_OS_PAGES"] = "10"
    server.run(["rm", "-f", REMOTE_LOG_FILE])
    server.run(["rm", "-f", REMOTE_FINISHED_NOTIFICATION_FILE])
    server.run(["touch", REMOTE_LOG_FILE])
    with server.follow_file(REMOTE_LOG_FILE):
        full_args = " ".join(shlex.quote(str(x)) for x in args)
        cmd = ""
        if cwd is not None:
            cmd += f"cd {shlex.quote(cwd)}; "
        for k, v in env.items():
            cmd += f"export {k}={shlex.quote(str(v))}; "
        for x in source:
            cmd += f"source {shlex.quote(str(x))}; "
        cmd += f"((({full_args}) && (echo 0 > {REMOTE_FINISHED_NOTIFICATION_FILE})) || (echo 1 > {REMOTE_FINISHED_NOTIFICATION_FILE}))"
        cmd += f"2>&1 | tee {REMOTE_LOG_FILE}"
        server.run(
            [
                "tmux",
                "new-session",
                "-d",
                f"bash -c {shlex.quote(cmd)}",
            ]
        )
        try:
            yield
            while True:
                out = (
                    server.run(
                        ["cat", REMOTE_FINISHED_NOTIFICATION_FILE],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL,
                        check=False,
                        print_run=False,
                    )
                    .stdout.strip()
                    .decode("ascii")
                )
                if len(out) != 0:
                    rc = int(out)
                    if rc != 0:
                        raise Exception(f"Server {server} failed {args}")
                    break
                time.sleep(1)
        finally:
            server.run(["tmux", "kill-server"], check=False)


def physical_cores(server):
    physical_cores = defaultdict(lambda: [])
    for i, data in enumerate(
        server.run(["cat", "/proc/cpuinfo"], stdout=subprocess.PIPE)
        .stdout.decode("ascii")
        .strip()
        .split("\n\n")
    ):
        lines = data.split("\n")
        cpu = dict()
        for line in lines:
            k, v = line.split(":")
            k = k.strip()
            v = v.strip()
            cpu[k] = v
        assert cpu["processor"] == str(i)
        physical_cores[int(cpu["core id"])].append(i)
    physical_cores = list(physical_cores.values())
    print(f"PHYSICAL CORES for {server}: {physical_cores}")
    return physical_cores


def disable_smt_taskset(physical_cores):
    return ["taskset", "--cpu-list", ",".join(str(min(x)) for x in physical_cores)]


CommandContext = namedtuple("CommandContext", ["prover", "verifier"])


@click.group()
@click.pass_context
def benchmark(ctx):
    """
    Run a mac n'cheese benchmark
    """

    # TODO: add perf/flamegraph options
    @functools.cache
    def make_it():
        prover, verifier = ctx.with_resource(get_servers())
        subprocess.check_call(["make"], cwd=str(TEST_CERTS))
        for server in [prover, verifier]:
            server.run(["tmux", "kill-server"], check=False)
            rsync_code(server)
            server.upload(TEST_CERTS / "rootCA.crt", ROOT_CA)
            server.upload(
                TEST_CERTS / "galois.macncheese.example.com.pem",
                TLS_CERT_AND_KEY,
            )
        return CommandContext(prover=prover, verifier=verifier)

    ctx.obj = make_it


@benchmark.command()
@click.option("--n", type=int, default=1000, help="The number of trials to run")
@click.option("--receiver/--sender", default=True)
@click.pass_context
def offline_svole(ctx, receiver, n):
    server = ctx.obj().prover
    server.run(
        ["cargo", "bench", "-p", "ocelot", "--bench", "svole2"],
        env={
            "CARGO_TARGET_DIR": REMOTE_SWANKY_TARGET,
            "N": str(n),
            "WHICH": "receiver" if receiver else "sender",
        },
        cwd=REMOTE_SWANKY_ROOT,
    )


@benchmark.command()
@click.option(
    "--memory-allocator",
    type=click.Choice(
        ["jemalloc", "snmalloc", "mimalloc", "rpmalloc", "system"], case_sensitive=False
    ),
    default=None,
)
@click.option(
    "--profile",
    type=click.Choice(
        [
            "flamegraph",
            "flamegraph-page-faults",
            "perf-stat",
            "roofline",
            "allocations",
            "vtune-performance-snapshot",
            "memory-stats",
        ]
    ),
    default=None,
)
@click.option("--num-threads", type=int, default=None)
@click.option("--vole-concurrency", type=int, default=512, show_default=True)
@click.option("--num-aes-groups", type=int, default=600, show_default=True)
@click.option("--aes-per-group", type=int, default=600, show_default=True)
@click.option("--num-connections", type=int, default=None)
@click.option(
    "--write-run-time-to",
    default=None,
    help="If specified, write the proof's runtime in nanoseconds to the specified file.",
)
@click.option(
    "--drop-disk-cache/--no-drop-disk-cache", default=False, show_default=True
)
@click.option(
    "--enable-event-logs/--disable-event-logs", default=True, show_default=True
)
@click.option("--disable-smt/--allow-smt", default=False, show_default=True)
# TODO: add intel profiling options
@click.pass_context
def aes(
    ctx,
    memory_allocator,
    profile,
    vole_concurrency,
    num_aes_groups,
    aes_per_group,
    num_threads,
    num_connections,
    drop_disk_cache,
    enable_event_logs,
    disable_smt,
    write_run_time_to,
):
    prover = ctx.obj().prover
    verifier = ctx.obj().verifier
    remote_setup_script = (
        Path(REMOTE_SWANKY_ROOT)
        / (BENCHMARKING_ROOT.relative_to(SWANKY_ROOT))
        / "benchmark-setup-remote.py"
    )
    compiler_args = [
        f"--vole-concurrency={vole_concurrency}",
        f"--num-aes-groups={num_aes_groups}",
        f"--aes-per-group={aes_per_group}",
    ]
    env = dict(
        REMOTE_SWANKY_ROOT=REMOTE_SWANKY_ROOT,
        CARGO_TARGET_DIR=REMOTE_SWANKY_TARGET,
        REMOTE_COMPILATION_OUTPUT_LOCATION=REMOTE_COMPILATION_OUTPUT_LOCATION,
        MAC_N_CHEESE_COMPILER_ARGS=" ".join(shlex.quote(str(x)) for x in compiler_args),
    )
    if profile == "allocations":
        if memory_allocator is not None:
            raise Exception("You can't profile memory _and_ set a memory allocator")
        memory_allocator = "dhat"
    if memory_allocator is not None:
        env["MEMORY_ALLOCATOR"] = memory_allocator
    if not enable_event_logs:
        env["DISABLE_EVENT_LOGS"] = "1"
    if profile in ["flamegraph", "flamegraph-page-faults"]:
        env["INSTALL_FLAMEGRAPH"] = "1"
    if profile in ["roofline", "vtune-performance-snapshot"]:
        env["INSTALL_INTEL_TOOLS"] = "1"
    with run_in_background_via_tmux(prover, [remote_setup_script], env):
        with run_in_background_via_tmux(verifier, [remote_setup_script], env):
            pass
    print("Rust and Mac n'Cheese compilation finished.")
    if drop_disk_cache:
        for server in [prover, verifier]:
            server.run(
                ["sudo", "bash", "-c", "sync; echo 1 > /proc/sys/vm/drop_caches"]
            )

    def runit(cmd_prefix, source=[], download_event_logs=True, cwd=None):
        nonlocal num_threads
        pc = physical_cores(prover)
        if disable_smt:
            if len(cmd_prefix) != 0:
                # TODO: will taskset mesh with cmd_prefix?
                raise Exception(
                    f"Cowardly refusing to use cmd_prefix {cmd_prefix} with taskset/--disable-smt"
                )
            if num_threads is None:
                num_threads = len(pc)
        base_cmd = cmd_prefix + [
            Path(REMOTE_SWANKY_TARGET) / "release/mac-n-cheese-runner",
            "--circuit",
            REMOTE_COMPILATION_OUTPUT_LOCATION / "aes.bin",
            "-r",
            ROOT_CA,
            "-k",
            TLS_CERT_AND_KEY,
            "--write-run-time-to",
            REMOTE_DURATION_FILE,
        ]
        if enable_event_logs:
            base_cmd += ["--event-log", EVENT_LOG]
        if num_threads is not None:
            base_cmd.append(f"--num-threads={num_threads}")
        cmd = []
        cmd += base_cmd
        if disable_smt:
            cmd = disable_smt_taskset(pc) + cmd
        cmd += [
            "--address",
            "0.0.0.0:8080",
            "prove",
            REMOTE_COMPILATION_OUTPUT_LOCATION / "aes.priv.bin",
        ]
        with run_in_background_via_tmux(
            prover,
            cmd,
            source=source,
            cwd=cwd,
        ):
            cmd = []
            cmd += base_cmd
            if disable_smt:
                cmd = disable_smt_taskset(pc) + cmd
            cmd += [
                "--address",
                f"{prover.ip}:8080",
                "verify",
            ]
            if num_connections is not None:
                cmd.append(f"--num-connections={num_connections}")
            with run_in_background_via_tmux(
                verifier,
                cmd,
                source=source,
                cwd=cwd,
            ):
                pass
        duration_ns = int(
            verifier.run(["cat", REMOTE_DURATION_FILE], subprocess.PIPE).stdout.decode(
                "ascii"
            )
        )
        if write_run_time_to is not None:
            Path(write_run_time_to).write_text(str(duration_ns))
        print(
            f"Proving and verification completed between {prover.availability_zone} and {verifier.availability_zone} in {duration_ns}ns"
        )
        # TODO: get the total # of and gates from the compiler
        print(
            f"RIGHT ONLY FOR AES: {duration_ns/(6400*num_aes_groups*aes_per_group)}ns per and gate"
        )
        if download_event_logs and enable_event_logs:
            for server in [prover, verifier]:
                server.download(EVENT_LOG, f"{server.name}.mclog")

    intel_source = ["/opt/intel/oneapi/setvars.sh"]
    if profile == "perf-stat":
        runit(
            [
                "perf",
                "stat",
                "--verbose",
            ]
        )
    elif profile in ["flamegraph", "flamegraph-page-faults"]:
        base = [
            "perf",
            "record",
            "-o",
            "perf.data",
            "-F",
            "997",
            "--call-graph",
            "dwarf",
            "-g",
        ]
        if profile == "flamegraph-page-faults":
            base += ["-e", "page-faults"]
        runit(base)
        print("Constructing flamegraphs..... this may take a while")
        # TODO: we can probably stick pv on the end of perf script and then count the number of lines
        # to display a progress bar
        make_flamegraph = ["flamegraph", "--perfdata", "perf.data"]
        with run_in_background_via_tmux(prover, make_flamegraph):
            with run_in_background_via_tmux(verifier, make_flamegraph):
                pass
        for server in [prover, verifier]:
            server.download("flamegraph.svg", f"flamegraph-{server.name}.svg")
            print(f"Flamegraph written to: flamegraph-{server.name}.svg")
    elif profile == "roofline":
        intel_advisor_out = "/home/ec2-user/intel-advisor-mnc-output/"
        for server in [prover, verifier]:
            server.run(["rm", "-rf", intel_advisor_out])
        runit(
            [
                "advixe-cl",
                "--collect=roofline",
                f"--project-dir={intel_advisor_out}",
                "--",
            ],
            download_event_logs=False,
            source=intel_source,
        )
        report_output_html = "/home/ec2-user/intel-roofline.html"
        for server in [prover, verifier]:
            server.run(
                [
                    "advixe-cl",
                    "--report=roofline",
                    f"--project-dir={intel_advisor_out}",
                    f"--report-output={report_output_html}",
                ],
                source=intel_source,
            )
            server.download(
                report_output_html, f"intel-advisor-roofline-{server.name}.html"
            )
        for server in [prover, verifier]:
            print(
                f"Intel advisor roofline report written to: intel-advisor-roofline-{server.name}.html"
            )
    elif profile == "vtune-performance-snapshot":
        out_dir = "/home/ec2-user/mnc-vtune-output"
        for server in [prover, verifier]:
            server.run(["rm", "-rf", out_dir])
            server.run(["mkdir", out_dir])
        runit(
            [
                "vtune",
                "-collect",
                "performance-snapshot",
                "--",
            ],
            source=intel_source,
            cwd=out_dir,
        )
        # TODO: fix this
        print("For now, you need to manually inspect the performance snapshot")
    elif profile == "allocations":
        profile_file = "/home/ec2-user/dhat-heap.json"
        for server in [prover, verifier]:
            server.run(["rm", "-f", profile_file])
        runit([])
        for server in [prover, verifier]:
            server.download(
                profile_file,
                f"memory-dhat-{server.name}.json",
                compress=True,
            )
    elif profile == "memory-stats":
        REMOTE_TIME_OUTPUT = "/home/ec2-user/mac-n-cheese.time.log"
        runit(["env", "time", "-v", "-o", REMOTE_TIME_OUTPUT])
        for server in [prover, verifier]:
            with Path(f"{server.name}.time.log").open("wb") as f:
                server.run(["cat", REMOTE_TIME_OUTPUT], stdout=f)
        print("Memory usage info written to prover.time.log and verifier.time.log")
    elif profile is None:
        runit([])
    else:
        raise Exception(f"Unknown profile type {profile}")


if __name__ == "__main__":
    benchmark()
