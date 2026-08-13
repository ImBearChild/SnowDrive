#!/usr/bin/env python3
"""Shared helpers for the SnowDrive external test suite.

Pure standard library. The suite treats the `snowdrive` binary as a black
box: it spawns `snowdrive serve` / `snowdrive mkisofs` as subprocesses and
drives them with external tools (`file`, `7z`, `isoinfo`, `bsdtar`,
`iscsiadm`, ...). Nothing here is compiled into cargo tests.
"""

import os
import re
import shutil
import signal
import subprocess
import time

# Repo root = three dirs up from this file (tools/ext-test/harness.py).
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# The target name the server reports (mirrors `transport.rs` / target tests).
TARGET_NAME = "iqn.1970-01.local.snowscsi:target"


def have_tool(name):
    """True if `name` is on PATH."""
    return shutil.which(name) is not None


def find_binary():
    """Locate the `snowdrive` binary.

    `SNOWDRIVE_BIN` overrides; otherwise `target/{debug,release}/snowdrive`
    under the repo root (release preferred). Raise if none is found.
    """
    override = os.environ.get("SNOWDRIVE_BIN")
    if override:
        if not os.path.isfile(override):
            raise FileNotFoundError(f"SNOWDRIVE_BIN is not a file: {override}")
        return override
    for profile in ("release", "debug"):
        cand = os.path.join(REPO_ROOT, "target", profile, "snowdrive")
        if os.path.isfile(cand):
            return cand
    raise FileNotFoundError(
        "snowdrive binary not found; build with `cargo build --workspace` "
        "or set SNOWDRIVE_BIN"
    )


def is_root():
    """True if running as root (kernel loopback tests need it)."""
    return hasattr(os, "geteuid") and os.geteuid() == 0


class ServerHandle:
    """Lifecycle of a `snowdrive serve` subprocess.

    Starts the server on an ephemeral loopback port (`--iscsi 127.0.0.1:0`),
    waits for the `listening on <addr>` stderr line to learn the actual
    bound address, and shuts it down with SIGINT on exit. `__exit__`
    asserts a clean exit (0), so a graceful-shutdown regression fails the
    test even when the body passed.
    """

    def __init__(self, *serve_args, work_buf_size=None):
        self.serve_args = list(serve_args)
        self.work_buf_size = work_buf_size
        self.proc = None
        self.addr = None
        self.port = None
        self._stderr = None

    def __enter__(self):
        cmd = [find_binary(), "serve", "--iscsi", "127.0.0.1:0"]
        cmd.extend(self.serve_args)
        if self.work_buf_size:
            cmd += ["--work-buf-size", str(self.work_buf_size)]
        self.proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        self._stderr = self.proc.stderr
        self._wait_ready()
        return self

    def _wait_ready(self, timeout=10.0):
        """Read stderr until `listening on <addr>`; raise on early exit."""
        deadline = time.monotonic() + timeout
        buf = ""
        while time.monotonic() < deadline:
            line = self._stderr.readline()
            if line == "":
                rc = self.proc.poll()
                self._close_stderr()
                raise RuntimeError(
                    f"snowdrive exited early (rc={rc}) before 'listening'"
                )
            m = re.search(r"listening on ([0-9.:]+)", line)
            if m:
                hostport = m.group(1)
                if hostport.startswith("[") and "]" in hostport:
                    host, _, port = hostport[1:].partition("]:")
                else:
                    host, _, port = hostport.rpartition(":")
                self.addr = hostport
                self.port = int(port)
                return
            buf += line
        # Timed out: kill to avoid leaking the child.
        self._kill()
        raise TimeoutError(
            f"snowdrive did not announce 'listening' in {timeout}s; "
            f"stderr so far: {buf[-512:]}"
        )

    def _kill(self):
        if self.proc and self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()
        self._close_stderr()

    def _close_stderr(self):
        """Release the Popen stderr pipe (avoids a ResourceWarning)."""
        if self._stderr is not None:
            self._stderr.close()
            self._stderr = None

    def __exit__(self, exc_type, exc, tb):
        self.stop()
        return False

    def stop(self):
        """SIGINT (graceful shutdown) then assert exit 0."""
        if self.proc is None:
            return
        try:
            if self.proc.poll() is None:
                self.proc.send_signal(signal.SIGINT)
                try:
                    self.proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self._kill()
                    raise AssertionError("snowdrive did not exit after SIGINT")
            if self.proc.returncode != 0:
                raise AssertionError(
                    f"snowdrive exited {self.proc.returncode} (expected 0 after "
                    f"SIGINT); tail of stderr:\n{self._tail()}"
                )
        finally:
            self._close_stderr()

    def _tail(self, n=1024):
        if self._stderr is None:
            return ""
        pos = self._stderr.tell()
        self._stderr.seek(max(0, pos - n))
        return self._stderr.read()


def run_snowdrive(args, cwd=None, timeout=120):
    """Run `snowdrive <args...>`, return CompletedProcess (check=False)."""
    return subprocess.run(
        [find_binary(), *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def mkisofs(src_dir, out_iso, label=None):
    """Run `snowdrive mkisofs`; return CompletedProcess."""
    args = ["mkisofs", src_dir, out_iso]
    if label:
        args += ["--label", label]
    return run_snowdrive(args)
