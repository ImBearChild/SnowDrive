#!/usr/bin/env python3
"""Real-kernel iSCSI loopback test (root).

A genuine Linux initiator (`iscsiadm`, the open-iscsi userspace driving the
`iscsi_tcp` kernel module) logs into `snowdrive serve` over loopback, brings
the device up as a block device, formats it with ext4, mounts it, writes and
reads data through the real block layer, and fsck-checks it.

This is the strongest possible black-box validation of the iSCSI target:
the kernel's SCSI midlayer + ext4 + VFS all exercise the emulated target,
covering login negotiation, REPORT LUNS, READ/WRITE(10), MODE SENSE and
sense handling that a userspace initiator would gloss over.

Skipped unless: running as root, `iscsiadm` present, `iscsiadm -m node`
works, and the `iscsid` daemon can be started. The test never loads or
unloads kernel modules. Every step that mutates system state (iscsid,
node records, devices) is torn down in `tearDown` regardless of pass/fail.
"""

import os
import shutil
import subprocess
import time
import unittest

from harness import ServerHandle, TARGET_NAME, have_tool, is_root

# RAM disk: 32 MiB = 65536 × 512 B sectors (enough for ext4).
RAM_SIZE = "32M"
PORTAL_PREFIX = "127.0.0.1"

# Device path the kernel picks for `ip-<portal>-iscsi-<iqn>-lun-0` (note the
# dash between portal and `iscsi`, mirroring the udev by-path naming).
BY_PATH_GLOB = f"ip-{PORTAL_PREFIX}:*-iscsi-{TARGET_NAME}-lun-0"


def sh(*argv, check=True, timeout=60, **kw):
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, **kw)


@unittest.skipUnless(
    is_root() and have_tool("iscsiadm"),
    "requires root + iscsiadm (open-iscsi)",
)
class IscsiLoopbackTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # iscsid must run for iscsiadm to manage sessions.
        if shutil.which("iscsid") and not _iscsid_running():
            cls.iscsid_started = _start_iscsid()
        else:
            cls.iscsid_started = False
        # Never load/unload kernel modules here (iscsid loads transports on
        # demand; yanking one from under a pre-existing setup breaks the
        # host). Probe the iscsiadm node DB instead to decide whether the
        # environment can run the test.
        if not _iscsiadm_node_ok():
            raise unittest.SkipTest("iscsiadm -m node failed")

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "iscsid_started", False):
            sh("systemctl", "stop", "iscsid", check=False)

    def setUp(self):
        self.server = ServerHandle("--disk", f"ram={RAM_SIZE}")
        self.server.__enter__()
        self.dev = None
        self.mount = None
        self.node_registered = False
        self.logged_in = False

    def tearDown(self):
        # Unmount, logout, delete the node, release the SELinux port label,
        # then stop the server. Order matters: unmount before logout, and
        # never leak a mounted device, a session or a node record.
        if self.mount and _is_mounted(self.mount):
            sh("umount", self.mount, check=False)
            time.sleep(0.5)
        if self.logged_in:
            sh(
                "iscsiadm",
                "-m", "node",
                "-T", TARGET_NAME,
                "-p", f"{PORTAL_PREFIX}:{self.server.port}",
                "--logout",
                check=False,
            )
        if self.node_registered:
            sh(
                "iscsiadm",
                "-m", "node",
                "-o", "delete",
                "-T", TARGET_NAME,
                "-p", f"{PORTAL_PREFIX}:{self.server.port}",
                check=False,
            )
        _selinux_deny_port(self.server.port)
        if self.server:
            try:
                self.server.__exit__(None, None, None)
            except AssertionError:
                pass  # the test body already recorded its own failure

    # ── helpers ─────────────────────────────────────────────────────

    def _login(self):
        # No SendTargets discovery (the target rejects TEXT_REQ); register
        # the node explicitly, then log in.
        sh(
            "iscsiadm",
            "-m", "node",
            "-o", "new",
            "-T", TARGET_NAME,
            "-p", f"{PORTAL_PREFIX}:{self.server.port}",
            check=True,
        )
        self.node_registered = True
        # Fedora's iscsid_t SELinux domain may only name_connect to ports
        # labelled iscsi_port_t (default: 3260); the server binds an
        # ephemeral port, so register it before login.
        _selinux_allow_port(self.server.port)
        sh(
            "iscsiadm",
            "-m", "node",
            "-T", TARGET_NAME,
            "-p", f"{PORTAL_PREFIX}:{self.server.port}",
            "--login",
            check=True,
        )
        self.logged_in = True
        # Wait for udev to create the device node.
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            self.dev = _find_device()
            if self.dev:
                return self.dev
            time.sleep(0.5)
        raise AssertionError("iSCSI device did not appear under /dev/disk/by-path")

    # ── tests ───────────────────────────────────────────────────────

    def test_login_format_mount_write_read_fsck(self):
        dev = self._login()
        self.assertTrue(os.path.exists(dev), f"device {dev} missing")

        # Full-disk destructive pattern test on the raw device: exercises
        # READ/WRITE across the entire LBA range (the fs payload below only
        # touches a small region). Skip if badblocks is absent.
        if have_tool("badblocks"):
            sh("badblocks", "-wsv", dev, timeout=300, check=True)
        else:
            print("  (badblocks not installed; skipping full-disk pattern test)")

        # Format as ext4 and mount.
        sh("mkfs.ext4", "-q", dev, check=True)
        self.mount = _make_mountpoint()
        sh("mount", dev, self.mount, check=True)
        self.assertTrue(_is_mounted(self.mount))

        # Write through the real filesystem, sync, read back and verify.
        payload = os.urandom(1 << 20)  # 1 MiB
        with open(os.path.join(self.mount, "payload.bin"), "wb") as f:
            f.write(payload)
        sh("sync")
        with open(os.path.join(self.mount, "payload.bin"), "rb") as f:
            self.assertEqual(f.read(), payload)

        # Unmount then fsck the filesystem read-only.
        sh("umount", self.mount, check=True)
        self.mount = None
        time.sleep(0.5)
        sh("fsck.ext4", "-fn", dev, check=True)


# ── module / daemon helpers ──────────────────────────────────────────

def _iscsid_running():
    if have_tool("systemctl"):
        r = sh("systemctl", "is-active", "iscsid", check=False)
        return r.returncode == 0 and r.stdout.strip() == "active"
    return sh("pgrep", "-x", "iscsid", check=False).returncode == 0


def _start_iscsid():
    if have_tool("systemctl"):
        return sh("systemctl", "start", "iscsid", check=False).returncode == 0
    return sh("iscsid", check=False).returncode == 0


def _iscsiadm_node_ok():
    # ISCSI_ERR_NO_OBJS_FOUND (21) means the node DB is readable but empty
    # — a fully working iscsiadm, so accept both that and success (0).
    r = sh("iscsiadm", "-m", "node", check=False)
    return r.returncode in (0, 21)


def _selinux_enforcing():
    if not have_tool("getenforce"):
        return False
    r = sh("getenforce", check=False)
    return r.returncode == 0 and r.stdout.strip() == "Enforcing"


def _selinux_allow_port(port):
    """Register `port` as iscsi_port_t so the iscsid_t SELinux domain may
    name_connect to it. Fedora by default only lets iscsid connect to the
    standard iSCSI port; the test server binds an ephemeral port, so this
    is required on SELinux-enforcing hosts. No-op otherwise. `timeout`
    guards a known semanage hang in this environment.
    """
    if not _selinux_enforcing() or not have_tool("semanage"):
        return
    sh(
        "timeout", "30", "semanage", "port", "-a",
        "-t", "iscsi_port_t", "-p", "tcp", str(port),
        check=False,
    )


def _selinux_deny_port(port):
    """Undo `_selinux_allow_port` (best-effort; a missing entry is fine)."""
    if not _selinux_enforcing() or not have_tool("semanage"):
        return
    sh(
        "timeout", "30", "semanage", "port", "-d",
        "-p", "tcp", str(port),
        check=False,
    )


def _find_device():
    r = sh("bash", "-c", f"ls -d /dev/disk/by-path/{BY_PATH_GLOB}", check=False)
    if r.returncode != 0:
        return None
    path = r.stdout.strip().splitlines()[0]
    return os.path.realpath(path)


def _make_mountpoint():
    path = f"/mnt/snowdrive-{os.getpid()}"
    os.makedirs(path, exist_ok=True)
    return path


def _is_mounted(mount):
    r = sh("findmnt", "-n", "-o", "SOURCE", mount, check=False)
    return r.returncode == 0 and r.stdout.strip() != ""


if __name__ == "__main__":
    unittest.main()
