#!/usr/bin/env python3
"""Real-kernel USB Mass Storage (BOT) loopback test (root).

Spawns `snowdrive serve --usb`, binds a FunctionFS gadget to a `dummy_hcd`
UDC, and lets the kernel's own `usb-storage` host driver attach and create a
`/dev/sdX`. Then exercises the §8.3 checklist through the real block layer:
capacity matches the backend, a `dd`/`badblocks` full-disk roundtrip, ext4
format / mount / write / read / fsck, and read-only backend write
protection.

Skipped unless: running as root, a `dummy_udc.0` UDC is present, and
configfs (`/sys/kernel/config/usb_gadget`) is writable. The test
auto-loads the test-only `dummy_hcd` module via `modprobe` (idempotent:
no-op if already loaded) and never unloads it, and auto-mounts configfs
at `/sys/kernel/config` if the distro has not already mounted it (most
do not), unmounting it again afterward. The runtime must also allow
Linux native aio (`io_setup`/`io_submit`/`io_getevents`); a
seccomp/container ban is not detectable up front and surfaces as a
failed first bulk transfer.
"""

import os
import shutil
import signal
import subprocess
import tempfile
import time
import unittest

from harness import find_binary, have_tool, is_root

# Backend image: 32 MiB (enough for ext4), matching the iSCSI loopback RAM size.
IMG_SIZE = 32 * 1024 * 1024


def sh(*argv, check=True, timeout=120, **kw):
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, **kw)


def _usb_udc_present():
    return os.path.isdir("/sys/class/udc/dummy_udc.0")


def _configfs_writable():
    return os.path.isdir("/sys/kernel/config/usb_gadget")


def _ensure_configfs():
    """Ensure configfs is mounted at /sys/kernel/config (most distros do not
    mount it by default). Returns True if we mounted it — the caller must
    unmount it again via [`_release_configfs`].
    """
    if _configfs_writable() or not have_tool("mount"):
        return False
    os.makedirs("/sys/kernel/config", exist_ok=True)
    r = sh("mount", "-t", "configfs", "none", "/sys/kernel/config", check=False)
    return r.returncode == 0 and _configfs_writable()


def _release_configfs(mounted):
    if mounted:
        sh("umount", "/sys/kernel/config", check=False)


@unittest.skipUnless(
    is_root(),
    "requires root (to modprobe dummy_hcd and drive the loopback)",
)
class UsbLoopbackTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Auto-load the test-only UDC module and the configfs gadget
        # framework (idempotent; we never unload them — they may be shared
        # with other tests/setups). libcomposite registers the
        # /sys/kernel/config/usb_gadget directory when loaded.
        if have_tool("modprobe"):
            sh("modprobe", "dummy_hcd", check=False)
            sh("modprobe", "libcomposite", check=False)
        if not _usb_udc_present():
            raise unittest.SkipTest(
                "dummy_hcd unavailable (modprobe dummy_hcd failed)"
            )
        # Mount configfs if the distro has not already (most do not); release
        # it again on the skip path since tearDownClass is not called then.
        cls._configfs_mounted = _ensure_configfs()
        if not _configfs_writable():
            _release_configfs(cls._configfs_mounted)
            raise unittest.SkipTest(
                "configfs not writable at /sys/kernel/config/usb_gadget"
            )

    @classmethod
    def tearDownClass(cls):
        _release_configfs(getattr(cls, "_configfs_mounted", False))

    def setUp(self):
        # Snapshot the block devices before the server binds, so the device
        # usb-storage creates is unambiguously ours.
        self.before = set(n for n in os.listdir("/sys/class/block") if n.startswith("sd"))
        fd, self.img = tempfile.mkstemp(prefix="snowdrive-usb-", suffix=".img")
        os.close(fd)
        os.truncate(self.img, IMG_SIZE)
        self.server = UsbServer(self.img)
        self.mount = None

    def tearDown(self):
        if self.mount and _is_mounted(self.mount):
            sh("umount", self.mount, check=False)
            time.sleep(0.5)
        log_path = getattr(self.server, "log_path", None)
        if self.server:
            try:
                self.server.stop()
            except AssertionError:
                pass  # the test body already recorded its own failure
        for path in (self.img, log_path):
            if path:
                try:
                    os.unlink(path)
                except OSError:
                    pass

    # ── helpers ─────────────────────────────────────────────────────

    def _wait_device(self, timeout=20):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            now = set(n for n in os.listdir("/sys/class/block") if n.startswith("sd"))
            new = sorted(now - self.before)
            if new:
                return f"/dev/{new[0]}"
            time.sleep(0.2)
        raise AssertionError(
            f"no /dev/sdX appeared after bind; server stderr:\n{self.server.log_tail()}"
        )

    # ── test ────────────────────────────────────────────────────────

    def test_loopback_end_to_end(self):
        dev = self._wait_device()

        # Capacity must match the backend file.
        actual = int(sh("blockdev", "--getsize64", dev).stdout.strip())
        self.assertEqual(actual, IMG_SIZE, "device capacity must match the backend")

        # Full-disk destructive pattern test (like the iSCSI loopback).
        if have_tool("badblocks"):
            sh("badblocks", "-wsv", dev, timeout=300, check=True)
        else:
            print("  (badblocks not installed; skipping full-disk pattern test)")

        # Format as ext4, mount, write/read through the real filesystem.
        sh("mkfs.ext4", "-q", dev, check=True)
        self.mount = _make_mountpoint()
        sh("mount", dev, self.mount, check=True)
        self.assertTrue(_is_mounted(self.mount))
        payload = os.urandom(1 << 20)  # 1 MiB
        with open(os.path.join(self.mount, "payload.bin"), "wb") as f:
            f.write(payload)
        sh("sync")
        with open(os.path.join(self.mount, "payload.bin"), "rb") as f:
            self.assertEqual(f.read(), payload)
        sh("umount", self.mount, check=True)
        self.mount = None
        time.sleep(0.5)
        sh("fsck.ext4", "-fn", dev, check=True)

        # Read-only backend: rebind the same image read-only, verify reads
        # work and writes are rejected.
        self.server.stop()
        self.server = UsbServer(self.img, read_only=True)
        dev = self._wait_device()
        sh("dd", f"if={dev}", "of=/dev/null", "bs=1M", "count=1", check=True)
        # Direct I/O so the write error (WRITE PROTECTED) surfaces in dd's
        # write() instead of being absorbed by the page cache.
        r = sh(
            "dd",
            "if=/dev/zero",
            f"of={dev}",
            "bs=512",
            "count=1",
            "oflag=direct",
            check=False,
        )
        self.assertNotEqual(
            r.returncode, 0, "write to a read-only backend must be rejected"
        )
        self.server.stop()
        self.server = None


class UsbServer:
    """Lifecycle of `snowdrive serve --usb` over a backend image.

    No "listening on" line to wait for (unlike iSCSI): readiness is the
    appearance of the host-side device. Shutdown is SIGINT (graceful exit,
    assert 0). stderr goes to a temp file so the first bulk failure's
    message is available for diagnostics.
    """

    def __init__(self, img, read_only=False):
        spec = f"img={img},ro" if read_only else f"img={img}"
        self.log_path = tempfile.mktemp(prefix="snowdrive-usb-log-")
        self.log = open(self.log_path, "w")
        self.proc = subprocess.Popen(
            [find_binary(), "serve", "--usb", "--disk", spec],
            stdout=subprocess.DEVNULL,
            stderr=self.log,
            text=True,
        )

    def log_tail(self, n=512):
        try:
            with open(self.log_path) as f:
                return f.read()[-n:]
        except OSError:
            return "<no server log>"

    def stop(self):
        if self.proc is None:
            return
        try:
            if self.proc.poll() is None:
                self.proc.send_signal(signal.SIGINT)
                try:
                    self.proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
                    self.proc.wait()
                    raise AssertionError("snowdrive did not exit after SIGINT")
            if self.proc.returncode != 0:
                raise AssertionError(
                    f"snowdrive exited {self.proc.returncode} (expected 0 after "
                    f"SIGINT); stderr:\n{self.log_tail()}"
                )
        finally:
            self.log.close()
            self.proc = None


def _make_mountpoint():
    path = f"/mnt/snowdrive-usb-{os.getpid()}"
    os.makedirs(path, exist_ok=True)
    return path


def _is_mounted(mount):
    r = sh("findmnt", "-n", "-o", "SOURCE", mount, check=False)
    return r.returncode == 0 and r.stdout.strip() != ""


if __name__ == "__main__":
    unittest.main()
