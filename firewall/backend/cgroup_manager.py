"""
cgroup v2 manager for firewall app-level rule enforcement.

The firewall emits nftables rules like::

    socket cgroupv2 level 2 "pe-compat.slice/firefox.scope"

For those predicates to ever match, the target application's PIDs must
actually live inside that cgroup path.  This module creates the slice /
scope directories on the unified cgroup v2 hierarchy and moves PIDs into
the appropriate scope so the nft matches actually fire.

Two placement strategies:

* **systemd-run** (preferred for new launches) -- wrap a command in a
  transient systemd scope unit bound to ``pe-compat.slice``.  systemd
  handles cgroup creation, controller enabling, and cleanup when the
  last PID exits.

* **direct cgroup write** (needed for already-running PIDs) -- mkdir the
  scope directory under ``/sys/fs/cgroup/pe-compat.slice`` and write the
  PID to ``cgroup.procs``.  Requires root and cgroup v2 unified mode.

If cgroup v2 is unavailable or we lack permission the manager degrades
gracefully: public calls return False / log a warning and leave the
firewall to operate without the app predicate (it just won't match
anything, which is the same behaviour as before this module existed).
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
from typing import Optional

logger = logging.getLogger("firewall.cgroup_manager")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CGROUP_ROOT = "/sys/fs/cgroup"
CGROUP_CONTROLLERS = "/sys/fs/cgroup/cgroup.controllers"
DEFAULT_SLICE = "pe-compat.slice"

# Controllers we would like enabled in the slice's subtree.  "pids" and
# "memory" are sufficient for our predicate to work (cgroup membership
# is enough for nft matching -- we don't actually need cpu/io controllers
# just to match sockets by cgroup path).
_DESIRED_CONTROLLERS = ("pids",)

# PIDs we refuse to move even if asked.  PID 1 is systemd, PID 2 is
# kthreadd and kernel threads cannot be moved at all -- writing them
# to cgroup.procs returns EINVAL and spams the kernel log.
_FORBIDDEN_PIDS = frozenset({0, 1, 2})

# Validate app names that form cgroup directory components.  Path
# traversal into other slices is prevented by requiring this pattern.
# Length cap of 64 keeps the scope name under cgroup's 255-byte limit.
_APP_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_\-]{0,63}$")


class CgroupError(Exception):
    """Raised when a cgroup operation fails for caller-visible reasons."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _validate_app_name(app_name: str) -> str:
    """Return *app_name* if safe for use as a scope directory component.

    Raises :class:`CgroupError` if the name contains characters that
    could escape the slice directory via ``..`` or embed shell
    metacharacters.  Caller is expected to sanitise first but we
    defence-in-depth here because this string ends up in a filesystem
    path AND in an nft rule string.
    """
    if not isinstance(app_name, str):
        raise CgroupError(f"app_name must be str, got {type(app_name).__name__}")
    if not _APP_NAME_RE.match(app_name):
        raise CgroupError(
            f"Invalid app_name {app_name!r}: must match [a-zA-Z0-9_-]+ "
            f"(1-64 chars, start alnum)"
        )
    return app_name


def app_name_from_path(app_path: str) -> Optional[str]:
    """Derive a safe cgroup app-name component from a binary path.

    Mirrors the mapping used in ``nft_manager._app_to_cgroup``: take the
    basename, replace dots with underscores, then validate.  Returns
    None if the result would be unsafe.
    """
    if not app_path:
        return None
    basename = os.path.basename(app_path).replace(".", "_")
    if not basename:
        return None
    # Strip any remaining non-conforming characters by truncating to
    # the allowed set rather than rejecting -- helps with names like
    # "chrome-sandbox" which are common.
    basename = re.sub(r"[^a-zA-Z0-9_\-]", "_", basename)[:64]
    if not _APP_NAME_RE.match(basename):
        return None
    return basename


def scope_name_for_app(app_name: str) -> str:
    """Return the scope filename for *app_name* (validated)."""
    return f"{_validate_app_name(app_name)}.scope"


def cgroup_path_for_app(app_name: str, slice_name: str = DEFAULT_SLICE) -> str:
    """Return the cgroup v2 path string used by nftables rules.

    Matches the string used in the nft rule::

        socket cgroupv2 level 2 "pe-compat.slice/<app>.scope"
    """
    return f"{slice_name}/{scope_name_for_app(app_name)}"


def fs_path_for_app(app_name: str, slice_name: str = DEFAULT_SLICE) -> str:
    """Return the absolute filesystem path of the scope directory.

    Uses forward-slash joins deliberately: cgroup v2 only exists on Linux,
    where ``/`` is the only valid separator.  Using :func:`os.path.join`
    on a Windows build host would emit backslashes and break the string
    used in the nft predicate if a developer ever serialises it.
    """
    return f"{fs_path_for_slice(slice_name)}/{scope_name_for_app(app_name)}"


def fs_path_for_slice(slice_name: str = DEFAULT_SLICE) -> str:
    """Return the absolute filesystem path of the slice directory."""
    # Slice names come from our own constants; still sanity-check.
    if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9_\-\.]{0,63}$", slice_name):
        raise CgroupError(f"Invalid slice_name {slice_name!r}")
    return f"{CGROUP_ROOT}/{slice_name}"


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

def detect_cgroupv2() -> bool:
    """Return True iff the unified cgroup v2 hierarchy is mounted.

    The canonical check is that ``/sys/fs/cgroup/cgroup.controllers``
    exists -- this file only appears in cgroup v2 unified mode.  Hybrid
    mode mounts v2 under ``/sys/fs/cgroup/unified`` and lacks this file
    at the top level, which we treat as "no v2" because our nft rules
    use top-level paths.
    """
    try:
        return os.path.isfile(CGROUP_CONTROLLERS)
    except OSError as exc:
        logger.debug("detect_cgroupv2 stat failed: %s", exc)
        return False


def have_write_permission(path: str = CGROUP_ROOT) -> bool:
    """Return True if we can create directories under *path*."""
    try:
        return os.access(path, os.W_OK)
    except OSError:
        return False


# ---------------------------------------------------------------------------
# CgroupManager
# ---------------------------------------------------------------------------

class CgroupManager:
    """Create firewall cgroup scopes and move PIDs into them."""

    def __init__(self, slice_name: str = DEFAULT_SLICE) -> None:
        # Slice constant -- callers should not change this at runtime
        # because the nft rules are compiled with the default value.
        self._slice_name = slice_name
        self._available: Optional[bool] = None
        self._slice_ready: bool = False
        self._systemd_run_bin = shutil.which("systemd-run")

    # ------------------------------------------------------------------
    # Availability
    # ------------------------------------------------------------------

    def available(self) -> bool:
        """Cache-aware check for cgroup v2 availability with write access."""
        if self._available is not None:
            return self._available
        v2 = detect_cgroupv2()
        if not v2:
            logger.warning(
                "cgroup v2 unified hierarchy not detected at %s -- "
                "app-level firewall rules will not match",
                CGROUP_CONTROLLERS,
            )
            self._available = False
            return False
        if not have_write_permission(CGROUP_ROOT):
            logger.warning(
                "no write permission on %s (daemon not running as root?) -- "
                "app-level firewall rules will not match",
                CGROUP_ROOT,
            )
            self._available = False
            return False
        self._available = True
        return True

    # ------------------------------------------------------------------
    # Slice / scope creation
    # ------------------------------------------------------------------

    def ensure_slice(self) -> bool:
        """Create ``pe-compat.slice`` and enable controllers.  Idempotent.

        Returns True on success or if the slice already exists, False on
        any failure.  Failure is logged but never raised so the firewall
        daemon keeps running.
        """
        if self._slice_ready:
            return True
        if not self.available():
            return False

        slice_path = fs_path_for_slice(self._slice_name)

        try:
            os.makedirs(slice_path, mode=0o755, exist_ok=True)
        except PermissionError as exc:
            logger.error("Cannot create %s: %s", slice_path, exc)
            return False
        except OSError as exc:
            # EBUSY if the slice is actively being populated by systemd.
            # We treat it as "already exists" since the directory is there.
            if not os.path.isdir(slice_path):
                logger.error("Cannot create %s: %s", slice_path, exc)
                return False

        # Ask the parent cgroup to enable controllers so our children can
        # use them.  This is best-effort -- controllers that aren't
        # available in the parent subtree_control can't be enabled.
        self._enable_subtree_controllers(CGROUP_ROOT)
        self._enable_subtree_controllers(slice_path)

        self._slice_ready = True
        logger.info("cgroup slice ready: %s", slice_path)
        return True

    def _enable_subtree_controllers(self, cgroup_dir: str) -> None:
        """Best-effort attempt to enable controllers in a cgroup's subtree."""
        ctrl_path = os.path.join(cgroup_dir, "cgroup.subtree_control")
        if not os.path.isfile(ctrl_path):
            return

        # Read current state to avoid writing no-ops that might fail
        # because a controller isn't present in cgroup.controllers.
        try:
            with open(os.path.join(cgroup_dir, "cgroup.controllers"), "r") as fh:
                available = set(fh.read().split())
        except OSError:
            available = set()

        try:
            with open(ctrl_path, "r") as fh:
                current = set()
                for part in fh.read().split():
                    current.add(part.lstrip("+-"))
        except OSError:
            current = set()

        for ctrl in _DESIRED_CONTROLLERS:
            if ctrl in current or ctrl not in available:
                continue
            try:
                with open(ctrl_path, "w") as fh:
                    fh.write(f"+{ctrl}")
            except OSError as exc:
                # EBUSY if the cgroup has processes directly in it -- on
                # the root that's normal (everything is there at boot);
                # we just skip.  EINVAL if the controller can't be moved.
                logger.debug(
                    "Could not enable %s controller in %s: %s",
                    ctrl, cgroup_dir, exc,
                )

    def ensure_app_scope(self, app_name: str) -> Optional[str]:
        """Create the scope directory for *app_name*.  Returns its path or None.

        Idempotent -- calling this repeatedly for the same app is cheap
        (one ``mkdir(exist_ok=True)`` call).
        """
        if not self.ensure_slice():
            return None
        try:
            scope_path = fs_path_for_app(app_name, self._slice_name)
        except CgroupError as exc:
            logger.warning("ensure_app_scope: %s", exc)
            return None

        try:
            os.makedirs(scope_path, mode=0o755, exist_ok=True)
        except PermissionError as exc:
            logger.error("Cannot create scope %s: %s", scope_path, exc)
            return None
        except OSError as exc:
            if not os.path.isdir(scope_path):
                logger.error("Cannot create scope %s: %s", scope_path, exc)
                return None
        return scope_path

    # ------------------------------------------------------------------
    # PID placement
    # ------------------------------------------------------------------

    def move_pid_to_app_scope(self, pid: int, app_name: str) -> bool:
        """Move *pid* into ``pe-compat.slice/<app_name>.scope``.

        Returns True on success.  Logs a warning and returns False for
        any failure (forbidden PID, scope creation failure, dead process,
        frozen cgroup, etc.) -- callers should not retry tight-loop, as
        most failures indicate structural issues.
        """
        if not isinstance(pid, int) or pid <= 0:
            logger.debug("move_pid_to_app_scope: invalid pid %r", pid)
            return False
        if pid in _FORBIDDEN_PIDS:
            logger.debug(
                "move_pid_to_app_scope: refusing to move kernel/init pid %d",
                pid,
            )
            return False

        # Don't move kernel threads (parent pid 2).  Reading status is
        # cheap and avoids a cgroup write that kernel would reject anyway.
        if self._is_kernel_thread(pid):
            logger.debug("move_pid_to_app_scope: pid %d is a kernel thread", pid)
            return False

        scope_path = self.ensure_app_scope(app_name)
        if scope_path is None:
            return False

        procs_file = os.path.join(scope_path, "cgroup.procs")
        try:
            with open(procs_file, "w") as fh:
                fh.write(str(pid))
        except FileNotFoundError:
            # Process exited between check and write -- not an error.
            logger.debug(
                "move_pid_to_app_scope: pid %d exited before cgroup write", pid,
            )
            return False
        except PermissionError as exc:
            logger.warning(
                "move_pid_to_app_scope: permission denied writing pid %d "
                "to %s: %s", pid, procs_file, exc,
            )
            return False
        except OSError as exc:
            # EBUSY = cgroup frozen or conflicting controller, EINVAL =
            # kernel thread or invalid placement, ESRCH = pid gone.
            logger.warning(
                "move_pid_to_app_scope: could not place pid %d in %s: %s",
                pid, scope_path, exc,
            )
            return False
        logger.info(
            "Placed pid %d into cgroup %s/%s.scope",
            pid, self._slice_name, app_name,
        )
        return True

    def _is_kernel_thread(self, pid: int) -> bool:
        """Return True if *pid* is a kernel thread (parent pid 2)."""
        try:
            with open(f"/proc/{pid}/status", "r") as fh:
                for line in fh:
                    if line.startswith("PPid:"):
                        ppid = int(line.split()[1])
                        return ppid in (0, 2)
        except (FileNotFoundError, PermissionError, ValueError, OSError):
            return False
        return False

    # ------------------------------------------------------------------
    # systemd-run launch helper (preferred for new launches)
    # ------------------------------------------------------------------

    def systemd_scope_run(
        self,
        command: list[str],
        app_name: str,
        slice_name: Optional[str] = None,
        extra_args: Optional[list[str]] = None,
    ) -> Optional[subprocess.Popen]:
        """Launch *command* inside a transient scope under the slice.

        Equivalent to::

            systemd-run --scope --slice=pe-compat.slice \\
                        --unit=fw-app-<name>.scope -- <command...>

        Returns the :class:`subprocess.Popen` handle on success or None
        if systemd-run is unavailable or the launch failed.  The caller
        owns the returned handle and is responsible for wait()/poll().

        Falls back to direct launch + :meth:`move_pid_to_app_scope` when
        systemd-run is missing, so callers don't need to branch.
        """
        try:
            _validate_app_name(app_name)
        except CgroupError as exc:
            logger.warning("systemd_scope_run: %s", exc)
            return None
        if not command or not isinstance(command, list):
            logger.warning("systemd_scope_run: command must be a non-empty list")
            return None

        slice_to_use = slice_name or self._slice_name

        # Ensure slice exists before launch so systemd-run can nest under it.
        self.ensure_slice()

        if self._systemd_run_bin:
            unit_name = f"fw-app-{app_name}.scope"
            argv = [
                self._systemd_run_bin,
                "--scope",
                f"--slice={slice_to_use}",
                f"--unit={unit_name}",
                "--collect",  # cleans up the scope after the process exits
            ]
            if extra_args:
                argv.extend(extra_args)
            argv.append("--")
            argv.extend(command)
            try:
                return subprocess.Popen(argv)
            except (FileNotFoundError, PermissionError, OSError) as exc:
                logger.warning(
                    "systemd-run failed for %s, falling back to direct launch: %s",
                    app_name, exc,
                )

        # Fallback: plain launch + cgroup move.  The target process sees
        # one round-trip's worth of time in the root cgroup; any sockets
        # opened in that window won't match the predicate, but normal
        # programs open sockets well after fork so this is fine.
        try:
            proc = subprocess.Popen(command)
        except (FileNotFoundError, PermissionError, OSError) as exc:
            logger.error("systemd_scope_run direct launch failed: %s", exc)
            return None
        self.move_pid_to_app_scope(proc.pid, app_name)
        return proc


# ---------------------------------------------------------------------------
# Module-level singleton helpers
# ---------------------------------------------------------------------------

_default_manager: Optional[CgroupManager] = None


def get_manager() -> CgroupManager:
    """Return a process-wide :class:`CgroupManager` instance."""
    global _default_manager
    if _default_manager is None:
        _default_manager = CgroupManager()
    return _default_manager


def ensure_app_scoped(pid: int, app_name: str) -> bool:
    """Idempotent ``move_pid_to_app_scope`` against the default manager."""
    return get_manager().move_pid_to_app_scope(pid, app_name)


def ensure_slice(slice_name: str = DEFAULT_SLICE) -> bool:
    """Module-level :meth:`CgroupManager.ensure_slice` wrapper.

    Always operates on the default manager singleton so callers that
    only want to pre-create the slice (without touching PIDs) have a
    one-liner.  Returns False cleanly on cgroup v1, missing perms, or
    any OS error -- never raises.
    """
    try:
        return get_manager().ensure_slice()
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("ensure_slice failed: %s", exc)
        return False


def systemd_scope_run(
    command: list[str],
    app_name: str,
    slice_name: Optional[str] = None,
    extra_args: Optional[list[str]] = None,
) -> Optional[subprocess.Popen]:
    """Module-level wrapper around :meth:`CgroupManager.systemd_scope_run`.

    Provides the "preferred for new launches" entry point described in
    the module docstring: callers that want to spawn a process already
    attached to ``pe-compat.slice/<app>.scope`` just call this helper
    without instantiating a manager.
    """
    return get_manager().systemd_scope_run(
        command, app_name, slice_name=slice_name, extra_args=extra_args,
    )
