"""
Filesystem module - AI file operations with safety guardrails.

Write operations are blocked for sensitive system paths.
"""

import os
import shutil
import logging
from pathlib import Path

logger = logging.getLogger("ai-control.filesystem")

# Paths that must never be written/deleted by the AI daemon.
# Directory entries MUST end with "/" to avoid matching unrelated
# siblings (e.g. "/usr/bin" accidentally matching "/usr/binary-data").
_BLOCKED_WRITE_PATHS = (
    "/etc/passwd", "/etc/shadow", "/etc/gshadow", "/etc/group",
    "/etc/sudoers", "/etc/ssh/sshd_config",
    "/etc/pam.d/", "/etc/security/", "/etc/ld.so.conf", "/etc/ld.so.cache",
    "/etc/cron.d/", "/etc/cron.daily/", "/etc/cron.hourly/",
    "/etc/cron.monthly/", "/etc/cron.weekly/", "/etc/crontab",
    "/boot/", "/usr/lib/systemd/", "/usr/bin/",
    "/usr/lib/", "/usr/sbin/", "/sbin/", "/bin/",
    "/root/.ssh/",
    "/var/lib/ai-control/",
    "/proc/", "/sys/", "/dev/",
)

# Paths that must never be read by the AI daemon (secrets/credentials)
_BLOCKED_READ_PATHS = (
    "/etc/shadow", "/etc/gshadow",
    "/root/.ssh/",
    "/var/lib/ai-control/auth_secret",
    "/etc/ssh/ssh_host_",
)


def _sanitize_log(s: str) -> str:
    """Strip CR/LF/NUL from user-supplied strings before logging."""
    if not isinstance(s, str):
        s = str(s)
    return s.replace("\r", "\\r").replace("\n", "\\n").replace("\x00", "\\0")[:512]


def _safe_realpath(path: str) -> str:
    """Canonicalize a path string, rejecting non-string / NUL input.

    Raises ValueError on obviously bad input.
    """
    if not isinstance(path, str) or not path:
        raise ValueError("path must be a non-empty string")
    if "\x00" in path:
        raise ValueError("path contains NUL byte")
    try:
        return os.path.realpath(path)
    except (OSError, ValueError) as e:
        raise ValueError(f"cannot resolve path: {e}")


def _check_path_blocked(rp: str, blocked_list: tuple, operation: str) -> str | None:
    """Return an error string if resolved path *rp* is in a blocked zone, else None."""
    for blocked in blocked_list:
        if blocked.endswith("/"):
            # Directory prefix: match children and the dir itself.
            if rp == blocked.rstrip("/") or rp.startswith(blocked):
                return f"{operation} blocked: path is inside protected path {blocked}"
        else:
            # Exact file match only; no prefix match on non-dir entries
            # (prevents "/etc/passwd" from shadowing "/etc/passwd-safe").
            if rp == blocked:
                return f"{operation} blocked: path is a protected file"
    return None


def _check_write_safe(path: str) -> str:
    """Check if path is safe to write. Returns resolved path.

    Raises ValueError if the path is blocked.
    """
    rp = _safe_realpath(path)
    err = _check_path_blocked(rp, _BLOCKED_WRITE_PATHS, "write")
    if err:
        raise ValueError(err)
    # Also refuse to write anything that resolves to a symlink target
    # outside the blocklist but whose parent is a blocked dir.
    parent = os.path.dirname(rp)
    err2 = _check_path_blocked(parent, _BLOCKED_WRITE_PATHS, "write")
    if err2:
        raise ValueError(err2)
    return rp


def _check_read_safe(path: str) -> str:
    """Check if path is safe to read. Returns resolved path.

    Raises ValueError if the path is blocked.
    """
    rp = _safe_realpath(path)
    err = _check_path_blocked(rp, _BLOCKED_READ_PATHS, "read")
    if err:
        raise ValueError(err)
    return rp


# Max file read size to avoid DoS via reading /dev/zero, /dev/urandom, or huge logs.
_MAX_READ_BYTES = 64 * 1024 * 1024  # 64 MiB


class FilesystemController:
    """Filesystem operations with write-safety guardrails."""

    def read_file(self, path: str, encoding: str = "utf-8") -> dict:
        """Read a file's contents."""
        try:
            rp = _check_read_safe(path)
        except ValueError as e:
            logger.warning("Blocked read: %s", _sanitize_log(str(e)))
            return {"success": False, "error": str(e)}
        try:
            # Use O_NOFOLLOW on the final component to prevent symlink-to-secret.
            # os.path.realpath already resolved symlinks, but defense in depth:
            # re-check whether the realpath is a regular file.
            try:
                st = os.lstat(rp)
            except OSError as e:
                return {"success": False, "error": str(e)}
            if not (os.path.stat.S_ISREG(st.st_mode) or os.path.stat.S_ISLNK(st.st_mode) is False):
                pass  # realpath stripped symlinks already; accept regular files only
            if not os.path.isfile(rp):
                return {"success": False, "error": "not a regular file"}
            if st.st_size > _MAX_READ_BYTES:
                return {"success": False, "error": f"file too large ({st.st_size} bytes)"}
            try:
                with open(rp, "r", encoding=encoding) as f:
                    return {"success": True, "content": f.read(_MAX_READ_BYTES + 1)}
            except UnicodeDecodeError:
                with open(rp, "rb") as f:
                    import base64
                    return {"success": True, "content_base64": base64.b64encode(f.read(_MAX_READ_BYTES + 1)).decode()}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def write_file(self, path: str, content: str, encoding: str = "utf-8") -> dict:
        """Write content to a file."""
        try:
            rp = _check_write_safe(path)
        except ValueError as e:
            logger.warning("Blocked write: %s", _sanitize_log(str(e)))
            return {"success": False, "error": str(e)}
        try:
            parent = Path(rp).parent
            parent.mkdir(parents=True, exist_ok=True)
            # Open with O_NOFOLLOW on the final component to refuse following
            # a symlink planted by another user pointing at /etc/shadow etc.
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
            fd = os.open(rp, flags, 0o600)
            try:
                with os.fdopen(fd, "w", encoding=encoding) as f:
                    f.write(content)
            except Exception:
                os.close(fd) if isinstance(fd, int) and fd >= 0 else None
                raise
            return {"success": True}
        except OSError as e:
            return {"success": False, "error": str(e)}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def append_file(self, path: str, content: str) -> dict:
        """Append content to a file."""
        try:
            rp = _check_write_safe(path)
        except ValueError as e:
            logger.warning("Blocked append: %s", _sanitize_log(str(e)))
            return {"success": False, "error": str(e)}
        try:
            flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW
            fd = os.open(rp, flags, 0o600)
            with os.fdopen(fd, "a") as f:
                f.write(content)
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def delete_file(self, path: str) -> dict:
        """Delete a file."""
        try:
            rp = _check_write_safe(path)
        except ValueError as e:
            logger.warning("Blocked delete: %s", _sanitize_log(str(e)))
            return {"success": False, "error": str(e)}
        try:
            # Refuse to unlink symlinks (they may point outside the allowed tree).
            st = os.lstat(rp)
            import stat as _stat
            if _stat.S_ISLNK(st.st_mode):
                return {"success": False, "error": "refusing to unlink symlink"}
            os.remove(rp)
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def list_directory(self, path: str) -> dict:
        """List directory contents."""
        try:
            rp = _safe_realpath(path)
        except ValueError as e:
            return {"success": False, "error": str(e)}
        # Block directory listings under read-protected paths so /root/.ssh/
        # contents can't be enumerated (even if individual files are blocked).
        err = _check_path_blocked(rp, _BLOCKED_READ_PATHS, "list")
        if err:
            logger.warning("Blocked list_directory: %s", _sanitize_log(err))
            return {"success": False, "error": err}
        try:
            entries = []
            with os.scandir(rp) as it:
                for entry in it:
                    try:
                        stat = entry.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    entries.append({
                        "name": entry.name,
                        "is_dir": entry.is_dir(follow_symlinks=False),
                        "is_file": entry.is_file(follow_symlinks=False),
                        "is_symlink": entry.is_symlink(),
                        "size": stat.st_size,
                        "modified": stat.st_mtime,
                    })
            return {"success": True, "entries": entries}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def create_directory(self, path: str) -> dict:
        """Create a directory (including parents)."""
        try:
            rp = _check_write_safe(path)
        except ValueError as e:
            logger.warning("Blocked create_directory: %s", _sanitize_log(str(e)))
            return {"success": False, "error": str(e)}
        try:
            Path(rp).mkdir(parents=True, exist_ok=True)
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def delete_directory(self, path: str) -> dict:
        """Delete a directory recursively."""
        try:
            rp = _check_write_safe(path)
        except ValueError as e:
            logger.warning("Blocked delete_directory: %s", _sanitize_log(str(e)))
            return {"success": False, "error": str(e)}
        # Never recursively delete a filesystem root or very shallow path.
        if rp in ("/", "") or rp.count("/") < 2:
            return {"success": False, "error": f"refusing to rmtree shallow path: {rp}"}
        try:
            # Refuse symlinks — shutil.rmtree follows them and can wipe unrelated trees.
            import stat as _stat
            try:
                st = os.lstat(rp)
                if _stat.S_ISLNK(st.st_mode):
                    return {"success": False, "error": "refusing to rmtree symlink"}
            except OSError:
                pass
            shutil.rmtree(rp)
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def copy(self, src: str, dst: str) -> dict:
        """Copy a file or directory."""
        try:
            rp_src = _check_read_safe(src)
            rp_dst = _check_write_safe(dst)
        except ValueError as e:
            logger.warning("Blocked copy: %s", _sanitize_log(str(e)))
            return {"success": False, "error": str(e)}
        try:
            if os.path.isdir(rp_src):
                shutil.copytree(rp_src, rp_dst, symlinks=True)
            else:
                shutil.copy2(rp_src, rp_dst, follow_symlinks=False)
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def move(self, src: str, dst: str) -> dict:
        """Move/rename a file or directory."""
        try:
            rp_src = _check_write_safe(src)
            rp_dst = _check_write_safe(dst)
        except ValueError as e:
            logger.warning("Blocked move: %s", _sanitize_log(str(e)))
            return {"success": False, "error": str(e)}
        try:
            shutil.move(rp_src, rp_dst)
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def file_info(self, path: str) -> dict:
        """Get detailed file information."""
        try:
            rp = _safe_realpath(path)
        except ValueError as e:
            return {"success": False, "error": str(e)}
        # file_info is metadata only — still block it under read-protected zones
        # so path existence of /root/.ssh/id_ed25519 isn't probeable.
        err = _check_path_blocked(rp, _BLOCKED_READ_PATHS, "stat")
        if err:
            return {"success": False, "error": err}
        try:
            stat = os.lstat(rp)
            return {
                "success": True,
                "exists": True,
                "size": stat.st_size,
                "mode": oct(stat.st_mode),
                "uid": stat.st_uid,
                "gid": stat.st_gid,
                "atime": stat.st_atime,
                "mtime": stat.st_mtime,
                "ctime": stat.st_ctime,
                "is_dir": os.path.isdir(rp),
                "is_file": os.path.isfile(rp),
                "is_symlink": os.path.islink(rp),
            }
        except FileNotFoundError:
            return {"success": True, "exists": False}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def chmod(self, path: str, mode: int) -> dict:
        """Change file permissions."""
        try:
            rp = _check_write_safe(path)
        except ValueError as e:
            logger.warning("Blocked chmod: %s", _sanitize_log(str(e)))
            return {"success": False, "error": str(e)}
        try:
            if not isinstance(mode, int) or mode < 0 or mode > 0o7777:
                return {"success": False, "error": "mode must be int in [0, 0o7777]"}
            # Use lchmod-equivalent via chmod with follow_symlinks=False where supported.
            try:
                os.chmod(rp, mode, follow_symlinks=False)
            except (NotImplementedError, TypeError):
                # Fallback: chmod resolves realpath already, but refuse if final is a symlink.
                import stat as _stat
                st = os.lstat(rp)
                if _stat.S_ISLNK(st.st_mode):
                    return {"success": False, "error": "refusing chmod on symlink"}
                os.chmod(rp, mode)
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def chown(self, path: str, uid: int, gid: int) -> dict:
        """Change file ownership."""
        try:
            rp = _check_write_safe(path)
        except ValueError as e:
            logger.warning("Blocked chown: %s", _sanitize_log(str(e)))
            return {"success": False, "error": str(e)}
        try:
            if not isinstance(uid, int) or not isinstance(gid, int):
                return {"success": False, "error": "uid/gid must be ints"}
            if uid < -1 or gid < -1 or uid > 0xFFFFFFFE or gid > 0xFFFFFFFE:
                return {"success": False, "error": "uid/gid out of range"}
            os.chown(rp, uid, gid, follow_symlinks=False)
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}
