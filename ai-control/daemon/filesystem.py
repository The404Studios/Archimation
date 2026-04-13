"""
Filesystem module - AI file operations with safety guardrails.

Write operations are blocked for sensitive system paths.
"""

import os
import shutil
import logging
from pathlib import Path

logger = logging.getLogger("ai-control.filesystem")

# Paths that must never be written/deleted by the AI daemon
_BLOCKED_WRITE_PATHS = (
    "/etc/passwd", "/etc/shadow", "/etc/gshadow", "/etc/group",
    "/etc/sudoers", "/etc/ssh/sshd_config",
    "/etc/pam.d/", "/etc/security/", "/etc/ld.so", "/etc/cron",
    "/boot/", "/usr/lib/systemd/", "/usr/bin/",
    "/usr/lib/", "/usr/sbin/", "/sbin/",
    "/root/.ssh/",
    "/var/lib/ai-control/",
)

# Paths that must never be read by the AI daemon (secrets/credentials)
_BLOCKED_READ_PATHS = (
    "/etc/shadow", "/etc/gshadow",
    "/root/.ssh/id_", "/root/.ssh/authorized_keys",
    "/var/lib/ai-control/auth_secret",
)


def _check_path_blocked(rp: str, blocked_list: tuple, operation: str) -> str | None:
    """Return an error string if resolved path *rp* is in a blocked zone, else None."""
    for blocked in blocked_list:
        if blocked.endswith("/"):
            if rp.startswith(blocked) or rp == blocked.rstrip("/"):
                return f"{operation} blocked: {rp} is inside protected path {blocked}"
        elif rp == blocked or rp.startswith(blocked):
            return f"{operation} blocked: {rp} is a protected file"
    return None


def _check_write_safe(path: str) -> str:
    """Check if path is safe to write. Returns resolved path.

    Raises ValueError if the path is blocked.
    """
    rp = os.path.realpath(path)
    err = _check_path_blocked(rp, _BLOCKED_WRITE_PATHS, "write")
    if err:
        raise ValueError(err)
    return rp


def _check_read_safe(path: str) -> str:
    """Check if path is safe to read. Returns resolved path.

    Raises ValueError if the path is blocked.
    """
    rp = os.path.realpath(path)
    err = _check_path_blocked(rp, _BLOCKED_READ_PATHS, "read")
    if err:
        raise ValueError(err)
    return rp


class FilesystemController:
    """Filesystem operations with write-safety guardrails."""

    def read_file(self, path: str, encoding: str = "utf-8") -> dict:
        """Read a file's contents."""
        try:
            rp = _check_read_safe(path)
        except ValueError as e:
            logger.warning("Blocked read: %s", e)
            return {"success": False, "error": str(e)}
        try:
            with open(rp, "r", encoding=encoding) as f:
                return {"success": True, "content": f.read()}
        except UnicodeDecodeError:
            with open(rp, "rb") as f:
                import base64
                return {"success": True, "content_base64": base64.b64encode(f.read()).decode()}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def write_file(self, path: str, content: str, encoding: str = "utf-8") -> dict:
        """Write content to a file."""
        try:
            rp = _check_write_safe(path)
        except ValueError as e:
            logger.warning("Blocked write: %s", e)
            return {"success": False, "error": str(e)}
        try:
            Path(rp).parent.mkdir(parents=True, exist_ok=True)
            with open(rp, "w", encoding=encoding) as f:
                f.write(content)
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def append_file(self, path: str, content: str) -> dict:
        """Append content to a file."""
        try:
            rp = _check_write_safe(path)
        except ValueError as e:
            logger.warning("Blocked append: %s", e)
            return {"success": False, "error": str(e)}
        try:
            with open(rp, "a") as f:
                f.write(content)
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def delete_file(self, path: str) -> dict:
        """Delete a file."""
        try:
            rp = _check_write_safe(path)
        except ValueError as e:
            logger.warning("Blocked delete: %s", e)
            return {"success": False, "error": str(e)}
        try:
            os.remove(rp)
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def list_directory(self, path: str) -> dict:
        """List directory contents."""
        try:
            entries = []
            for entry in os.scandir(path):
                stat = entry.stat(follow_symlinks=False)
                entries.append({
                    "name": entry.name,
                    "is_dir": entry.is_dir(),
                    "is_file": entry.is_file(),
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
            logger.warning("Blocked create_directory: %s", e)
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
            logger.warning("Blocked delete_directory: %s", e)
            return {"success": False, "error": str(e)}
        try:
            shutil.rmtree(rp)
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def copy(self, src: str, dst: str) -> dict:
        """Copy a file or directory."""
        try:
            rp_dst = _check_write_safe(dst)
        except ValueError as e:
            logger.warning("Blocked copy destination: %s", e)
            return {"success": False, "error": str(e)}
        try:
            rp_src = os.path.realpath(src)
            if os.path.isdir(rp_src):
                shutil.copytree(rp_src, rp_dst)
            else:
                shutil.copy2(rp_src, rp_dst)
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def move(self, src: str, dst: str) -> dict:
        """Move/rename a file or directory."""
        try:
            rp_dst = _check_write_safe(dst)
        except ValueError as e:
            logger.warning("Blocked move destination: %s", e)
            return {"success": False, "error": str(e)}
        try:
            rp_src = os.path.realpath(src)
            shutil.move(rp_src, rp_dst)
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def file_info(self, path: str) -> dict:
        """Get detailed file information."""
        try:
            stat = os.stat(path)
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
                "is_dir": os.path.isdir(path),
                "is_file": os.path.isfile(path),
                "is_symlink": os.path.islink(path),
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
            logger.warning("Blocked chmod: %s", e)
            return {"success": False, "error": str(e)}
        try:
            os.chmod(rp, mode)
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def chown(self, path: str, uid: int, gid: int) -> dict:
        """Change file ownership."""
        try:
            rp = _check_write_safe(path)
        except ValueError as e:
            logger.warning("Blocked chown: %s", e)
            return {"success": False, "error": str(e)}
        try:
            os.chown(rp, uid, gid)
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}
