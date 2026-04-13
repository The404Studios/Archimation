#!/usr/bin/env python3
"""
Filesystem Safety - Unit tests.

Tests the read/write path blocking logic and FilesystemController
operations without touching real protected system files.

Note: The safety-check functions use os.path.realpath(), which on
Windows resolves /etc/shadow to C:\\etc\\shadow. We monkey-patch
realpath in the filesystem module so blocklist tests behave the same
as they do on the target Linux system.
"""

import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

# Add daemon to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "ai-control" / "daemon"))

import filesystem
from filesystem import FilesystemController

# Monkey-patch os.path.realpath inside the filesystem module so that
# Linux-style absolute paths are returned unchanged (identity), just
# like on a real Linux box.  This only affects the module under test.
_orig_realpath = os.path.realpath


def _linux_realpath(p, *a, **kw):
    """On non-Linux: return POSIX paths unchanged; delegate others."""
    if isinstance(p, str) and p.startswith("/"):
        return p  # keep as-is, mimicking Linux
    return _orig_realpath(p, *a, **kw)


filesystem.os.path.realpath = _linux_realpath

# Re-import the helper functions so they use the patched realpath
from filesystem import _check_write_safe, _check_read_safe

passed = 0
failed = 0


def test(name, condition):
    global passed, failed
    print(f"  {name:55s}", end=" ")
    if condition:
        print("\033[32mPASS\033[0m")
        passed += 1
    else:
        print("\033[31mFAIL\033[0m")
        failed += 1


# ------------------------------------------------------------------
# _check_read_safe
# ------------------------------------------------------------------

def test_block_shadow_read():
    result = _check_read_safe("/etc/shadow")
    test("block /etc/shadow read", result is not None)


def test_block_gshadow_read():
    result = _check_read_safe("/etc/gshadow")
    test("block /etc/gshadow read", result is not None)


def test_block_root_ssh_key_read():
    result = _check_read_safe("/root/.ssh/id_rsa")
    test("block /root/.ssh/id_rsa read", result is not None)


def test_block_root_authorized_keys_read():
    result = _check_read_safe("/root/.ssh/authorized_keys")
    test("block /root/.ssh/authorized_keys read", result is not None)


def test_block_auth_secret_read():
    result = _check_read_safe("/var/lib/ai-control/auth_secret")
    test("block auth_secret read", result is not None)


def test_allow_home_read():
    result = _check_read_safe("/home/arch/test.txt")
    test("allow /home/arch/test.txt read", result is None)


def test_allow_tmp_read():
    result = _check_read_safe("/tmp/some_file.log")
    test("allow /tmp/some_file.log read", result is None)


def test_allow_etc_hostname_read():
    result = _check_read_safe("/etc/hostname")
    test("allow /etc/hostname read", result is None)


def test_allow_var_log_read():
    result = _check_read_safe("/var/log/syslog")
    test("allow /var/log/syslog read", result is None)


# ------------------------------------------------------------------
# _check_write_safe
# ------------------------------------------------------------------

def test_block_passwd_write():
    result = _check_write_safe("/etc/passwd")
    test("block /etc/passwd write", result is not None)


def test_block_shadow_write():
    result = _check_write_safe("/etc/shadow")
    test("block /etc/shadow write", result is not None)


def test_block_sudoers_write():
    result = _check_write_safe("/etc/sudoers")
    test("block /etc/sudoers write", result is not None)


def test_block_sshd_config_write():
    result = _check_write_safe("/etc/ssh/sshd_config")
    test("block /etc/ssh/sshd_config write", result is not None)


def test_block_boot_write():
    result = _check_write_safe("/boot/vmlinuz")
    test("block /boot/vmlinuz write", result is not None)


def test_block_boot_subdir_write():
    result = _check_write_safe("/boot/grub/grub.cfg")
    test("block /boot/grub/grub.cfg write", result is not None)


def test_block_systemd_write():
    result = _check_write_safe("/usr/lib/systemd/system/foo.service")
    test("block /usr/lib/systemd/ write", result is not None)


def test_block_usr_bin_write():
    result = _check_write_safe("/usr/bin/ls")
    test("block /usr/bin/ls write", result is not None)


def test_block_root_ssh_write():
    result = _check_write_safe("/root/.ssh/authorized_keys")
    test("block /root/.ssh/ write", result is not None)


def test_allow_home_write():
    result = _check_write_safe("/home/arch/notes.txt")
    test("allow /home/arch/notes.txt write", result is None)


def test_allow_tmp_write():
    result = _check_write_safe("/tmp/output.txt")
    test("allow /tmp/output.txt write", result is None)


def test_allow_var_lib_write():
    result = _check_write_safe("/var/lib/ai-control/state.db")
    test("allow /var/lib/ai-control/state.db write", result is None)


def test_allow_opt_write():
    result = _check_write_safe("/opt/myapp/config.json")
    test("allow /opt/myapp/config.json write", result is None)


# ------------------------------------------------------------------
# _check_write_safe returns error message content
# ------------------------------------------------------------------

def test_error_message_contains_path():
    result = _check_write_safe("/etc/passwd")
    test("error mentions protected file", "protected" in result.lower())


def test_error_message_mentions_write():
    result = _check_write_safe("/boot/vmlinuz")
    test("error mentions write operation", "write" in result.lower() or "blocked" in result.lower())


# ------------------------------------------------------------------
# FilesystemController - read_file
# ------------------------------------------------------------------

def test_controller_read_blocked():
    fc = FilesystemController()
    result = fc.read_file("/etc/shadow")
    test("controller blocks shadow read", result["success"] is False)
    test("controller read error has message", "error" in result)


def test_controller_read_nonexistent():
    fc = FilesystemController()
    result = fc.read_file("/tmp/__nonexistent_test_file_12345__")
    test("controller read nonexistent fails", result["success"] is False)


def test_controller_read_real_file():
    fc = FilesystemController()
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("test content abc")
        tmp_path = f.name
    try:
        result = fc.read_file(tmp_path)
        test("controller reads temp file ok", result["success"] is True)
        test("controller read content matches", result.get("content") == "test content abc")
    finally:
        os.unlink(tmp_path)


# ------------------------------------------------------------------
# FilesystemController - write_file
# ------------------------------------------------------------------

def test_controller_write_blocked():
    fc = FilesystemController()
    result = fc.write_file("/etc/passwd", "hacked")
    test("controller blocks passwd write", result["success"] is False)


def test_controller_write_real_file():
    fc = FilesystemController()
    tmp_path = os.path.join(tempfile.gettempdir(), "__ai_test_write__.txt")
    try:
        result = fc.write_file(tmp_path, "hello from test")
        test("controller writes temp file ok", result["success"] is True)
        with open(tmp_path) as f:
            content = f.read()
        test("written content matches", content == "hello from test")
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


# ------------------------------------------------------------------
# FilesystemController - append_file
# ------------------------------------------------------------------

def test_controller_append_blocked():
    fc = FilesystemController()
    result = fc.append_file("/etc/shadow", "bad data")
    test("controller blocks shadow append", result["success"] is False)


def test_controller_append_real_file():
    fc = FilesystemController()
    tmp_path = os.path.join(tempfile.gettempdir(), "__ai_test_append__.txt")
    try:
        fc.write_file(tmp_path, "line1\n")
        result = fc.append_file(tmp_path, "line2\n")
        test("controller appends ok", result["success"] is True)
        with open(tmp_path) as f:
            content = f.read()
        test("appended content correct", content == "line1\nline2\n")
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


# ------------------------------------------------------------------
# FilesystemController - delete_file
# ------------------------------------------------------------------

def test_controller_delete_blocked():
    fc = FilesystemController()
    result = fc.delete_file("/etc/passwd")
    test("controller blocks passwd delete", result["success"] is False)


def test_controller_delete_real_file():
    fc = FilesystemController()
    with tempfile.NamedTemporaryFile(delete=False) as f:
        tmp_path = f.name
    result = fc.delete_file(tmp_path)
    test("controller deletes temp file ok", result["success"] is True)
    test("file actually removed", not os.path.exists(tmp_path))


# ------------------------------------------------------------------
# FilesystemController - list_directory
# ------------------------------------------------------------------

def test_controller_list_directory():
    fc = FilesystemController()
    tmp_dir = tempfile.mkdtemp()
    try:
        # Create a couple of files in the temp dir
        Path(os.path.join(tmp_dir, "a.txt")).touch()
        Path(os.path.join(tmp_dir, "b.txt")).touch()
        os.mkdir(os.path.join(tmp_dir, "subdir"))
        result = fc.list_directory(tmp_dir)
        test("list_directory succeeds", result["success"] is True)
        names = [e["name"] for e in result["entries"]]
        test("list_directory finds a.txt", "a.txt" in names)
        test("list_directory finds b.txt", "b.txt" in names)
        test("list_directory finds subdir", "subdir" in names)
        subdir_entry = [e for e in result["entries"] if e["name"] == "subdir"][0]
        test("subdir marked as directory", subdir_entry["is_dir"] is True)
    finally:
        import shutil
        shutil.rmtree(tmp_dir)


def test_controller_list_nonexistent():
    fc = FilesystemController()
    result = fc.list_directory("/tmp/__nonexistent_dir_99999__")
    test("list nonexistent dir fails", result["success"] is False)


# ------------------------------------------------------------------
# FilesystemController - create_directory
# ------------------------------------------------------------------

def test_controller_create_directory():
    fc = FilesystemController()
    tmp_dir = os.path.join(tempfile.gettempdir(), "__ai_test_mkdir__", "nested", "dir")
    try:
        result = fc.create_directory(tmp_dir)
        test("create_directory succeeds", result["success"] is True)
        test("directory actually exists", os.path.isdir(tmp_dir))
    finally:
        import shutil
        base = os.path.join(tempfile.gettempdir(), "__ai_test_mkdir__")
        if os.path.exists(base):
            shutil.rmtree(base)


# ------------------------------------------------------------------
# FilesystemController - file_info
# ------------------------------------------------------------------

def test_controller_file_info():
    fc = FilesystemController()
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("info test")
        tmp_path = f.name
    try:
        result = fc.file_info(tmp_path)
        test("file_info succeeds", result["success"] is True)
        test("file_info shows exists", result["exists"] is True)
        test("file_info shows is_file", result["is_file"] is True)
        test("file_info shows not is_dir", result["is_dir"] is False)
        test("file_info has size", result["size"] == 9)
    finally:
        os.unlink(tmp_path)


def test_controller_file_info_nonexistent():
    fc = FilesystemController()
    result = fc.file_info("/tmp/__no_such_file_at_all_98765__")
    test("file_info nonexistent shows exists=False", result.get("exists") is False)


# ------------------------------------------------------------------
# FilesystemController - copy
# ------------------------------------------------------------------

def test_controller_copy_blocked():
    fc = FilesystemController()
    result = fc.copy("/tmp/anything", "/etc/passwd")
    test("copy to /etc/passwd blocked", result["success"] is False)


def test_controller_copy_real_file():
    fc = FilesystemController()
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("copy me")
        src = f.name
    dst = src + ".copy"
    try:
        result = fc.copy(src, dst)
        test("copy file succeeds", result["success"] is True)
        with open(dst) as f:
            test("copied content matches", f.read() == "copy me")
    finally:
        for p in (src, dst):
            if os.path.exists(p):
                os.unlink(p)


# ------------------------------------------------------------------
# FilesystemController - move
# ------------------------------------------------------------------

def test_controller_move_blocked():
    fc = FilesystemController()
    result = fc.move("/tmp/anything", "/boot/vmlinuz")
    test("move to /boot/vmlinuz blocked", result["success"] is False)


# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------

def main():
    print("=== Filesystem Safety Unit Tests ===\n")

    print("-- Read Safety Checks --")
    test_block_shadow_read()
    test_block_gshadow_read()
    test_block_root_ssh_key_read()
    test_block_root_authorized_keys_read()
    test_block_auth_secret_read()
    test_allow_home_read()
    test_allow_tmp_read()
    test_allow_etc_hostname_read()
    test_allow_var_log_read()

    print("\n-- Write Safety Checks --")
    test_block_passwd_write()
    test_block_shadow_write()
    test_block_sudoers_write()
    test_block_sshd_config_write()
    test_block_boot_write()
    test_block_boot_subdir_write()
    test_block_systemd_write()
    test_block_usr_bin_write()
    test_block_root_ssh_write()
    test_allow_home_write()
    test_allow_tmp_write()
    test_allow_var_lib_write()
    test_allow_opt_write()

    print("\n-- Error Messages --")
    test_error_message_contains_path()
    test_error_message_mentions_write()

    print("\n-- Controller: Read --")
    test_controller_read_blocked()
    test_controller_read_nonexistent()
    test_controller_read_real_file()

    print("\n-- Controller: Write --")
    test_controller_write_blocked()
    test_controller_write_real_file()

    print("\n-- Controller: Append --")
    test_controller_append_blocked()
    test_controller_append_real_file()

    print("\n-- Controller: Delete --")
    test_controller_delete_blocked()
    test_controller_delete_real_file()

    print("\n-- Controller: List Directory --")
    test_controller_list_directory()
    test_controller_list_nonexistent()

    print("\n-- Controller: Create Directory --")
    test_controller_create_directory()

    print("\n-- Controller: File Info --")
    test_controller_file_info()
    test_controller_file_info_nonexistent()

    print("\n-- Controller: Copy --")
    test_controller_copy_blocked()
    test_controller_copy_real_file()

    print("\n-- Controller: Move --")
    test_controller_move_blocked()

    print(f"\n=== Results: {passed} passed, {failed} failed ===")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
