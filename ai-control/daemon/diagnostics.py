"""
AI Arch Linux - System Diagnostics Module

Provides comprehensive system health checks for the AI daemon API
and the pe-status CLI tool. Checks all 5 layers of the architecture.
"""

import asyncio
import json
import logging
import os
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Any

logger = logging.getLogger("ai-control.diagnostics")

# Subsystem check results
STATUS_OK = "ok"
STATUS_WARN = "warning"
STATUS_FAIL = "error"
STATUS_SKIP = "skipped"


def _check(name: str, status: str, detail: str = "", **extra) -> dict:
    result = {"name": name, "status": status, "detail": detail}
    result.update(extra)
    return result


async def _run_cmd(cmd: list[str], timeout: float = 5.0) -> tuple[int, str]:
    """Run a command with timeout, return (returncode, stdout)."""
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
        return proc.returncode, stdout.decode(errors="replace").strip()
    except FileNotFoundError:
        return -1, f"Command not found: {cmd[0]}"
    except asyncio.TimeoutError:
        if proc is not None:
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass
        return -2, "Command timed out"
    except Exception as e:
        if proc is not None:
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass
        return -3, str(e)


async def check_layer0_kernel() -> list[dict]:
    """Layer 0: Kernel checks (trust.ko, binfmt_pe)."""
    results = []

    # Check trust.ko module via /proc/modules (avoids spawning lsmod)
    trust_loaded = False
    try:
        with open("/proc/modules", "r") as f:
            for line in f:
                # Each line: <name> <size> <used> <by> <state> <offset>
                name = line.split(" ", 1)[0] if line else ""
                if name == "trust" or name.startswith("trust"):
                    trust_loaded = True
                    break
    except (FileNotFoundError, PermissionError):
        pass
    if trust_loaded:
        results.append(_check("trust.ko", STATUS_OK, "Trust kernel module loaded"))
    else:
        results.append(_check("trust.ko", STATUS_WARN,
                              "Trust kernel module not loaded (expected on first boot)"))

    # Check /dev/trust device
    if os.path.exists("/dev/trust"):
        results.append(_check("/dev/trust", STATUS_OK, "Trust device node exists"))
    else:
        results.append(_check("/dev/trust", STATUS_WARN, "Trust device not found"))

    # Check binfmt_misc for PE
    binfmt_pe = Path("/proc/sys/fs/binfmt_misc/PE")
    if binfmt_pe.exists():
        try:
            content = binfmt_pe.read_text()
            if "enabled" in content:
                results.append(_check("binfmt_pe", STATUS_OK,
                                      "PE binary format handler active"))
            else:
                results.append(_check("binfmt_pe", STATUS_WARN,
                                      "PE handler registered but disabled"))
        except Exception:
            results.append(_check("binfmt_pe", STATUS_WARN,
                                  "Cannot read binfmt status"))
    else:
        results.append(_check("binfmt_pe", STATUS_WARN,
                              "PE binary format not registered"))

    # Check kernel version via os.uname() (avoids subprocess)
    try:
        release = os.uname().release
        results.append(_check("kernel", STATUS_OK, f"Linux {release}"))
    except (AttributeError, OSError):
        pass

    return results


async def check_layer1_broker() -> list[dict]:
    """Layer 1: Object Broker (pe-objectd)."""
    results = []

    # Check if pe-objectd is running
    rc, out = await _run_cmd(["systemctl", "is-active", "pe-objectd.service"])
    if rc == 0 and "active" in out:
        results.append(_check("pe-objectd", STATUS_OK, "Object broker running"))
    else:
        results.append(_check("pe-objectd", STATUS_WARN,
                              "Object broker not running"))

    # Check broker socket
    sock_path = "/run/pe-compat/objectd.sock"
    if os.path.exists(sock_path):
        results.append(_check("objectd.sock", STATUS_OK, "Broker socket exists"))
    else:
        results.append(_check("objectd.sock", STATUS_WARN, "Broker socket missing"))

    # Check registry directory
    reg_dir = Path("/var/lib/pe-compat/registry")
    if reg_dir.exists():
        results.append(_check("registry", STATUS_OK,
                              f"Registry hive at {reg_dir}"))
    else:
        results.append(_check("registry", STATUS_WARN, "Registry directory missing"))

    return results


async def check_layer2_pe_runtime() -> list[dict]:
    """Layer 2: PE Runtime (peloader, DLL stubs)."""
    results = []

    # Check peloader binary
    peloader = shutil.which("peloader") or "/usr/bin/peloader"
    if os.path.isfile(peloader) and os.access(peloader, os.X_OK):
        results.append(_check("peloader", STATUS_OK, f"Binary at {peloader}"))
    else:
        results.append(_check("peloader", STATUS_FAIL, "peloader binary not found"))

    # Check DLL stubs
    dll_dirs = [
        Path("/usr/lib/pe-compat"),
        Path.home() / ".pe-compat" / "dlls",
    ]
    dll_count = 0
    for d in dll_dirs:
        if d.exists():
            dll_count += len(list(d.glob("libpe_*.so")))

    if dll_count > 30:
        results.append(_check("dll_stubs", STATUS_OK,
                              f"{dll_count} DLL stubs installed"))
    elif dll_count > 0:
        results.append(_check("dll_stubs", STATUS_WARN,
                              f"Only {dll_count} DLL stubs (expected 37+)"))
    else:
        results.append(_check("dll_stubs", STATUS_FAIL, "No DLL stubs found"))

    # Check DXVK
    dxvk_dir = Path("/usr/lib/dxvk")
    if dxvk_dir.exists() and list(dxvk_dir.glob("*.dll")):
        results.append(_check("dxvk", STATUS_OK, "DXVK translation layer present"))
    else:
        results.append(_check("dxvk", STATUS_WARN, "DXVK not installed"))

    # Check VKD3D-Proton
    vkd3d_dir = Path("/usr/lib/vkd3d-proton")
    if vkd3d_dir.exists():
        results.append(_check("vkd3d-proton", STATUS_OK,
                              "VKD3D-Proton (D3D12) present"))
    else:
        results.append(_check("vkd3d-proton", STATUS_WARN,
                              "VKD3D-Proton not installed"))

    # Check Vulkan
    rc, out = await _run_cmd(["vulkaninfo", "--summary"], timeout=10)
    if rc == 0:
        results.append(_check("vulkan", STATUS_OK, "Vulkan driver available"))
    else:
        results.append(_check("vulkan", STATUS_WARN, "Vulkan not available"))

    return results


async def check_layer3_services() -> list[dict]:
    """Layer 3: Service Fabric (scm-daemon, anti-cheat)."""
    results = []

    # Check SCM daemon
    rc, out = await _run_cmd(["systemctl", "is-active", "scm-daemon.service"])
    if rc == 0 and "active" in out:
        results.append(_check("scm-daemon", STATUS_OK,
                              "Service Control Manager running"))
    else:
        results.append(_check("scm-daemon", STATUS_WARN,
                              "SCM daemon not running"))

    # Check SCM socket
    scm_sock = "/run/pe-compat/scm.sock"
    if os.path.exists(scm_sock):
        results.append(_check("scm.sock", STATUS_OK, "SCM socket active"))
    else:
        results.append(_check("scm.sock", STATUS_WARN, "SCM socket missing"))

    # Check anti-cheat library
    ac_lib = Path("/usr/lib/pe-compat/libpe_anticheat.so")
    if ac_lib.exists():
        results.append(_check("anticheat", STATUS_OK, "Anti-cheat shims available"))
    else:
        results.append(_check("anticheat", STATUS_WARN, "Anti-cheat library missing"))

    return results


async def check_layer4_cortex() -> list[dict]:
    """Layer 4: AI Cortex (daemon, cortex, event bus)."""
    results = []

    # Check AI daemon
    rc, out = await _run_cmd(["systemctl", "is-active", "ai-control.service"])
    if rc == 0 and "active" in out:
        results.append(_check("ai-daemon", STATUS_OK, "AI control daemon running"))
    else:
        results.append(_check("ai-daemon", STATUS_WARN, "AI daemon not running"))

    # Check daemon health endpoint
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect(("127.0.0.1", 8420))
            results.append(_check("api:8420", STATUS_OK, "API port responsive"))
    except Exception:
        results.append(_check("api:8420", STATUS_WARN, "API port 8420 not listening"))

    # Check cortex
    rc, out = await _run_cmd(["systemctl", "is-active", "ai-cortex.service"])
    if rc == 0 and "active" in out:
        results.append(_check("ai-cortex", STATUS_OK, "Cortex engine running"))
    else:
        results.append(_check("ai-cortex", STATUS_WARN, "Cortex not running"))

    # Check event bus socket
    evt_sock = "/run/pe-compat/events.sock"
    if os.path.exists(evt_sock):
        results.append(_check("event_bus", STATUS_OK, "Event bus socket active"))
    else:
        results.append(_check("event_bus", STATUS_WARN, "Event bus socket missing"))

    # Check firewall
    rc, out = await _run_cmd(["systemctl", "is-active", "pe-compat-firewall.service"])
    if rc == 0 and "active" in out:
        results.append(_check("firewall", STATUS_OK, "Firewall active"))
    else:
        results.append(_check("firewall", STATUS_WARN, "Firewall not running"))

    return results


async def check_desktop() -> list[dict]:
    """Desktop environment checks."""
    results = []

    # Check display server
    display = os.environ.get("DISPLAY", "")
    wayland = os.environ.get("WAYLAND_DISPLAY", "")
    if wayland:
        results.append(_check("display", STATUS_OK, f"Wayland ({wayland})"))
    elif display:
        results.append(_check("display", STATUS_OK, f"X11 ({display})"))
    else:
        results.append(_check("display", STATUS_WARN, "No display server detected"))

    # Check GPU via sysfs (PCI class 0x03xxxx = Display controller)
    gpu_found = None
    try:
        pci_root = Path("/sys/bus/pci/devices")
        if pci_root.exists():
            for dev in pci_root.iterdir():
                try:
                    cls = (dev / "class").read_text().strip()
                    # 0x030000 VGA, 0x030200 3D controller, 0x030100 XGA
                    if not cls.startswith("0x03"):
                        continue
                    vendor = (dev / "vendor").read_text().strip()
                    device = (dev / "device").read_text().strip()
                    kind = "VGA" if cls == "0x030000" else ("3D" if cls == "0x030200" else "Display")
                    gpu_found = f"{kind} {vendor[2:]}:{device[2:]}"
                    break
                except (FileNotFoundError, PermissionError, OSError):
                    continue
    except (FileNotFoundError, PermissionError):
        pass
    if gpu_found:
        results.append(_check("gpu", STATUS_OK, gpu_found))
    else:
        results.append(_check("gpu", STATUS_WARN, "No GPU detected"))

    # Check NVIDIA driver
    rc, out = await _run_cmd(["nvidia-smi", "--query-gpu=driver_version",
                              "--format=csv,noheader"])
    if rc == 0:
        results.append(_check("nvidia", STATUS_OK,
                              f"NVIDIA driver {out.strip()}"))
    else:
        results.append(_check("nvidia", STATUS_SKIP,
                              "NVIDIA driver not present (AMD/Intel?)"))

    return results


async def check_system() -> list[dict]:
    """General system health checks."""
    results = []

    # Disk usage
    stat = os.statvfs("/")
    total_gb = (stat.f_blocks * stat.f_frsize) / (1024**3)
    free_gb = (stat.f_bavail * stat.f_frsize) / (1024**3)
    pct_used = round(100 * (1 - free_gb / total_gb), 1) if total_gb > 0 else 0
    status = STATUS_OK if pct_used < 90 else STATUS_WARN
    results.append(_check("disk", status,
                          f"{free_gb:.1f} GB free / {total_gb:.1f} GB total "
                          f"({pct_used}% used)"))

    # Memory
    try:
        with open("/proc/meminfo") as f:
            mem = {}
            for line in f:
                parts = line.split()
                if parts[0] in ("MemTotal:", "MemAvailable:"):
                    mem[parts[0]] = int(parts[1])
        total_mb = mem.get("MemTotal:", 0) / 1024
        avail_mb = mem.get("MemAvailable:", 0) / 1024
        pct_used = round(100 * (1 - avail_mb / total_mb), 1) if total_mb > 0 else 0
        status = STATUS_OK if pct_used < 90 else STATUS_WARN
        results.append(_check("memory", status,
                              f"{avail_mb:.0f} MB free / {total_mb:.0f} MB total "
                              f"({pct_used}% used)"))
    except Exception:
        pass

    # NetworkManager
    rc, out = await _run_cmd(["systemctl", "is-active", "NetworkManager.service"])
    if rc == 0 and "active" in out:
        results.append(_check("network", STATUS_OK, "NetworkManager active"))
    else:
        results.append(_check("network", STATUS_WARN, "NetworkManager not running"))

    # SSH
    rc, out = await _run_cmd(["systemctl", "is-active", "sshd.service"])
    if rc == 0 and "active" in out:
        results.append(_check("ssh", STATUS_OK, "SSH server active"))

    return results


async def run_full_diagnostics() -> dict[str, Any]:
    """Run all diagnostic checks and return structured results."""
    checks = await asyncio.gather(
        check_layer0_kernel(),
        check_layer1_broker(),
        check_layer2_pe_runtime(),
        check_layer3_services(),
        check_layer4_cortex(),
        check_desktop(),
        check_system(),
    )

    layers = [
        "Layer 0: Kernel",
        "Layer 1: Object Broker",
        "Layer 2: PE Runtime",
        "Layer 3: Service Fabric",
        "Layer 4: AI Cortex",
        "Desktop",
        "System",
    ]

    all_results = []
    sections = {}
    for name, results in zip(layers, checks):
        sections[name] = results
        all_results.extend(results)

    ok_count = sum(1 for r in all_results if r["status"] == STATUS_OK)
    warn_count = sum(1 for r in all_results if r["status"] == STATUS_WARN)
    fail_count = sum(1 for r in all_results if r["status"] == STATUS_FAIL)

    overall = STATUS_OK
    if fail_count > 0:
        overall = STATUS_FAIL
    elif warn_count > 3:
        overall = STATUS_WARN

    return {
        "overall": overall,
        "summary": {
            "ok": ok_count,
            "warnings": warn_count,
            "errors": fail_count,
            "total": len(all_results),
        },
        "sections": sections,
    }


def format_diagnostics(report: dict) -> str:
    """Format diagnostic report as colored terminal output."""
    lines = []
    status_icons = {
        STATUS_OK: "\033[32m[OK]\033[0m",
        STATUS_WARN: "\033[33m[!!]\033[0m",
        STATUS_FAIL: "\033[31m[XX]\033[0m",
        STATUS_SKIP: "\033[90m[--]\033[0m",
    }

    lines.append("")
    lines.append("\033[1m  AI Arch Linux - System Diagnostics\033[0m")
    lines.append("  " + "=" * 42)
    lines.append("")

    for section_name, checks in report["sections"].items():
        lines.append(f"  \033[1;36m{section_name}\033[0m")
        for check in checks:
            icon = status_icons.get(check["status"], "[??]")
            lines.append(f"    {icon}  {check['name']:20s}  {check['detail']}")
        lines.append("")

    s = report["summary"]
    overall_icon = status_icons.get(report["overall"], "[??]")
    lines.append(f"  {overall_icon}  Overall: {s['ok']} ok, "
                 f"{s['warnings']} warnings, {s['errors']} errors "
                 f"({s['total']} checks)")
    lines.append("")

    return "\n".join(lines)
