"""
GPU enumeration and PRIME routing for the AI Control daemon.

This module exposes:
  - GPUController: enumerates DRM devices (/sys/class/drm/card*), identifies
    vendor, boot_vga flag, and render node; caches for 60 s since PCI config
    does not change at runtime.
  - A FastAPI router (build_router) registering:
        GET /gpu/list           [{index, name, vendor, render_node, boot_vga, tier}]
        GET /gpu/select?mode=X  {env: {...}, mode: ...}   -- runs gpu-select.sh
        GET /gpu/primary        {card, vendor, render_node}
        GET /gpu/render         {card, vendor, render_node, tier}
        POST /gpu/prime         {env}  -- explicit PRIME offload env vars

Designed to degrade gracefully on Windows + non-Linux hosts: enumeration
returns an empty list rather than crashing import.  Linux-only syscalls are
gated with sys.platform checks.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("ai-control.gpu")


# Vendor ID -> human-readable name
_VENDOR_NAMES: Dict[str, str] = {
    "10de": "nvidia",
    "1002": "amd",
    "8086": "intel",
    "1af4": "virtio",   # QEMU virtio-gpu
    "1234": "qemu",     # Bochs / QEMU std-vga
    "15ad": "vmware",
    "80ee": "virtualbox",
}

# Device IDs that we classify as "legacy" (no Vulkan 1.0+ capability).
# Used by /gpu/list to flag an entry so the AI daemon knows it's CPU-only.
_LEGACY_NVIDIA_PREFIXES: Tuple[str, ...] = (
    "0a", "0b", "0c", "0d",  # GT218 family + siblings (Tesla/Fermi-1 gen)
)
_LEGACY_INTEL_IDS: Tuple[str, ...] = (
    # Sandy Bridge HD 2000/3000 -- no Vulkan support
    "0102", "0106", "010a", "010b", "0112", "0116", "0122", "0126",
)


def _read_sysfs_attr(path: Path) -> str:
    """Best-effort read of a sysfs attribute; returns '' on any error."""
    try:
        with path.open("r") as f:
            return f.read().strip()
    except (OSError, IOError):
        return ""


def _classify_tier(vendor: str, device_id: str) -> str:
    """Return 'legacy' | 'modern' | 'software' | 'unknown'."""
    if vendor == "10de":
        # Strip leading zeros and prefix-match first two nybbles
        d = device_id.lstrip("0").lower()
        d = d.zfill(4)
        prefix = d[:2]
        if prefix in _LEGACY_NVIDIA_PREFIXES:
            return "legacy"
        return "modern"
    if vendor == "8086":
        d = device_id.lstrip("0").lower().zfill(4)
        if d in _LEGACY_INTEL_IDS:
            return "legacy"
        return "modern"
    if vendor == "1002":
        return "modern"  # All AMD with open amdgpu is modern-enough
    if vendor in ("1af4", "1234", "15ad", "80ee"):
        return "software"  # Virt GPUs route through llvmpipe
    if vendor == "":
        return "unknown"
    return "unknown"


class GPUController:
    """Enumerates DRM GPUs and provides PRIME routing helpers."""

    # Cache TTL: PCI config doesn't change at runtime, but hotplug (USB-C dock
    # dGPUs, Thunderbolt eGPUs) does.  60 s is a good middle ground.
    _CACHE_TTL_SEC: float = 60.0

    def __init__(self, select_script: str = "/usr/lib/ai-arch/gpu-select.sh") -> None:
        self.select_script = select_script
        self._cache: Optional[List[Dict[str, Any]]] = None
        self._cache_mtime: float = 0.0

    # ------------------------------------------------------------------
    # Enumeration
    # ------------------------------------------------------------------
    def enumerate(self, force_refresh: bool = False) -> List[Dict[str, Any]]:
        """Return a list of GPU dicts.

        Each entry:
            index        (int)   -- enumeration order (0-based)
            card         (str)   -- e.g., "card0"
            path         (str)   -- "/dev/dri/card0"
            vendor_id    (str)   -- "10de" (4-char lowercase hex)
            vendor       (str)   -- "nvidia" | "amd" | "intel" | ...
            device_id    (str)   -- 4-char lowercase hex
            boot_vga     (bool)  -- True if firmware used this for POST
            render_node  (str)   -- "/dev/dri/renderD128" or ""
            tier         (str)   -- "modern" | "legacy" | "software" | "unknown"
            pci_addr     (str)   -- full PCI BDF (best-effort)
        """
        now = time.time()
        if (
            not force_refresh
            and self._cache is not None
            and (now - self._cache_mtime) < self._CACHE_TTL_SEC
        ):
            return self._cache

        devices: List[Dict[str, Any]] = []

        # Linux-only path -- on non-Linux return an empty list, NOT an error.
        if not sys.platform.startswith("linux"):
            self._cache = devices
            self._cache_mtime = now
            return devices

        drm_root = Path("/sys/class/drm")
        if not drm_root.is_dir():
            # System has no DRM subsystem at all (headless server without GPU).
            self._cache = devices
            self._cache_mtime = now
            return devices

        # Deterministic enumeration: sort so card0 < card1 < card10
        def _key(p: Path) -> Tuple[int, str]:
            name = p.name  # "card0", "card1", ...
            try:
                return (int(name.replace("card", "")), name)
            except ValueError:
                return (999, name)

        candidates = sorted(
            (p for p in drm_root.glob("card[0-9]*") if (p / "device").is_dir()),
            key=_key,
        )

        for idx, card_path in enumerate(candidates):
            name = card_path.name
            dev_dir = card_path / "device"

            vendor_id = _read_sysfs_attr(dev_dir / "vendor").lower()
            # Strip 0x prefix, keep 4 hex digits
            if vendor_id.startswith("0x"):
                vendor_id = vendor_id[2:]
            vendor_id = vendor_id.zfill(4)

            device_id = _read_sysfs_attr(dev_dir / "device").lower()
            if device_id.startswith("0x"):
                device_id = device_id[2:]
            device_id = device_id.zfill(4)

            boot_vga_raw = _read_sysfs_attr(dev_dir / "boot_vga")
            boot_vga = boot_vga_raw == "1"

            # render node: /sys/class/drm/cardN/device/drm/renderD*
            render_node = ""
            drm_sub = dev_dir / "drm"
            if drm_sub.is_dir():
                for rd in drm_sub.glob("renderD[0-9]*"):
                    render_node = f"/dev/dri/{rd.name}"
                    break

            # PCI address (resolve the symlink target)
            pci_addr = ""
            try:
                resolved = (dev_dir).resolve(strict=False)
                # Layout: /sys/devices/pci0000:00/0000:00:01.0/0000:01:00.0
                parts = resolved.parts
                for part in reversed(parts):
                    if ":" in part and "." in part:
                        pci_addr = part
                        break
            except (OSError, RuntimeError):
                pass

            entry = {
                "index": idx,
                "card": name,
                "path": f"/dev/dri/{name}",
                "vendor_id": vendor_id,
                "vendor": _VENDOR_NAMES.get(vendor_id, "unknown"),
                "device_id": device_id,
                "boot_vga": boot_vga,
                "render_node": render_node,
                "tier": _classify_tier(vendor_id, device_id),
                "pci_addr": pci_addr,
            }
            devices.append(entry)

        self._cache = devices
        self._cache_mtime = now
        return devices

    # ------------------------------------------------------------------
    # Selection helpers
    # ------------------------------------------------------------------
    def primary(self) -> Optional[Dict[str, Any]]:
        """Return the boot_vga GPU, or first GPU if none flagged, or None."""
        devs = self.enumerate()
        for d in devs:
            if d["boot_vga"]:
                return d
        return devs[0] if devs else None

    def render(self) -> Optional[Dict[str, Any]]:
        """Return the best render-target GPU (prefer non-boot_vga dGPU)."""
        devs = self.enumerate()
        if not devs:
            return None
        if len(devs) == 1:
            return devs[0]
        for d in devs:
            if not d["boot_vga"]:
                return d
        # All flagged boot_vga (shouldn't happen); return first one.
        return devs[0]

    def has_hybrid(self) -> bool:
        """True when we have a distinct display GPU + render GPU (PRIME)."""
        p = self.primary()
        r = self.render()
        if p is None or r is None:
            return False
        return p["card"] != r["card"]

    # ------------------------------------------------------------------
    # gpu-select.sh wrapper
    # ------------------------------------------------------------------
    def select_env(self, mode: str = "render", timeout: float = 5.0) -> Dict[str, str]:
        """Run gpu-select.sh <mode> and parse its `export X=Y` output.

        Returns {VAR: VAL} dict.  On any failure returns {} so callers degrade
        to "do nothing" rather than crashing.
        """
        allowed = {"render", "display", "compute", "list", "software"}
        if mode not in allowed:
            raise ValueError(f"mode must be one of {sorted(allowed)}")

        # If the script is missing we build an in-process fallback that mirrors
        # the minimal PRIME logic, so the daemon still works on dev machines
        # without the script deployed.
        if not Path(self.select_script).is_file():
            return self._fallback_env(mode)

        try:
            proc = subprocess.run(
                [self.select_script, mode],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError) as e:
            logger.warning("gpu-select.sh failed: %s (falling back to in-proc)", e)
            return self._fallback_env(mode)

        env: Dict[str, str] = {}
        for line in (proc.stdout or "").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                rest = line[len("export "):]
                if "=" in rest:
                    k, v = rest.split("=", 1)
                    # Strip surrounding quotes if any
                    if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
                        v = v[1:-1]
                    env[k.strip()] = v.strip()
        return env

    def _fallback_env(self, mode: str) -> Dict[str, str]:
        """In-process PRIME env builder for systems without gpu-select.sh."""
        env: Dict[str, str] = {}
        devs = self.enumerate()
        if not devs or mode == "software":
            env["LIBGL_ALWAYS_SOFTWARE"] = "1"
            env["GALLIUM_DRIVER"] = "llvmpipe"
            env["GPU_TIER"] = "software"
            return env

        primary = self.primary()
        render = self.render()
        if primary is None or render is None:
            env["GPU_TIER"] = "unknown"
            return env

        if mode == "display":
            env["AI_DISPLAY_CARD"] = primary["path"]
            env["AI_DISPLAY_VENDOR"] = primary["vendor_id"]
            return env
        if mode == "compute":
            env["AI_COMPUTE_NODE"] = render["render_node"] or render["path"]
            env["AI_COMPUTE_VENDOR"] = render["vendor_id"]
            return env

        # render (default)
        env["AI_PRIMARY_CARD"] = primary["path"]
        env["AI_RENDER_CARD"] = render["path"]
        if render["render_node"]:
            env["AI_RENDER_NODE"] = render["render_node"]
        env["LIBGL_DRI3_DISABLE"] = "0"
        env["MESA_GLTHREAD"] = "true"
        if primary["card"] != render["card"]:
            env["DRI_PRIME"] = "1"
            if render["vendor_id"] == "10de":
                env["__NV_PRIME_RENDER_OFFLOAD"] = "1"
                env["__VK_LAYER_NV_optimus"] = "NVIDIA_only"
                env["__GLX_VENDOR_LIBRARY_NAME"] = "nvidia"
        env["GPU_TIER"] = render["tier"]
        return env

    # ------------------------------------------------------------------
    # Vulkan probe (best-effort)
    # ------------------------------------------------------------------
    def vulkan_info(self, timeout: float = 3.0) -> Dict[str, Any]:
        """Return {'available': bool, 'api': str, 'device': str} from vulkaninfo.

        Returns {'available': False, ...} if vulkan-tools is not installed or
        the probe times out -- never raises.
        """
        result: Dict[str, Any] = {"available": False, "api": "", "device": ""}
        vi = shutil.which("vulkaninfo")
        if not vi:
            return result
        try:
            proc = subprocess.run(
                [vi, "--summary"],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except (subprocess.TimeoutExpired, OSError):
            return result
        if proc.returncode != 0 or not proc.stdout:
            return result
        for line in proc.stdout.splitlines():
            if "apiVersion" in line and "=" in line and not result["api"]:
                result["api"] = line.split("=", 1)[1].strip()
            elif "deviceName" in line and "=" in line and not result["device"]:
                result["device"] = line.split("=", 1)[1].strip()
        result["available"] = bool(result["api"])
        return result


# ----------------------------------------------------------------------
# FastAPI router
# ----------------------------------------------------------------------
def build_router(controller: Optional[GPUController] = None):
    """Return a FastAPI APIRouter with /gpu/* endpoints.

    Importing fastapi inside this function keeps the module import cheap on
    systems without FastAPI installed (e.g., unit-test environments).
    """
    try:
        from fastapi import APIRouter, HTTPException, Query
    except ImportError:
        logger.error("FastAPI missing; /gpu/* endpoints unavailable")
        return None

    ctrl = controller or GPUController()

    router = APIRouter(prefix="/gpu", tags=["gpu"])

    @router.get("/list")
    async def list_gpus(refresh: bool = Query(False)):
        try:
            devs = ctrl.enumerate(force_refresh=refresh)
        except Exception:
            # Don't echo the raw exception to the caller; it can include
            # DRM device paths, PCI addresses, and sysfs leaf names that
            # leak internals. Full trace goes to the daemon log.
            logger.exception("GPU enumerate failed")
            raise HTTPException(status_code=500, detail="enumerate failed")
        return {"count": len(devs), "gpus": devs}

    @router.get("/primary")
    async def primary_gpu():
        dev = ctrl.primary()
        if dev is None:
            raise HTTPException(status_code=404, detail="no GPU found")
        return dev

    @router.get("/render")
    async def render_gpu():
        dev = ctrl.render()
        if dev is None:
            raise HTTPException(status_code=404, detail="no GPU found")
        return dev

    @router.get("/hybrid")
    async def hybrid_info():
        return {"hybrid": ctrl.has_hybrid()}

    @router.get("/select")
    async def select(mode: str = Query("render")):
        try:
            env = ctrl.select_env(mode)
        except ValueError as e:
            # ValueError here comes from known validation paths ("unknown
            # mode") — safe to echo.
            raise HTTPException(status_code=400, detail=str(e))
        except Exception:
            logger.exception("gpu-select failed")
            raise HTTPException(status_code=500, detail="gpu-select failed")
        return {"mode": mode, "env": env}

    @router.get("/vulkan")
    async def vulkan():
        return ctrl.vulkan_info()

    return router


__all__ = ["GPUController", "build_router"]
