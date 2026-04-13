"""
Screen capture module - capture screen contents for AI vision.

Supports multiple capture methods:
- X11 (via Xlib/scrot)
- Wayland (via wlr-screencopy or pipewire)
- Framebuffer (fallback)
"""

import logging
import subprocess
import base64
import io
import os

logger = logging.getLogger("ai-control.screen")


class ScreenCapture:
    """Captures screen contents for AI visual processing."""

    def __init__(self, method: str = "auto"):
        self.method = method
        if method == "auto":
            self.method = self._detect_method()
        logger.info(f"Screen capture method: {self.method}")

    def _detect_method(self) -> str:
        """Auto-detect the best capture method."""
        if os.environ.get("WAYLAND_DISPLAY"):
            return "wayland"
        if os.environ.get("DISPLAY"):
            return "x11"
        if os.path.exists("/dev/fb0"):
            return "framebuffer"
        return "none"

    def capture_full(self) -> bytes | None:
        """Capture the entire screen as PNG bytes."""
        if self.method == "x11":
            return self._capture_x11()
        elif self.method == "wayland":
            return self._capture_wayland()
        elif self.method == "framebuffer":
            return self._capture_framebuffer()
        else:
            logger.warning("No screen capture method available")
            return None

    def capture_region(self, x: int, y: int, width: int, height: int) -> bytes | None:
        """Capture a region of the screen as PNG bytes."""
        if self.method == "x11":
            return self._capture_x11_region(x, y, width, height)
        else:
            # Capture full and crop
            full = self.capture_full()
            if full:
                return self._crop_png(full, x, y, width, height)
            return None

    def capture_base64(self) -> str | None:
        """Capture screen and return as base64-encoded PNG."""
        data = self.capture_full()
        if data:
            return base64.b64encode(data).decode("ascii")
        return None

    def _capture_x11(self) -> bytes | None:
        """Capture using scrot or import (ImageMagick)."""
        try:
            # Try scrot first (faster) — use mkstemp to avoid symlink attacks
            import tempfile
            fd, capture_path = tempfile.mkstemp(suffix=".png", prefix="ai-screen-")
            os.close(fd)
            try:
                result = subprocess.run(
                    ["scrot", "-o", capture_path],
                    capture_output=True, timeout=5
                )
                if result.returncode == 0:
                    with open(capture_path, "rb") as f:
                        data = f.read()
                    return data
            finally:
                try:
                    os.unlink(capture_path)
                except OSError:
                    pass
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        try:
            # Fallback to xdotool + import
            result = subprocess.run(
                ["import", "-window", "root", "png:-"],
                capture_output=True, timeout=5
            )
            if result.returncode == 0:
                return result.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        logger.error("X11 screen capture failed")
        return None

    def _capture_x11_region(self, x: int, y: int, w: int, h: int) -> bytes | None:
        """Capture a specific region using scrot."""
        import tempfile
        fd, capture_path = tempfile.mkstemp(suffix=".png", prefix="ai-screen-")
        os.close(fd)
        try:
            result = subprocess.run(
                ["scrot", "-a", f"{x},{y},{w},{h}", "-o", capture_path],
                capture_output=True, timeout=5
            )
            if result.returncode == 0:
                with open(capture_path, "rb") as f:
                    data = f.read()
                return data
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        finally:
            try:
                os.unlink(capture_path)
            except OSError:
                pass
        return None

    def _capture_wayland(self) -> bytes | None:
        """Capture using grim (wlroots) or gnome-screenshot."""
        try:
            result = subprocess.run(
                ["grim", "-"],
                capture_output=True, timeout=5
            )
            if result.returncode == 0:
                return result.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        import tempfile
        try:
            fd, capture_path = tempfile.mkstemp(suffix=".png", prefix="ai-screen-")
            os.close(fd)
            try:
                result = subprocess.run(
                    ["gnome-screenshot", "-f", capture_path],
                    capture_output=True, timeout=5
                )
                if result.returncode == 0:
                    with open(capture_path, "rb") as f:
                        data = f.read()
                    return data
            finally:
                try:
                    os.unlink(capture_path)
                except OSError:
                    pass
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        logger.error("Wayland screen capture failed")
        return None

    def _detect_fb_resolution(self) -> tuple[int, int]:
        """Auto-detect framebuffer resolution from sysfs."""
        try:
            with open("/sys/class/graphics/fb0/virtual_size", "r") as f:
                parts = f.read().strip().split(",")
                if len(parts) == 2:
                    return int(parts[0]), int(parts[1])
        except (FileNotFoundError, ValueError, PermissionError):
            pass
        # Fallback: try to read from fb_var_screeninfo via ioctl
        try:
            with open("/sys/class/graphics/fb0/modes", "r") as f:
                mode = f.readline().strip()
                # Format like "U:1920x1080p-60"
                if "x" in mode:
                    dim = mode.split(":")[1].split("p")[0] if ":" in mode else mode
                    w, h = dim.split("x")
                    return int(w), int(h)
        except (FileNotFoundError, ValueError, IndexError, PermissionError):
            pass
        return 1920, 1080  # Default fallback

    def _capture_framebuffer(self) -> bytes | None:
        """Capture from /dev/fb0 (requires root)."""
        try:
            width, height = self._detect_fb_resolution()
            with open("/dev/fb0", "rb") as fb:
                raw = fb.read(width * height * 4)  # BGRA = 4 bytes/pixel
            from PIL import Image
            img = Image.frombytes("RGBA", (width, height), raw, "raw", "BGRA")
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            return buf.getvalue()
        except FileNotFoundError:
            logger.error("Framebuffer /dev/fb0 not available")
            return None
        except Exception as e:
            logger.error(f"Framebuffer capture failed: {e}")
            return None

    def _crop_png(self, png_data: bytes, x: int, y: int,
                  w: int, h: int) -> bytes | None:
        """Crop a PNG image."""
        try:
            from PIL import Image
            img = Image.open(io.BytesIO(png_data))
            cropped = img.crop((x, y, x + w, y + h))
            buf = io.BytesIO()
            cropped.save(buf, format="PNG")
            return buf.getvalue()
        except Exception as e:
            logger.error(f"Crop failed: {e}")
            return None

    def get_screen_size(self) -> tuple[int, int]:
        """Get the screen resolution."""
        if self.method == "x11":
            try:
                result = subprocess.run(
                    ["xdpyinfo"],
                    capture_output=True, text=True, timeout=2
                )
                for line in result.stdout.split("\n"):
                    if "dimensions:" in line:
                        parts = line.split()
                        dims = parts[1].split("x")
                        return int(dims[0]), int(dims[1])
            except Exception:
                pass
        elif self.method == "framebuffer":
            return self._detect_fb_resolution()
        return 1920, 1080  # Default fallback
