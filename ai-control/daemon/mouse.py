"""
Mouse control module - synthesize mouse events via evdev/uinput.

Provides full mouse control for the AI agent:
- Move to absolute/relative positions
- Click (left, right, middle)
- Scroll
- Drag operations
"""

import logging
import time

logger = logging.getLogger("ai-control.mouse")


def _detect_screen_size() -> tuple[int, int]:
    """Detect the actual screen resolution via xrandr or fallback to sysfs."""
    import subprocess
    try:
        result = subprocess.run(
            ["xrandr", "--query"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if "*" in line:
                    # e.g. "   1920x1080     60.00*+  "
                    parts = line.strip().split()
                    if parts:
                        res = parts[0].split("x")
                        if len(res) == 2:
                            return int(res[0]), int(res[1])
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Fallback: try /sys/class/drm
    import glob
    for mode_path in glob.glob("/sys/class/drm/card*-*/modes"):
        try:
            with open(mode_path) as f:
                first_mode = f.readline().strip()
                if "x" in first_mode:
                    w, h = first_mode.split("x")
                    return int(w), int(h)
        except (OSError, ValueError):
            continue

    return 1920, 1080  # Final fallback


class MouseController:
    """Controls mouse input via Linux uinput."""

    def __init__(self, screen_width: int = 0, screen_height: int = 0):
        self.device = None
        if screen_width == 0 or screen_height == 0:
            screen_width, screen_height = _detect_screen_size()
            logger.info("Detected screen size: %dx%d", screen_width, screen_height)
        self.screen_width = screen_width
        self.screen_height = screen_height
        self._setup_device()

    def _setup_device(self):
        """Create a virtual mouse device via uinput."""
        try:
            import evdev
            from evdev import UInput, ecodes, AbsInfo

            capabilities = {
                ecodes.EV_KEY: [
                    ecodes.BTN_LEFT,
                    ecodes.BTN_RIGHT,
                    ecodes.BTN_MIDDLE,
                ],
                ecodes.EV_ABS: [
                    (ecodes.ABS_X, AbsInfo(
                        value=0, min=0, max=self.screen_width,
                        fuzz=0, flat=0, resolution=0)),
                    (ecodes.ABS_Y, AbsInfo(
                        value=0, min=0, max=self.screen_height,
                        fuzz=0, flat=0, resolution=0)),
                ],
                ecodes.EV_REL: [
                    ecodes.REL_WHEEL,
                    ecodes.REL_HWHEEL,
                ],
            }
            self.device = UInput(capabilities, name="ai-control-mouse")
            # Cache ecodes constants on the instance to avoid re-importing
            # evdev.ecodes on every move/click/scroll call.
            self._ecodes = ecodes
            self._btn_map = {
                "left": ecodes.BTN_LEFT,
                "right": ecodes.BTN_RIGHT,
                "middle": ecodes.BTN_MIDDLE,
            }
            logger.info("Virtual mouse device created")
        except ImportError:
            logger.warning("python-evdev not available, mouse control disabled")
        except PermissionError:
            logger.warning("No permission to create uinput device (need root)")
        except OSError as e:
            logger.warning("Cannot create uinput mouse device: %s", e)

    def move_to(self, x: int, y: int):
        """Move mouse to absolute position."""
        if not self.device:
            return False
        ecodes = self._ecodes

        x = max(0, min(x, self.screen_width))
        y = max(0, min(y, self.screen_height))

        self.device.write(ecodes.EV_ABS, ecodes.ABS_X, x)
        self.device.write(ecodes.EV_ABS, ecodes.ABS_Y, y)
        self.device.syn()
        return True

    def click(self, button: str = "left"):
        """Click a mouse button."""
        if not self.device:
            return False
        ecodes = self._ecodes
        btn = self._btn_map.get(button, ecodes.BTN_LEFT)

        self.device.write(ecodes.EV_KEY, btn, 1)  # Press
        self.device.syn()
        time.sleep(0.05)
        self.device.write(ecodes.EV_KEY, btn, 0)  # Release
        self.device.syn()
        return True

    def double_click(self, button: str = "left"):
        """Double-click a mouse button."""
        self.click(button)
        time.sleep(0.1)
        self.click(button)

    def click_at(self, x: int, y: int, button: str = "left"):
        """Move to position and click."""
        self.move_to(x, y)
        time.sleep(0.05)
        self.click(button)

    def drag(self, from_x: int, from_y: int, to_x: int, to_y: int,
             button: str = "left", steps: int = 20):
        """Drag from one position to another."""
        if not self.device:
            return False
        ecodes = self._ecodes
        btn = self._btn_map.get(button, ecodes.BTN_LEFT)

        # Move to start position
        self.move_to(from_x, from_y)
        time.sleep(0.05)

        # Press button
        self.device.write(ecodes.EV_KEY, btn, 1)
        self.device.syn()
        time.sleep(0.05)

        # Interpolate movement
        for i in range(1, steps + 1):
            t = i / steps
            x = int(from_x + (to_x - from_x) * t)
            y = int(from_y + (to_y - from_y) * t)
            self.move_to(x, y)
            time.sleep(0.01)

        # Release button
        self.device.write(ecodes.EV_KEY, btn, 0)
        self.device.syn()
        return True

    def scroll(self, amount: int, horizontal: bool = False):
        """Scroll the mouse wheel."""
        if not self.device:
            return False
        ecodes = self._ecodes

        axis = ecodes.REL_HWHEEL if horizontal else ecodes.REL_WHEEL
        self.device.write(ecodes.EV_REL, axis, amount)
        self.device.syn()
        return True

    def close(self):
        """Close the virtual mouse device."""
        if self.device:
            self.device.close()
            self.device = None

    def __del__(self):
        """Ensure the uinput device is closed on garbage collection."""
        try:
            self.close()
        except Exception:
            pass

    def __enter__(self):
        """Support use as a context manager."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Close the device when exiting the context."""
        self.close()
