"""
Keyboard control module - synthesize keystrokes via evdev/uinput.

Provides full keyboard control for the AI agent:
- Type text strings
- Press/release individual keys
- Key combinations (Ctrl+C, Alt+Tab, etc.)
"""

import logging
import time

logger = logging.getLogger("ai-control.keyboard")

# Key code mapping (subset - full table in production)
KEY_MAP = {
    "escape": 1, "1": 2, "2": 3, "3": 4, "4": 5, "5": 6, "6": 7,
    "7": 8, "8": 9, "9": 10, "0": 11, "minus": 12, "equal": 13,
    "backspace": 14, "tab": 15,
    "q": 16, "w": 17, "e": 18, "r": 19, "t": 20, "y": 21, "u": 22,
    "i": 23, "o": 24, "p": 25, "leftbrace": 26, "rightbrace": 27,
    "enter": 28, "leftctrl": 29,
    "a": 30, "s": 31, "d": 32, "f": 33, "g": 34, "h": 35, "j": 36,
    "k": 37, "l": 38, "semicolon": 39, "apostrophe": 40, "grave": 41,
    "leftshift": 42, "backslash": 43,
    "z": 44, "x": 45, "c": 46, "v": 47, "b": 48, "n": 49, "m": 50,
    "comma": 51, "dot": 52, "slash": 53, "rightshift": 54,
    "leftalt": 56, "space": 57, "capslock": 58,
    "f1": 59, "f2": 60, "f3": 61, "f4": 62, "f5": 63,
    "f6": 64, "f7": 65, "f8": 66, "f9": 67, "f10": 68,
    "f11": 87, "f12": 88,
    "up": 103, "left": 105, "right": 106, "down": 108,
    "insert": 110, "delete": 111, "home": 102, "end": 107,
    "pageup": 104, "pagedown": 109,
    "leftmeta": 125, "rightmeta": 126,
}

# Character to key mapping for typing
CHAR_TO_KEY = {
    **{c: KEY_MAP[c] for c in "abcdefghijklmnopqrstuvwxyz"},
    **{str(i): KEY_MAP[str(i)] for i in range(10)},
    " ": KEY_MAP["space"],
    "\n": KEY_MAP["enter"],
    "\t": KEY_MAP["tab"],
    "-": KEY_MAP["minus"],
    "=": KEY_MAP["equal"],
    "[": KEY_MAP["leftbrace"],
    "]": KEY_MAP["rightbrace"],
    ";": KEY_MAP["semicolon"],
    "'": KEY_MAP["apostrophe"],
    "`": KEY_MAP["grave"],
    "\\": KEY_MAP["backslash"],
    ",": KEY_MAP["comma"],
    ".": KEY_MAP["dot"],
    "/": KEY_MAP["slash"],
}

# Characters that require shift
SHIFT_CHARS = {
    "!": "1", "@": "2", "#": "3", "$": "4", "%": "5",
    "^": "6", "&": "7", "*": "8", "(": "9", ")": "0",
    "_": "minus", "+": "equal", "{": "leftbrace", "}": "rightbrace",
    ":": "semicolon", '"': "apostrophe", "~": "grave",
    "|": "backslash", "<": "comma", ">": "dot", "?": "slash",
}


class KeyboardController:
    """Controls keyboard input via Linux uinput."""

    def __init__(self):
        self.device = None
        self._setup_device()

    def _setup_device(self):
        """Create a virtual keyboard device via uinput."""
        try:
            import evdev
            from evdev import UInput, ecodes

            capabilities = {
                ecodes.EV_KEY: list(range(1, 256)),  # All key codes
            }
            self.device = UInput(capabilities, name="ai-control-keyboard")
            logger.info("Virtual keyboard device created")
        except ImportError:
            logger.warning("python-evdev not available, keyboard control disabled")
        except PermissionError:
            logger.warning("No permission to create uinput device (need root)")
        except OSError as e:
            logger.warning("Cannot create uinput keyboard device: %s", e)

    def press_key(self, key_name: str):
        """Press a key down."""
        if not self.device:
            return False
        import evdev.ecodes as ecodes

        code = KEY_MAP.get(key_name.lower())
        if code is None:
            logger.warning(f"Unknown key: {key_name}")
            return False

        self.device.write(ecodes.EV_KEY, code, 1)  # Key down
        self.device.syn()
        return True

    def release_key(self, key_name: str):
        """Release a key."""
        if not self.device:
            return False
        import evdev.ecodes as ecodes

        code = KEY_MAP.get(key_name.lower())
        if code is None:
            return False

        self.device.write(ecodes.EV_KEY, code, 0)  # Key up
        self.device.syn()
        return True

    def tap_key(self, key_name: str, duration: float = 0.05):
        """Press and release a key."""
        self.press_key(key_name)
        time.sleep(duration)
        self.release_key(key_name)

    def key_combo(self, *keys: str):
        """Press a key combination (e.g., key_combo('leftctrl', 'c'))."""
        for key in keys:
            self.press_key(key)
            time.sleep(0.02)
        time.sleep(0.05)
        for key in reversed(keys):
            self.release_key(key)

    def type_text(self, text: str, delay: float = 0.02):
        """Type a string of text."""
        if not self.device:
            logger.warning("No keyboard device available")
            return False

        for char in text:
            if char.isupper():
                self.press_key("leftshift")
                self.tap_key(char.lower(), 0.02)
                self.release_key("leftshift")
            elif char in SHIFT_CHARS:
                self.press_key("leftshift")
                self.tap_key(SHIFT_CHARS[char], 0.02)
                self.release_key("leftshift")
            elif char in CHAR_TO_KEY:
                key_name = None
                for name, code in KEY_MAP.items():
                    if code == CHAR_TO_KEY[char]:
                        key_name = name
                        break
                if key_name:
                    self.tap_key(key_name, 0.02)
            time.sleep(delay)

        return True

    def close(self):
        """Close the virtual keyboard device."""
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
