"""Configuration loader for AI Control Daemon.

Validation philosophy
---------------------
Values are validated *permissively*: a bad value in a user-supplied TOML
file falls back to the default and emits a warning, rather than aborting
the daemon. This matches the project's "daemon must always start"
philosophy (see ``cortex/config.py``). Only *schema-breaking* damage
(e.g. non-dict top-level) is ignored silently by the TOML parser itself.

Callers that want hard-fail behaviour should pass ``strict=True``.
"""

import logging
import os
import sys
from pathlib import Path

logger = logging.getLogger("ai-control.config")

# ---------------------------------------------------------------------------
# Default configuration
# ---------------------------------------------------------------------------
# Note: every key a caller may read via ``config.get(KEY, DEFAULT)`` should
# also appear here so that a naive ``config[KEY]`` lookup works. Callers in
# this project consistently use ``.get(..., default)`` so missing keys are
# safe, but listing them here keeps the "schema" in one place.
DEFAULT_CONFIG = {
    # --- server / network -------------------------------------------------
    "api_host": "127.0.0.1",        # bind loopback only; do NOT expose 0.0.0.0 by default
    "api_port": 8420,
    # --- logging ----------------------------------------------------------
    "log_level": "INFO",
    "log_file": "/var/log/ai-control-daemon/daemon.log",
    "audit_log": "/var/log/ai-control-daemon/audit.log",
    # --- session capture / input -----------------------------------------
    "screen_capture_method": "auto",   # auto, x11, wayland, framebuffer
    "input_method": "uinput",          # uinput, xdotool
    # --- state ------------------------------------------------------------
    "state_dir": "/var/lib/ai-control-daemon",
    # --- auth -------------------------------------------------------------
    "auth_enabled": True,              # Auth on by default even without config file
    "auth_auto_bootstrap": True,       # main.py reads this with .get(...,False); keep explicit
}

# Valid ranges / enums used by the validator.
_VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
_VALID_CAPTURE = {"auto", "x11", "wayland", "framebuffer"}
_VALID_INPUT = {"uinput", "xdotool"}


def _coerce_int(val, default, name, lo=None, hi=None):
    """Coerce ``val`` to int with optional range check; fall back to default."""
    try:
        ival = int(val)
    except (TypeError, ValueError):
        logger.warning("config: %s=%r not an int; using default %r", name, val, default)
        return default
    if lo is not None and ival < lo:
        logger.warning("config: %s=%d below min %d; using default %r", name, ival, lo, default)
        return default
    if hi is not None and ival > hi:
        logger.warning("config: %s=%d above max %d; using default %r", name, ival, hi, default)
        return default
    return ival


def _coerce_float(val, default, name, lo=None, hi=None):
    try:
        fval = float(val)
    except (TypeError, ValueError):
        logger.warning("config: %s=%r not a number; using default %r", name, val, default)
        return default
    if lo is not None and fval < lo:
        logger.warning("config: %s=%s below min %s; using default %r", name, fval, lo, default)
        return default
    if hi is not None and fval > hi:
        logger.warning("config: %s=%s above max %s; using default %r", name, fval, hi, default)
        return default
    return fval


def _coerce_bool(val, default, name):
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return bool(val)
    if isinstance(val, str):
        s = val.strip().lower()
        if s in ("true", "1", "yes", "on"):
            return True
        if s in ("false", "0", "no", "off"):
            return False
    logger.warning("config: %s=%r not a bool; using default %r", name, val, default)
    return default


def _flatten_toml(config, toml_data):
    """Map nested TOML sections to flat config keys."""
    if "server" in toml_data and isinstance(toml_data["server"], dict):
        s = toml_data["server"]
        if "host" in s: config["api_host"] = s["host"]
        if "port" in s: config["api_port"] = s["port"]
    if "logging" in toml_data and isinstance(toml_data["logging"], dict):
        l = toml_data["logging"]
        if "level" in l: config["log_level"] = l["level"]
        if "file" in l: config["log_file"] = l["file"]
    if "screen" in toml_data and isinstance(toml_data["screen"], dict):
        if "capture_method" in toml_data["screen"]:
            config["screen_capture_method"] = toml_data["screen"]["capture_method"]
    if "input" in toml_data and isinstance(toml_data["input"], dict):
        if "method" in toml_data["input"]:
            config["input_method"] = toml_data["input"]["method"]
    if "audit" in toml_data and isinstance(toml_data["audit"], dict):
        if "log" in toml_data["audit"]:
            config["audit_log"] = toml_data["audit"]["log"]
    if "auth" in toml_data and isinstance(toml_data["auth"], dict):
        if "enabled" in toml_data["auth"]:
            config["auth_enabled"] = toml_data["auth"]["enabled"]
        if "auto_bootstrap" in toml_data["auth"]:
            config["auth_auto_bootstrap"] = toml_data["auth"]["auto_bootstrap"]
    if "trust" in toml_data and isinstance(toml_data["trust"], dict):
        t = toml_data["trust"]
        if "poll_interval" in t: config["trust_poll_interval"] = t["poll_interval"]
        if "oscillation_window" in t: config["trust_oscillation_window"] = t["oscillation_window"]
        if "oscillation_threshold" in t: config["trust_oscillation_threshold"] = t["oscillation_threshold"]
        if "freeze_duration" in t: config["trust_freeze_duration"] = t["freeze_duration"]
    if "automation" in toml_data and isinstance(toml_data["automation"], dict):
        a = toml_data["automation"]
        if "full_access" in a: config["full_access"] = a["full_access"]
        if "auto_observe" in a: config["auto_observe"] = a["auto_observe"]
    if "scanner" in toml_data and isinstance(toml_data["scanner"], dict):
        s = toml_data["scanner"]
        if "enabled" in s: config["scanner_enabled"] = s["enabled"]
        if "patterns_dir" in s: config["scanner_patterns_dir"] = s["patterns_dir"]
        if "stub_log_path" in s: config["scanner_stub_log_path"] = s["stub_log_path"]
        if "auto_scan_on_pe_load" in s: config["scanner_auto_scan_on_pe_load"] = s["auto_scan_on_pe_load"]
        if "max_scan_size_mb" in s: config["scanner_max_scan_size_mb"] = s["max_scan_size_mb"]
    if "analysis" in toml_data and isinstance(toml_data["analysis"], dict):
        a = toml_data["analysis"]
        if "enabled" in a: config["analysis_enabled"] = a["enabled"]
        if "win_api_db_path" in a: config["win_api_db_path"] = a["win_api_db_path"]
        if "signatures_path" in a: config["signatures_db_path"] = a["signatures_path"]
        if "generated_stubs_path" in a: config["stub_generator_output_dir"] = a["generated_stubs_path"]
        if "auto_analyze_on_pe_load" in a: config["auto_analyze_on_pe_load"] = a["auto_analyze_on_pe_load"]
        if "syscall_poll_interval" in a: config["syscall_poll_interval"] = a["syscall_poll_interval"]
        if "syscall_process_ttl" in a: config["syscall_process_ttl"] = a["syscall_process_ttl"]
        if "syscall_max_processes" in a: config["syscall_max_processes"] = a["syscall_max_processes"]


def _validate(config):
    """Validate / coerce config values. Invalid entries fall back to defaults.

    This is intentionally permissive — bad values log a warning and fall
    back to the default so the daemon can always start. If a hostile or
    typo'd TOML sets ``port = 999999`` we silently use 8420 rather than
    crashing at bind() time with an opaque OSError.
    """
    # --- network ----------------------------------------------------------
    config["api_port"] = _coerce_int(
        config.get("api_port"), DEFAULT_CONFIG["api_port"],
        "api_port", lo=1, hi=65535,
    )
    host = config.get("api_host")
    if not isinstance(host, str) or not host.strip():
        logger.warning("config: api_host=%r invalid; using default", host)
        config["api_host"] = DEFAULT_CONFIG["api_host"]
    elif host.strip() == "0.0.0.0":
        # Not a failure -- but yell about it. Exposing the AI control
        # daemon on all interfaces is a security decision the operator
        # should consciously make.
        logger.warning(
            "config: api_host=0.0.0.0 exposes the AI control daemon on ALL "
            "network interfaces. Ensure auth_enabled=true and a strong token."
        )
        config["api_host"] = host.strip()
    else:
        config["api_host"] = host.strip()

    # --- logging ----------------------------------------------------------
    lvl = str(config.get("log_level", "INFO")).upper()
    if lvl not in _VALID_LOG_LEVELS:
        logger.warning(
            "config: log_level=%r not in %s; using INFO",
            config.get("log_level"), sorted(_VALID_LOG_LEVELS),
        )
        lvl = "INFO"
    config["log_level"] = lvl

    # --- screen / input enums --------------------------------------------
    cap = config.get("screen_capture_method")
    if cap not in _VALID_CAPTURE:
        logger.warning(
            "config: screen_capture_method=%r not in %s; using 'auto'",
            cap, sorted(_VALID_CAPTURE),
        )
        config["screen_capture_method"] = "auto"
    im = config.get("input_method")
    if im not in _VALID_INPUT:
        logger.warning(
            "config: input_method=%r not in %s; using 'uinput'",
            im, sorted(_VALID_INPUT),
        )
        config["input_method"] = "uinput"

    # --- auth (bools) -----------------------------------------------------
    config["auth_enabled"] = _coerce_bool(
        config.get("auth_enabled"), True, "auth_enabled",
    )
    config["auth_auto_bootstrap"] = _coerce_bool(
        config.get("auth_auto_bootstrap", True), True, "auth_auto_bootstrap",
    )
    if not config["auth_enabled"]:
        logger.warning(
            "config: auth_enabled=false -- AI control API is UNAUTHENTICATED. "
            "Only safe on an isolated / single-user system."
        )

    # --- trust observer ---------------------------------------------------
    if "trust_poll_interval" in config:
        config["trust_poll_interval"] = _coerce_float(
            config["trust_poll_interval"], 1.0, "trust_poll_interval",
            lo=0.05, hi=3600.0,
        )
    if "trust_oscillation_window" in config:
        config["trust_oscillation_window"] = _coerce_float(
            config["trust_oscillation_window"], 10.0, "trust_oscillation_window",
            lo=1.0, hi=86400.0,
        )
    if "trust_oscillation_threshold" in config:
        config["trust_oscillation_threshold"] = _coerce_int(
            config["trust_oscillation_threshold"], 4, "trust_oscillation_threshold",
            lo=1, hi=1000,
        )
    if "trust_freeze_duration" in config:
        config["trust_freeze_duration"] = _coerce_float(
            config["trust_freeze_duration"], 30.0, "trust_freeze_duration",
            lo=0.0, hi=86400.0,
        )

    # --- scanner / analysis ---------------------------------------------
    if "scanner_max_scan_size_mb" in config:
        config["scanner_max_scan_size_mb"] = _coerce_int(
            config["scanner_max_scan_size_mb"], 64, "scanner_max_scan_size_mb",
            lo=1, hi=65536,
        )
    if "syscall_poll_interval" in config:
        config["syscall_poll_interval"] = _coerce_float(
            config["syscall_poll_interval"], 2.0, "syscall_poll_interval",
            lo=0.1, hi=3600.0,
        )
    if "syscall_process_ttl" in config:
        config["syscall_process_ttl"] = _coerce_float(
            config["syscall_process_ttl"], 300.0, "syscall_process_ttl",
            lo=1.0, hi=86400.0,
        )
    if "syscall_max_processes" in config:
        config["syscall_max_processes"] = _coerce_int(
            config["syscall_max_processes"], 512, "syscall_max_processes",
            lo=1, hi=100000,
        )
    for k in ("scanner_enabled", "scanner_auto_scan_on_pe_load",
              "analysis_enabled", "auto_analyze_on_pe_load",
              "full_access", "auto_observe"):
        if k in config:
            config[k] = _coerce_bool(config[k], bool(config[k]), k)


def _detect_hardware_class() -> str:
    """Return 'old', 'mid', or 'new' based on RAM + CPU count.

    Old:   < 2 GB RAM or single-core        → disable observers, smaller caches
    Mid:   2-8 GB RAM, 2-4 cores            → default settings
    New:   >= 8 GB RAM or >= 4 cores        → enable concurrency, larger caches

    Reads /proc/meminfo directly (no psutil dependency, no subprocess).
    """
    mem_gb = 0.0
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    parts = line.split()
                    if len(parts) >= 2:
                        mem_gb = int(parts[1]) / (1024 * 1024)
                    break
    except OSError:
        pass
    cpu_count = os.cpu_count() or 1

    if mem_gb < 2.0 or cpu_count <= 1:
        return "old"
    if mem_gb >= 8.0 and cpu_count >= 4:
        return "new"
    return "mid"


def _detect_iouring_support() -> tuple[bool, dict]:
    """Probe kernel io_uring availability.

    Returns ``(available, feature_bitmap_dict)``.  Probe is cheap (one
    setup+teardown of a depth-2 ring) and cached by :class:`IOUring`
    itself, so repeated calls are free.  Never raises -- a failed probe
    just returns ``(False, {})`` and the observers stay on /proc text
    reads.
    """
    if sys.platform != "linux":
        return (False, {})
    try:
        # Import is intentionally deferred so non-Linux tooling
        # (mkarchiso on WSL, Windows test harness) doesn't pay the
        # ctypes/mmap setup cost at import time.
        from iouring import IOUring  # type: ignore[import-not-found]
    except ImportError:
        try:
            from daemon.iouring import IOUring  # type: ignore[import-not-found,no-redef]
        except ImportError:
            return (False, {})
    try:
        ok = IOUring.available()
        return (ok, IOUring.features() if ok else {})
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("iouring probe raised: %s", exc)
        return (False, {})


def _apply_hardware_defaults(config: dict) -> None:
    """Set observer + cache defaults based on detected hardware class.

    Only fills keys the operator hasn't explicitly set. The detected class
    is stored in config['hardware_class'] so controllers can read it.
    """
    hw = _detect_hardware_class()
    config.setdefault("hardware_class", hw)
    logger.info("config: detected hardware_class=%s", hw)

    # Keys we tune per class. Operator overrides in TOML are preserved.
    def _default(key, val):
        if key not in config:
            config[key] = val

    if hw == "old":
        # Low-mem, single-core: drop to minimum viable footprint.
        _default("trust_poll_interval", 5.0)         # from 1.0
        _default("memory_poll_interval", 30.0)       # from 5.0
        _default("memory_process_ttl", 120.0)
        _default("memory_max_processes", 64)         # from 512
        _default("memory_diff_max_snapshots", 5)
        _default("syscall_poll_interval", 10.0)      # from 2.0
        _default("syscall_process_ttl", 60.0)
        _default("syscall_max_processes", 64)        # from 512
        _default("scanner_enabled", False)           # disable by default
    elif hw == "mid":
        _default("trust_poll_interval", 2.0)
        _default("memory_poll_interval", 10.0)
        _default("memory_max_processes", 256)
        _default("syscall_poll_interval", 5.0)
        _default("syscall_max_processes", 256)
    else:  # new
        _default("trust_poll_interval", 1.0)
        _default("memory_poll_interval", 5.0)
        _default("memory_max_processes", 512)
        _default("syscall_poll_interval", 2.0)
        _default("syscall_max_processes", 512)

    # ── io_uring (R32) -------------------------------------------------
    #
    # Default policy:
    #   - old HW: never.  SQPOLL would burn the only spare core, and the
    #     /proc text-read path works fine at its reduced poll cadence.
    #   - mid HW: enable if the kernel supports it, no SQPOLL.
    #   - new HW: enable with SQPOLL (kernel poll thread pinned to the
    #     last CPU) for the lowest-latency observer ticks.
    #
    # Operators can override:
    #   use_iouring         : false -> force classic /proc text I/O
    #                         true  -> force on (probe still gates)
    #   iouring_sqpoll      : false -> disable SQPOLL even on new HW
    #   iouring_sq_cpu      : int   -> pin the SQPOLL thread to this CPU
    #   iouring_depth       : int   -> SQ depth per ring (power of two)
    ok, feats = _detect_iouring_support()
    config.setdefault("iouring_available", ok)
    config.setdefault("iouring_features", feats)

    if hw == "old":
        _default("use_iouring", False)
        _default("iouring_sqpoll", False)
    elif hw == "mid":
        _default("use_iouring", ok)
        _default("iouring_sqpoll", False)
    else:
        _default("use_iouring", ok)
        # SQPOLL pins a kernel thread to a CPU; only safe with >= 4 cores.
        cpu_count = os.cpu_count() or 1
        _default("iouring_sqpoll", ok and cpu_count >= 4)
        if config["iouring_sqpoll"]:
            # Pin to last physical CPU (observers don't need cache locality
            # with any particular user thread).
            _default("iouring_sq_cpu", cpu_count - 1)

    _default("iouring_depth", 64 if hw == "new" else 32)

    if config.get("use_iouring"):
        logger.info(
            "config: io_uring enabled (sqpoll=%s, depth=%d, features=0x%x)",
            config.get("iouring_sqpoll", False),
            config.get("iouring_depth", 32),
            feats.get("features", 0) if isinstance(feats, dict) else 0,
        )
    elif ok:
        logger.debug(
            "config: io_uring available but disabled on hardware_class=%s", hw
        )
    else:
        logger.debug("config: io_uring unavailable (kernel <5.1 or non-Linux)")


def load_config(path: str) -> dict:
    """Load configuration from TOML file, falling back to defaults.

    Unknown TOML parse errors are logged and defaults returned so the
    daemon can always start. Range / enum violations are coerced to
    defaults with a warning (see :func:`_validate`).
    """
    config = dict(DEFAULT_CONFIG)

    if os.path.exists(path):
        tomllib = None  # type: ignore[assignment]
        try:
            import tomllib  # type: ignore[import-not-found,no-redef]
        except ImportError:
            try:
                import tomli as tomllib  # type: ignore[import-not-found,no-redef]
            except ImportError:
                logger.warning(
                    "No TOML parser available (need Python 3.11+ or tomli); "
                    "using default config"
                )
                tomllib = None

        if tomllib is not None:
            try:
                with open(path, "rb") as f:
                    file_config = tomllib.load(f)
                if isinstance(file_config, dict):
                    _flatten_toml(config, file_config)
                else:
                    logger.warning(
                        "config: %s top-level is not a table; using defaults",
                        path,
                    )
            except Exception as exc:  # TOMLDecodeError + OSError
                logger.warning(
                    "config: failed to parse %s: %s; using defaults", path, exc,
                )

    # Coerce/validate values (invalid -> default + warning).
    _validate(config)

    # Auto-detect hardware class and apply sane defaults so the daemon
    # doesn't crash low-memory boxes with unbounded observer buffers.
    # Operators can still override individual keys in the TOML.
    _apply_hardware_defaults(config)

    # Ensure required directories exist. Swallow PermissionError so a
    # running daemon that loses write-access to /var/log doesn't crash
    # on reload -- existing log-file handles stay open.
    for key in ("state_dir",):
        dir_path = config.get(key)
        if dir_path:
            try:
                Path(dir_path).mkdir(parents=True, exist_ok=True)
            except (OSError, PermissionError) as exc:
                logger.warning("config: cannot create %s=%s: %s", key, dir_path, exc)

    for key in ("log_file", "audit_log"):
        file_path = config.get(key)
        if file_path:
            try:
                Path(file_path).parent.mkdir(parents=True, exist_ok=True)
            except (OSError, PermissionError) as exc:
                logger.warning("config: cannot create parent of %s=%s: %s",
                               key, file_path, exc)

    return config
