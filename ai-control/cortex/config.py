"""Cortex configuration."""

import logging
import os
from dataclasses import dataclass, field

logger = logging.getLogger("cortex.config")

# Valid ranges / enums used by validators.
_VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
# Autonomy level range (0=OBSERVE, 1=ADVISE, 2=ACT+REPORT, 3=AUTONOMOUS).
# SOVEREIGN (4) was removed as a safety measure; see cortex/autonomy.py.
_AUTONOMY_MAX = 3


def _clamp_autonomy(val, default, name):
    """Coerce autonomy level to int in [0, 3]; fall back to *default* on error."""
    try:
        ival = int(val)
    except (TypeError, ValueError):
        logger.warning(
            "cortex.config: autonomy.%s=%r not an int; using %d",
            name, val, default,
        )
        return default
    if ival < 0 or ival > _AUTONOMY_MAX:
        logger.warning(
            "cortex.config: autonomy.%s=%d out of range [0, %d]; clamping",
            name, ival, _AUTONOMY_MAX,
        )
        return max(0, min(_AUTONOMY_MAX, ival))
    return ival


@dataclass
class AutonomyConfig:
    """Per-domain autonomy levels (0-3).

    0 = fully manual (always ask human)
    1 = suggest only
    2 = act with audit trail
    3 = act autonomously, log (hard maximum)

    Defaults are intentionally conservative: trust_modification defaults to
    0 (always ask) because a misbehaving AI that can edit its own trust
    graph breaks the whole authority model. Raise deliberately in TOML.
    """
    process_management: int = 2
    network_access: int = 1
    trust_modification: int = 0
    hardware_control: int = 1
    pe_execution: int = 2
    service_management: int = 2
    security_response: int = 2
    system_configuration: int = 1


@dataclass
class CortexConfig:
    """Top-level configuration for the AI Cortex.

    Loaded from ``/etc/pe-compat/cortex.toml`` with sane defaults so the
    daemon can always start even when the config file is absent.

    Security-relevant defaults:
      * ``llm_model_path`` is empty by default -- cortex falls back to
        policy+heuristics rather than crashing on a missing model file.
      * ``initial_trust_score=50`` puts new subjects at the Level 2
        ceiling, not at max trust.
    """
    event_socket: str = "/run/pe-compat/events.sock"
    command_socket: str = "/run/pe-compat/cortex-cmd.sock"
    broker_socket: str = "/run/pe-compat/objects.sock"
    scm_socket: str = "/run/pe-compat/scm.sock"
    trust_device: str = "/dev/trust"
    log_level: str = "INFO"
    llm_model_path: str = ""  # Empty = no LLM loaded
    autonomy: AutonomyConfig = field(default_factory=AutonomyConfig)
    initial_trust_score: int = 50  # Start at Level 2 ceiling

    @classmethod
    def load(cls, path: str = "/etc/pe-compat/cortex.toml") -> "CortexConfig":
        """Load configuration from a TOML file, falling back to defaults.

        Uses ``tomllib`` (Python 3.11+) with a ``tomli`` fallback for 3.10.
        Returns a default ``CortexConfig`` on any parse error so the daemon
        always starts.
        """
        config = cls()

        if not os.path.exists(path):
            _validate_cortex_config(config)
            return config

        # Import a TOML parser -- tomllib is stdlib from 3.11,
        # tomli is the backport for 3.10.  If neither is available,
        # skip file loading and return default config.
        tomllib = None  # type: ignore[assignment]
        try:
            import tomllib  # type: ignore[import-not-found,no-redef]
        except ImportError:
            try:
                import tomli as tomllib  # type: ignore[import-not-found,no-redef]
            except ImportError:
                pass

        if tomllib is None:
            logger.warning(
                "No TOML parser available (need Python 3.11+ or tomli package); "
                "using default config"
            )
            _validate_cortex_config(config)
            return config

        try:
            with open(path, "rb") as f:
                data = tomllib.load(f)
        except Exception as exc:
            logger.warning(
                "Failed to parse config %s: %s; using defaults", path, exc,
            )
            _validate_cortex_config(config)
            return config

        if not isinstance(data, dict):
            logger.warning(
                "cortex.config: %s top-level is not a table; using defaults",
                path,
            )
            _validate_cortex_config(config)
            return config

        # The TOML file uses nested sections:
        #   [general]  -> log_level
        #   [sockets]  -> event_socket, command_socket, broker_socket, scm_socket
        #   [trust]    -> device (-> trust_device), initial_score (-> initial_trust_score)
        #   [llm]      -> model_path (-> llm_model_path)
        #   [api]      -> port, enabled
        #   [autonomy] -> per-domain levels
        # Also support flat top-level keys for backwards compatibility.

        def _set_str(obj, key, value, default):
            """Type-check string config values before assignment."""
            if not isinstance(value, str):
                logger.warning(
                    "cortex.config: %s=%r not a string; using default %r",
                    key, value, default,
                )
                return
            setattr(obj, key, value)

        # [general] section
        general = data.get("general", {})
        if isinstance(general, dict) and "log_level" in general:
            _set_str(config, "log_level", general["log_level"], config.log_level)

        # [sockets] section
        sockets = data.get("sockets", {})
        if isinstance(sockets, dict):
            _socket_keys = ["event_socket", "command_socket", "broker_socket", "scm_socket"]
            for key in _socket_keys:
                if key in sockets:
                    _set_str(config, key, sockets[key], getattr(config, key))

        # [trust] section
        trust = data.get("trust", {})
        if isinstance(trust, dict):
            if "device" in trust:
                _set_str(config, "trust_device", trust["device"], config.trust_device)
            if "initial_score" in trust:
                try:
                    score = int(trust["initial_score"])
                except (TypeError, ValueError):
                    logger.warning(
                        "cortex.config: trust.initial_score=%r not an int; "
                        "using default 50", trust["initial_score"],
                    )
                    score = 50
                config.initial_trust_score = max(0, min(100, score))

        # [llm] section
        llm = data.get("llm", {})
        if isinstance(llm, dict) and "model_path" in llm:
            _set_str(config, "llm_model_path", llm["model_path"], config.llm_model_path)

        # Backwards compatibility: flat top-level scalar keys.
        _string_scalar_keys = [
            "event_socket", "command_socket", "broker_socket",
            "scm_socket", "trust_device", "log_level", "llm_model_path",
        ]
        for key in _string_scalar_keys:
            if key in data:
                _set_str(config, key, data[key], getattr(config, key))
        # initial_trust_score is numeric; validate separately.
        if "initial_trust_score" in data:
            try:
                config.initial_trust_score = max(0, min(100, int(data["initial_trust_score"])))
            except (TypeError, ValueError):
                logger.warning(
                    "cortex.config: initial_trust_score=%r not an int; keeping %d",
                    data["initial_trust_score"], config.initial_trust_score,
                )

        # [autonomy] section -- per-domain levels (clamped to 0..3).
        if "autonomy" in data and isinstance(data["autonomy"], dict):
            for key, val in data["autonomy"].items():
                if hasattr(config.autonomy, key):
                    current = getattr(config.autonomy, key)
                    setattr(
                        config.autonomy, key,
                        _clamp_autonomy(val, current, key),
                    )

        # Final validation pass.
        _validate_cortex_config(config)

        return config


def _validate_cortex_config(config: "CortexConfig") -> None:
    """Validate / normalise config in-place. Invalid -> default + warning.

    Only applies to fields where a bad value would otherwise surface later
    as a cryptic runtime error (e.g. setLevel() raising on junk log_level,
    or llama-cpp crashing on a non-existent model path).
    """
    # log_level: must be a real logging-module name.
    lvl = str(config.log_level or "INFO").upper()
    if lvl not in _VALID_LOG_LEVELS:
        logger.warning(
            "cortex.config: log_level=%r not in %s; using INFO",
            config.log_level, sorted(_VALID_LOG_LEVELS),
        )
        lvl = "INFO"
    config.log_level = lvl

    # initial_trust_score: paranoia clamp (TOML path already clamps but
    # flat-key path and default struct modification can still poke this).
    try:
        score = int(config.initial_trust_score)
    except (TypeError, ValueError):
        score = 50
    config.initial_trust_score = max(0, min(100, score))

    # llm_model_path: non-existent path is NOT a fatal error -- the cortex
    # falls back to policy+heuristics when the model isn't loaded. We just
    # warn so the operator knows why the LLM tier is disabled.
    mp = config.llm_model_path or ""
    if mp and not os.path.exists(mp):
        logger.warning(
            "cortex.config: llm_model_path=%s does not exist; "
            "LLM tier disabled (policy+heuristics only)",
            mp,
        )
        # Keep the path string on the config so ops can see what was
        # *configured*; the LLM loader already handles the missing-file case.

    # Autonomy struct: clamp each field one more time in case someone
    # constructed a CortexConfig() directly and poked an out-of-range value.
    for fname in AutonomyConfig.__dataclass_fields__:
        current = getattr(config.autonomy, fname, 0)
        clamped = _clamp_autonomy(current, current, fname)
        setattr(config.autonomy, fname, clamped)
