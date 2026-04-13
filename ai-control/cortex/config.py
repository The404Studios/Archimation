"""Cortex configuration."""

import logging
import os
from dataclasses import dataclass, field

logger = logging.getLogger("cortex.config")


@dataclass
class AutonomyConfig:
    """Per-domain autonomy levels (0-3).

    0 = fully manual (always ask human)
    1 = suggest only
    2 = act with audit trail
    3 = act autonomously, log (hard maximum)
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
            return config

        try:
            with open(path, "rb") as f:
                data = tomllib.load(f)
        except Exception as exc:
            logger.warning(
                "Failed to parse config %s: %s; using defaults", path, exc,
            )
            return config

        # The TOML file uses nested sections:
        #   [general]  -> log_level
        #   [sockets]  -> event_socket, command_socket, broker_socket, scm_socket
        #   [trust]    -> device (-> trust_device), initial_score (-> initial_trust_score)
        #   [llm]      -> model_path (-> llm_model_path)
        #   [api]      -> port, enabled
        #   [autonomy] -> per-domain levels
        # Also support flat top-level keys for backwards compatibility.

        # [general] section
        general = data.get("general", {})
        if isinstance(general, dict) and "log_level" in general:
            config.log_level = general["log_level"]

        # [sockets] section
        sockets = data.get("sockets", {})
        if isinstance(sockets, dict):
            _socket_keys = ["event_socket", "command_socket", "broker_socket", "scm_socket"]
            for key in _socket_keys:
                if key in sockets:
                    setattr(config, key, sockets[key])

        # [trust] section
        trust = data.get("trust", {})
        if isinstance(trust, dict):
            if "device" in trust:
                config.trust_device = trust["device"]
            if "initial_score" in trust:
                config.initial_trust_score = max(0, min(100, int(trust["initial_score"])))

        # [llm] section
        llm = data.get("llm", {})
        if isinstance(llm, dict) and "model_path" in llm:
            config.llm_model_path = llm["model_path"]

        # Backwards compatibility: flat top-level scalar keys
        _scalar_keys = [
            "event_socket", "command_socket", "broker_socket",
            "scm_socket", "trust_device", "log_level",
            "llm_model_path", "initial_trust_score",
        ]
        for key in _scalar_keys:
            if key in data:
                setattr(config, key, data[key])

        # [autonomy] section -- per-domain levels
        if "autonomy" in data and isinstance(data["autonomy"], dict):
            for key, val in data["autonomy"].items():
                if hasattr(config.autonomy, key):
                    setattr(config.autonomy, key, max(0, min(3, int(val))))

        return config
