"""Configuration loader for AI Control Daemon."""

import os
from pathlib import Path

# Default configuration
DEFAULT_CONFIG = {
    "api_host": "127.0.0.1",
    "api_port": 8420,
    "log_level": "INFO",
    "log_file": "/var/log/ai-control-daemon/daemon.log",
    "screen_capture_method": "auto",  # auto, x11, wayland, framebuffer
    "input_method": "uinput",         # uinput, xdotool
    "audit_log": "/var/log/ai-control-daemon/audit.log",
    "state_dir": "/var/lib/ai-control-daemon",
    "auth_enabled": True,             # Auth on by default even without config file
}


def _flatten_toml(config, toml_data):
    """Map nested TOML sections to flat config keys."""
    if "server" in toml_data:
        s = toml_data["server"]
        if "host" in s: config["api_host"] = s["host"]
        if "port" in s: config["api_port"] = s["port"]
    if "logging" in toml_data:
        l = toml_data["logging"]
        if "level" in l: config["log_level"] = l["level"]
        if "file" in l: config["log_file"] = l["file"]
    if "screen" in toml_data:
        if "capture_method" in toml_data["screen"]:
            config["screen_capture_method"] = toml_data["screen"]["capture_method"]
    if "input" in toml_data:
        if "method" in toml_data["input"]:
            config["input_method"] = toml_data["input"]["method"]
    if "audit" in toml_data:
        if "log" in toml_data["audit"]:
            config["audit_log"] = toml_data["audit"]["log"]
    if "auth" in toml_data:
        if "enabled" in toml_data["auth"]:
            config["auth_enabled"] = toml_data["auth"]["enabled"]
        if "auto_bootstrap" in toml_data["auth"]:
            config["auth_auto_bootstrap"] = toml_data["auth"]["auto_bootstrap"]
    if "trust" in toml_data:
        t = toml_data["trust"]
        if "poll_interval" in t: config["trust_poll_interval"] = t["poll_interval"]
        if "oscillation_window" in t: config["trust_oscillation_window"] = t["oscillation_window"]
        if "oscillation_threshold" in t: config["trust_oscillation_threshold"] = t["oscillation_threshold"]
        if "freeze_duration" in t: config["trust_freeze_duration"] = t["freeze_duration"]
    if "automation" in toml_data:
        a = toml_data["automation"]
        if "full_access" in a: config["full_access"] = a["full_access"]
        if "auto_observe" in a: config["auto_observe"] = a["auto_observe"]
    if "scanner" in toml_data:
        s = toml_data["scanner"]
        if "enabled" in s: config["scanner_enabled"] = s["enabled"]
        if "patterns_dir" in s: config["scanner_patterns_dir"] = s["patterns_dir"]
        if "stub_log_path" in s: config["scanner_stub_log_path"] = s["stub_log_path"]
        if "auto_scan_on_pe_load" in s: config["scanner_auto_scan_on_pe_load"] = s["auto_scan_on_pe_load"]
        if "max_scan_size_mb" in s: config["scanner_max_scan_size_mb"] = s["max_scan_size_mb"]
    if "analysis" in toml_data:
        a = toml_data["analysis"]
        if "enabled" in a: config["analysis_enabled"] = a["enabled"]
        if "win_api_db_path" in a: config["win_api_db_path"] = a["win_api_db_path"]
        if "signatures_path" in a: config["signatures_db_path"] = a["signatures_path"]
        if "generated_stubs_path" in a: config["stub_generator_output_dir"] = a["generated_stubs_path"]
        if "auto_analyze_on_pe_load" in a: config["auto_analyze_on_pe_load"] = a["auto_analyze_on_pe_load"]
        if "syscall_poll_interval" in a: config["syscall_poll_interval"] = a["syscall_poll_interval"]
        if "syscall_process_ttl" in a: config["syscall_process_ttl"] = a["syscall_process_ttl"]
        if "syscall_max_processes" in a: config["syscall_max_processes"] = a["syscall_max_processes"]


def load_config(path: str) -> dict:
    """Load configuration from TOML file, falling back to defaults."""
    config = dict(DEFAULT_CONFIG)

    if os.path.exists(path):
        try:
            import tomllib
        except ImportError:
            try:
                import tomli as tomllib
            except ImportError:
                # No TOML parser available, use defaults
                return config

        with open(path, "rb") as f:
            file_config = tomllib.load(f)
            _flatten_toml(config, file_config)

    # Ensure required directories exist
    for key in ("state_dir",):
        dir_path = config.get(key)
        if dir_path:
            Path(dir_path).mkdir(parents=True, exist_ok=True)

    for key in ("log_file", "audit_log"):
        file_path = config.get(key)
        if file_path:
            Path(file_path).parent.mkdir(parents=True, exist_ok=True)

    return config
