#!/usr/bin/env python3
"""
AI Control Daemon - Full system control for AI agents

Runs as root with unrestricted access to:
- Keyboard and mouse (evdev/uinput)
- Screen capture (X11/framebuffer)
- Network (NetworkManager D-Bus + raw sockets)
- System management (pacman, systemd, processes)
- Filesystem (full read/write)
- Firewall (nftables rule management)
- Windows services (SCM bridge)

Exposes a REST + WebSocket API on port 8420.
"""

import asyncio
import logging
import signal
import socket
import sys
import os
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from config import load_config
from api_server import create_app, start_server

logger = logging.getLogger("ai-control")


def setup_logging(config: dict):
    level = getattr(logging, config.get("log_level", "INFO").upper())
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
        ],
    )
    log_file = config.get("log_file")
    if log_file:
        fh = logging.FileHandler(log_file)
        fh.setLevel(level)
        fh.setFormatter(
            logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")
        )
        logging.getLogger().addHandler(fh)


def check_root():
    if os.geteuid() != 0:
        logger.warning(
            "AI Control Daemon should run as root for full hardware access. "
            "Some features may not work."
        )


def check_port_available(host: str, port: int) -> bool:
    """Check if the desired port is available before starting the server."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, port))
            return True
    except OSError as e:
        logger.error(
            "Port %d on %s is already in use (errno %s). "
            "Another instance of ai-control-daemon may be running. "
            "Stop it with: systemctl stop ai-control",
            port, host, e.errno,
        )
        return False


def detect_session_type() -> str:
    """Detect and log the display session type (Wayland, X11, or headless)."""
    session_type = os.environ.get("XDG_SESSION_TYPE", "").lower()
    wayland_display = os.environ.get("WAYLAND_DISPLAY", "")
    hyprland_sig = os.environ.get("HYPRLAND_INSTANCE_SIGNATURE", "")
    display = os.environ.get("DISPLAY", "")

    if session_type == "wayland" or wayland_display:
        compositor = "Hyprland" if hyprland_sig else "unknown"
        logger.info(
            "Session type: Wayland (WAYLAND_DISPLAY=%s, compositor=%s)",
            wayland_display, compositor,
        )
        return "wayland"
    elif session_type == "x11" or display:
        logger.info("Session type: X11 (DISPLAY=%s)", display)
        return "x11"
    else:
        logger.warning(
            "Session type: headless (no DISPLAY or WAYLAND_DISPLAY set). "
            "Desktop and compositor features will be unavailable."
        )
        return "headless"


async def _watch_server(server_task, shutdown_event):
    """Monitor the server task and trigger shutdown if it crashes."""
    try:
        await server_task
    except asyncio.CancelledError:
        pass
    except Exception as e:
        logger.error("Server crashed: %s", e, exc_info=True)
    finally:
        shutdown_event.set()


async def main():
    # Load configuration
    config_path = "/etc/ai-control-daemon/config.toml"
    if len(sys.argv) > 2 and sys.argv[1] == "--config":
        config_path = sys.argv[2]

    config = load_config(config_path)
    setup_logging(config)

    logger.info("AI Control Daemon starting...")
    check_root()

    # Detect and log session type (Wayland vs X11 vs headless)
    session = detect_session_type()

    # Auto-detect XAUTHORITY if not set or if the current path is stale.
    # On persistent USB boots, the home-dir .Xauthority from a previous
    # session persists but is invalid — LightDM regenerates auth cookies
    # each boot at /run/lightdm/<user>/:0.
    xauth_env = os.environ.get("XAUTHORITY", "")
    if not xauth_env or not Path(xauth_env).exists():
        xauth_candidates = [
            Path("/run/lightdm/root/:0"),
            Path("/run/lightdm/arch/:0"),
        ]
        # Also check home dirs as a last resort
        try:
            for user_dir in Path("/home").iterdir():
                xauth_candidates.append(user_dir / ".Xauthority")
        except (OSError, PermissionError):
            pass

        for xauth in xauth_candidates:
            if xauth.exists():
                os.environ["XAUTHORITY"] = str(xauth)
                logger.info(f"Auto-detected XAUTHORITY: {xauth}")
                break
        else:
            logger.warning("No XAUTHORITY found; X11 features may not work")

    # Auto-generate bootstrap token for AI agent on first boot
    if config.get("auth_auto_bootstrap", False) and config.get("auth_enabled", False):
        bootstrap_path = os.path.join(
            config.get("state_dir", "/var/lib/ai-control-daemon"),
            "bootstrap-token"
        )
        if not os.path.exists(bootstrap_path):
            try:
                from auth import create_token
                # Create an admin token for the AI agent
                # Trust level 900 = kernel-level access (full automation)
                # TTL = 24 hours (use /auth/refresh to extend before expiry)
                token = create_token(
                    subject_id=0, name="ai-agent",
                    trust_level=900, ttl=86400
                )
                os.makedirs(os.path.dirname(bootstrap_path), exist_ok=True)
                with open(bootstrap_path, "w") as f:
                    f.write(token)
                os.chmod(bootstrap_path, 0o600)
                logger.info("Bootstrap token created at %s", bootstrap_path)
            except Exception as e:
                logger.warning("Failed to create bootstrap token: %s", e)
        else:
            logger.info("Bootstrap token exists at %s", bootstrap_path)

    # Create FastAPI application with all control modules
    try:
        app = create_app(config)
    except ImportError as e:
        logger.critical(
            "Missing required dependency: %s. "
            "Install with: pip install fastapi uvicorn", e
        )
        sys.exit(1)
    except Exception as e:
        logger.critical("Failed to create application: %s", e, exc_info=True)
        sys.exit(1)

    # Handle shutdown gracefully
    loop = asyncio.get_running_loop()
    shutdown_event = asyncio.Event()

    def handle_signal(sig):
        logger.info(f"Received signal {sig}, shutting down...")
        shutdown_event.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, handle_signal, sig)

    # Start the API server
    host = config.get("api_host", "127.0.0.1")
    port = config.get("api_port", 8420)

    # Verify port is available before attempting to bind
    if not check_port_available(host, port):
        logger.critical("Cannot bind to %s:%d - aborting startup", host, port)
        sys.exit(1)

    logger.info(f"Starting API server on {host}:{port} (session={session})")

    server_task = asyncio.create_task(start_server(app, host, port))

    # Notify systemd we're ready (if running under systemd)
    try:
        import sdnotify
        n = sdnotify.SystemdNotifier()
        n.notify("READY=1")
    except ImportError:
        pass

    logger.info("AI Control Daemon ready - full system access enabled")

    # Wait for either shutdown signal or server crash
    server_done = asyncio.create_task(_watch_server(server_task, shutdown_event))
    await shutdown_event.wait()

    logger.info("AI Control Daemon shutting down...")
    server_task.cancel()
    server_done.cancel()
    try:
        await asyncio.wait_for(asyncio.gather(server_task, server_done, return_exceptions=True), timeout=10)
    except asyncio.TimeoutError:
        logger.warning("Server shutdown timed out after 10s")
    except Exception:
        pass
    finally:
        # Close log file handlers
        for handler in logging.getLogger().handlers[:]:
            handler.close()


if __name__ == "__main__":
    asyncio.run(main())
