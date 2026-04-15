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


def _notify_systemd(state: str) -> bool:
    """Send one datagram to systemd's NOTIFY_SOCKET (libsystemd sd_notify(3)
    protocol). Returns True on success, False when not running under
    Type=notify (NOTIFY_SOCKET unset) or if the send fails.

    Uses only stdlib (socket + os). Avoids the python-sdnotify dependency
    which is AUR-only — not available on a minimal Arch pacstrap.

    Supports both filesystem sockets (unix:/path) and abstract namespace
    sockets (@name → NUL-prefixed). Both forms are documented in
    systemd.exec(5) NOTIFY_SOCKET.
    """
    sock_path = os.environ.get("NOTIFY_SOCKET")
    if not sock_path:
        return False
    addr = "\x00" + sock_path[1:] if sock_path.startswith("@") else sock_path
    try:
        # SOCK_CLOEXEC avoids leaking the fd to any future exec()
        sock = socket.socket(socket.AF_UNIX,
                             socket.SOCK_DGRAM | socket.SOCK_CLOEXEC)
        try:
            sock.connect(addr)
            sock.sendall(state.encode("utf-8"))
            return True
        finally:
            sock.close()
    except OSError as e:
        logger.warning("sd_notify(%r) failed: %s", state, e)
        return False


def _install_sigchld_reaper():
    """Install SIGCHLD = SIG_IGN to auto-reap orphaned children.

    Session 23/24: desktop_automation.launch_app/launch_exe spawn fire-and-forget
    children via subprocess.Popen(start_new_session=True) without calling wait().
    Without this, each launch leaves a <defunct> entry in /proc until the daemon
    exits. After hundreds of /contusion/launch calls the PID table bloats and
    eventually `fork()` returns EAGAIN.

    On Linux, SIG_IGN on SIGCHLD tells the kernel to reap children automatically
    instead of delivering them as zombies. This is POSIX-specified behavior.

    Interaction with subprocess/asyncio:
    - CPython's subprocess module internally handles ECHILD on wait() via
      os.waitpid retry loops — it does NOT rely on SIGCHLD delivery.
    - asyncio on Linux 3.8+ uses ThreadedChildWatcher by default, which calls
      waitpid(pid, 0) on a dedicated thread per child. Compatible with SIG_IGN
      because it targets a specific pid (not -1), and kernel only auto-reaps
      when parent has SIG_IGN AND no one calls waitpid. Specific-pid waits win.
    - Must be installed BEFORE any subprocess is spawned (before uvicorn starts
      workers, before FastAPI routes execute, before create_app).
    """
    # Only valid on POSIX. Windows/macOS SIGCHLD+SIG_IGN is a no-op but harmless.
    try:
        signal.signal(signal.SIGCHLD, signal.SIG_IGN)
        logger.info("SIGCHLD=SIG_IGN installed — orphaned children auto-reaped by kernel")
    except (AttributeError, ValueError, OSError) as e:
        # AttributeError: SIGCHLD missing (Windows)
        # ValueError: not called from main thread
        # OSError: platform rejection
        logger.warning("Could not install SIGCHLD reaper: %s", e)


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
    # Log hardware class up-front so thermal/power orchestrators' poll-rate
    # choices are visible to operators reading the journal on boot.
    logger.info(
        "hardware_class=%s (controls thermal poll rate and observer tuning)",
        config.get("hardware_class", "unknown"),
    )
    check_root()

    # Install SIGCHLD reaper BEFORE any subprocess can be spawned.
    # Session 24: desktop_automation.launch_app/launch_exe fire-and-forget
    # children accumulate as zombies without this. Must come before create_app
    # and before any async task that could spawn a child.
    _install_sigchld_reaper()

    # Round 32: pre-create cgroup v2 slice directories so the first
    # /contusion/launch invocation doesn't pay a systemd lazy-instantiation
    # cost.  Idempotent; logs and continues on systems without cgroup v2.
    try:
        from cgroup import ensure_slices
        ensure_slices()
    except Exception as e:  # pylint: disable=broad-except
        logger.debug("cgroup slice pre-creation skipped: %s", e)

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

    # Direct-HW routers: GPU enumeration/PRIME + input aggregator.
    # Mounted post-create_app so api_server.py does not need to import them.
    # Each router is fault-isolated: import errors are logged and the daemon
    # continues without that specific endpoint group.
    try:
        import gpu as _gpu_mod
        _gpu_router = _gpu_mod.build_router()
        if _gpu_router is not None:
            app.include_router(_gpu_router)
            logger.info("GPU router mounted at /gpu")
    except Exception as e:
        logger.warning("GPU router unavailable: %s", e)

    try:
        import input as _input_mod
        _input_router = _input_mod.build_router()
        if _input_router is not None:
            app.include_router(_input_router)
            logger.info("Input router mounted at /input")
    except Exception as e:
        logger.warning("Input router unavailable: %s", e)

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

    # Event set by start_server() once uvicorn has bound + lifespan.startup
    # has completed. Gates systemd READY=1 so the Type=notify contract
    # reflects real HTTP-accepting state, not just "python is running".
    uvicorn_ready = asyncio.Event()
    server_task = asyncio.create_task(start_server(app, host, port, ready_event=uvicorn_ready))

    # Wait (bounded) for uvicorn to actually start accepting connections
    # before notifying systemd. On cold boot this is typically <1s;
    # 60s timeout accommodates slow I/O (QEMU TCG, 1GB Pentium 4).
    try:
        await asyncio.wait_for(uvicorn_ready.wait(), timeout=60.0)
    except asyncio.TimeoutError:
        logger.critical("uvicorn did not signal startup within 60s — aborting")
        server_task.cancel()
        sys.exit(1)

    # Notify systemd we're ready (if running under systemd with Type=notify).
    # Uses the native NOTIFY_SOCKET protocol directly — same as libsystemd's
    # sd_notify(3). We don't depend on python-sdnotify (AUR-only; not in
    # Arch core/extra) so this works on a minimal pacstrap.
    _sent = _notify_systemd("READY=1")
    if _sent:
        logger.info("Sent READY=1 to systemd (Type=notify)")
    else:
        logger.debug("NOTIFY_SOCKET not set; not running under systemd Type=notify")

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
