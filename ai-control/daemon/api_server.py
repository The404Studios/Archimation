"""
API Server - REST + WebSocket interface for AI control.

Exposes all control modules via HTTP endpoints on port 8420.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

import asyncio
import glob
import ipaddress
import json
import logging
import os
import time
from typing import Optional

logger = logging.getLogger("ai-control.api")

_start_time = time.time()

# Lazy imports to handle missing dependencies gracefully
_keyboard = None
_mouse = None
_screen = None
_system = None
_network = None
_filesystem = None
_firewall = None
_win_services = None
_trust_observer = None
_audit = None
_desktop = None
_llm = None
_compositor = None
_contusion = None
_scanner = None
_stub_discovery = None
_memory_observer = None
_memory_diff = None
_binary_signatures = None
_stub_generator = None
_behavioral_model = None
_win_api_db = None
_syscall_translator = None
_syscall_monitor = None
_thermal = None
_power = None
# S74 agents 6+7 + integration finding #1
_active_inference = None
_entropy_observer = None
_assembly_index = None
_algedonic_reader = None
# S75 Agent B: library_census ecosystem observer (Maturana-Varela Criterion 1).
_library_census = None
# S75 Agent C: Monte-Carlo cortex sampler (research-A §2.6, roadmap §1.2.4).
_monte_carlo = None


def _init_controllers(config: dict):
    """Initialize all control modules. Each controller is fault-isolated."""
    global _keyboard, _mouse, _screen, _system, _network, _filesystem
    global _firewall, _win_services, _trust_observer, _audit, _desktop
    global _llm, _compositor, _contusion, _scanner, _stub_discovery
    global _memory_observer, _memory_diff, _binary_signatures
    global _stub_generator, _behavioral_model, _win_api_db
    global _syscall_translator, _syscall_monitor
    global _thermal, _power
    global _active_inference, _entropy_observer, _assembly_index
    global _algedonic_reader
    global _library_census
    global _monte_carlo

    def _safe_init(name, factory):
        try:
            return factory()
        except Exception as e:
            logger.error("Failed to initialize %s: %s", name, e)
            return None

    def _import_and_init(name, import_path, class_name, factory=None):
        try:
            mod = __import__(import_path)
            cls = getattr(mod, class_name)
            return _safe_init(name, factory if factory else cls)
        except Exception as e:
            logger.error("Failed to load %s: %s", name, e)
            return None

    _keyboard = _import_and_init("keyboard", "keyboard", "KeyboardController")
    _mouse = _import_and_init("mouse", "mouse", "MouseController")
    _screen = _import_and_init("screen", "screen", "ScreenCapture",
                               lambda: __import__("screen").ScreenCapture(config.get("screen_capture_method", "auto")))
    _system = _import_and_init("system", "system", "SystemController")
    _network = _import_and_init("network", "network", "NetworkController")
    _filesystem = _import_and_init("filesystem", "filesystem", "FilesystemController")
    _firewall = _import_and_init("firewall", "firewall", "FirewallController")
    _win_services = _import_and_init("win_services", "services", "WindowsServiceController")
    _trust_observer = _import_and_init("trust_observer", "trust_observer", "TrustObserver",
                                        lambda: __import__("trust_observer").TrustObserver(
                                            poll_interval=config.get("trust_poll_interval", 1.0),
                                            oscillation_window=config.get("trust_oscillation_window", 10.0),
                                            oscillation_threshold=config.get("trust_oscillation_threshold", 4),
                                            freeze_duration=config.get("trust_freeze_duration", 30.0),
                                        ))
    _audit = _import_and_init("audit", "audit", "AuditLogger")
    _desktop = _import_and_init("desktop", "desktop_automation", "DesktopAutomation")

    # LLM controller (module-level functions, no class)
    try:
        import llm as llm_mod
        _llm = llm_mod
    except Exception as e:
        logger.warning("LLM controller unavailable: %s", e)
        _llm = None

    # Compositor controller (module-level functions, no class)
    try:
        import compositor as compositor_mod
        _compositor = compositor_mod
    except Exception as e:
        logger.warning("Compositor controller unavailable: %s", e)
        _compositor = None

    # Contusion automation engine
    try:
        from contusion import Contusion
        _contusion = Contusion()
    except Exception as e:
        logger.warning("Contusion engine unavailable: %s", e)
        _contusion = None

    # Pattern scanner (memory pattern matching engine)
    if config.get("scanner_enabled", True):
        try:
            from pattern_scanner import MemoryScanner, PatternDatabase
            _pattern_db = PatternDatabase(
                db_path=config.get("scanner_patterns_dir", "/var/lib/ai-control/patterns"),
            )
            _scanner = MemoryScanner(db=_pattern_db)
            logger.info("Pattern scanner initialized with %d patterns",
                        len(_scanner.db.patterns))
        except Exception as e:
            logger.error("Failed to init pattern scanner: %s", e)
            _scanner = None
    else:
        logger.info("Pattern scanner disabled by config")
        _scanner = None

    # Stub discovery engine (auto-detect unimplemented Windows APIs)
    if config.get("scanner_enabled", True):
        try:
            from stub_discovery import StubDiscoveryEngine
            _stub_discovery = StubDiscoveryEngine()
            logger.info("Stub discovery engine initialized")
        except Exception as e:
            logger.error("Failed to init stub discovery: %s", e)
            _stub_discovery = None
    else:
        logger.info("Stub discovery engine disabled by config")
        _stub_discovery = None

    # Memory observer (PE memory translator)
    try:
        from memory_observer import MemoryObserver
        _memory_observer = MemoryObserver(
            poll_interval=config.get("memory_poll_interval", 5.0),
            process_ttl=config.get("memory_process_ttl", 300.0),
            max_processes=config.get("memory_max_processes", 512),
        )
        logger.info("Memory observer initialized")
    except Exception as e:
        logger.error("Failed to init memory observer: %s", e)
        _memory_observer = None

    # Memory diff engine (snapshot capture and comparison)
    try:
        from memory_diff import MemoryDiffEngine
        _memory_diff = MemoryDiffEngine(
            max_snapshots_per_pid=config.get("memory_diff_max_snapshots", 20),
        )
        logger.info("Memory diff engine initialized")
    except Exception as e:
        logger.error("Failed to init memory diff engine: %s", e)
        _memory_diff = None

    # Binary signature database (PE identification and dependency profiles)
    try:
        from binary_signatures import BinarySignatureDB
        _binary_signatures = BinarySignatureDB(
            db_path=config.get("signatures_db_path", "/var/lib/ai-control/signatures"),
        )
        logger.info("Binary signature DB initialized with %d profiles",
                     len(_binary_signatures._profiles))
    except Exception as e:
        logger.error("Failed to init binary signature DB: %s", e)
        _binary_signatures = None

    # Stub generator (auto-generates C implementations for Windows API stubs)
    try:
        from stub_generator import StubGenerator
        _stub_generator = StubGenerator(
            output_dir=config.get("stub_generator_output_dir", "/tmp/generated-stubs"),
        )
        logger.info("Stub generator initialized (output: %s)", _stub_generator.output_dir)
    except Exception as e:
        logger.error("Failed to init stub generator: %s", e)
        _stub_generator = None

    # Behavioral model engine (AI analysis of PE process behavior)
    try:
        from behavioral_model import BehavioralModelEngine
        _behavioral_model = BehavioralModelEngine()
        logger.info("Behavioral model engine initialized")
    except Exception as e:
        logger.error("Failed to init behavioral model engine: %s", e)
        _behavioral_model = None

    # Windows API signature database (for auto-stub generator)
    try:
        from win_api_db import WinApiDatabase
        _win_api_db = WinApiDatabase(
            db_path=config.get("win_api_db_path", "/var/lib/ai-control/win_api_db.json"),
        )
        logger.info("Win API database initialized with %d signatures", len(_win_api_db))
    except Exception as e:
        logger.error("Failed to init Win API database: %s", e)
        _win_api_db = None

    # Syscall-to-WinAPI translator (always available -- pure lookup tables)
    try:
        from syscall_translator import SyscallTranslator
        _syscall_translator = SyscallTranslator()
        stats = _syscall_translator.get_stats()
        logger.info("Syscall translator initialized (%d Linux + %d NT syscalls, %d IOCTLs)",
                    stats["linux_syscalls_mapped"],
                    stats["nt_syscalls_mapped"],
                    stats["known_ioctls"])
    except Exception as e:
        logger.error("Failed to init syscall translator: %s", e)
        _syscall_translator = None

    # Syscall monitor (live PE process syscall tracing and behavioral analysis)
    try:
        from syscall_monitor import SyscallMonitor
        _syscall_monitor = SyscallMonitor(
            poll_interval=config.get("syscall_poll_interval", 2.0),
            process_ttl=config.get("syscall_process_ttl", 300.0),
            max_processes=config.get("syscall_max_processes", 512),
        )
        logger.info("Syscall monitor initialized")
    except Exception as e:
        logger.error("Failed to init syscall monitor: %s", e)
        _syscall_monitor = None

    # Thermal + power orchestrators. These depend on memory_observer +
    # pattern_scanner references (for throttle-on-hot) so they must be
    # constructed AFTER those modules above.
    try:
        from thermal import ThermalOrchestrator
        _thermal = ThermalOrchestrator(
            hardware_class=config.get("hardware_class", "mid"),
        )
        logger.info(
            "Thermal orchestrator initialized (hw=%s, msr=%s, gpu=%s)",
            _thermal.hardware_class, _thermal.msr_available,
            _thermal.gpu_vendor or "none",
        )
    except Exception as e:
        logger.error("Failed to init thermal orchestrator: %s", e)
        _thermal = None

    try:
        from power import PowerOrchestrator
        _power = PowerOrchestrator(
            thermal_orchestrator=_thermal,
            hardware_class=config.get("hardware_class", "mid"),
            memory_observer=_memory_observer,
            scanner=_scanner,
        )
        logger.info(
            "Power orchestrator initialized (baseline=%s)",
            _power.baseline_governor or "auto",
        )
    except Exception as e:
        logger.error("Failed to init power orchestrator: %s", e)
        _power = None


def create_app(config: dict):
    """Create the FastAPI application."""
    try:
        from contextlib import asynccontextmanager
        from fastapi import FastAPI, HTTPException
        from fastapi.responses import JSONResponse, Response
        from pydantic import BaseModel, Field
    except ImportError:
        logger.error("FastAPI not installed. Install with: pip install fastapi uvicorn")
        raise

    _init_controllers(config)

    # Event loop reference for thread-safe WebSocket broadcasts from trust observer
    _main_loop: Optional[asyncio.AbstractEventLoop] = None
    # WebSocket client tracking (declared here so lifespan shutdown can access them)
    _ws_clients: set = set()
    _ws_queues: dict = {}  # ws -> asyncio.Queue
    _WS_QUEUE_MAX = 64  # max queued messages per client; oldest dropped when full
    # Strong references to fire-and-forget broadcast tasks so the GC does not
    # collect them mid-run. Each task auto-removes itself on completion.
    _bg_broadcast_tasks: set = set()
    # Shared aiohttp client session for cortex proxy (lifespan shutdown closes it)
    _cortex_session_holder: dict = {"session": None, "aiohttp": None}

    @asynccontextmanager
    async def lifespan(app):
        nonlocal _main_loop
        # Capture the event loop reference for thread-safe WebSocket broadcasts
        _main_loop = asyncio.get_running_loop()
        # Startup
        if _trust_observer:
            try:
                await _trust_observer.start_async()
            except Exception as e:
                logger.error("Trust observer failed to start: %s (continuing without it)", e)
        if _memory_observer:
            try:
                await _memory_observer.start()
            except Exception as e:
                logger.error("Memory observer failed to start: %s (continuing without it)", e)
        if _syscall_monitor:
            try:
                await _syscall_monitor.start()
            except Exception as e:
                logger.error("Syscall monitor failed to start: %s (continuing without it)", e)
        if _thermal:
            try:
                await _thermal.start()
            except Exception as e:
                logger.error("Thermal orchestrator failed to start: %s (continuing without it)", e)
        if _power:
            try:
                await _power.start()
            except Exception as e:
                logger.error("Power orchestrator failed to start: %s (continuing without it)", e)
        # S74 integration: algedonic_reader drains /dev/trust_algedonic.
        # Graceful if the device is absent (WSL/QEMU/no trust.ko).
        if _algedonic_reader:
            try:
                await _algedonic_reader.start()
            except Exception as e:
                logger.error(
                    "Algedonic reader failed to start: %s "
                    "(continuing without it)", e
                )
        # S75 Agent B: library_census polls memory_observer DLL maps and
        # publishes cross-PID histograms. Runs in a background thread so
        # the asyncio loop is untouched.
        if _library_census:
            try:
                _library_census.start_polling(_library_census._poll_interval)
            except Exception as e:
                logger.error(
                    "Library census failed to start: %s "
                    "(continuing without it)", e
                )
        yield
        # Shutdown: close all WebSocket clients, then stop trust observer
        for ws in list(_ws_clients):
            try:
                await ws.close(code=1001)
            except Exception:
                pass
        _ws_clients.clear()
        _ws_queues.clear()
        # Stop power/thermal BEFORE observers so PowerOrchestrator can revert
        # the poll-interval mutations it applied on throttle entry.
        if _power:
            try:
                await _power.stop()
            except Exception as e:
                logger.error("Power orchestrator failed to stop cleanly: %s", e)
        if _thermal:
            try:
                await _thermal.stop()
            except Exception as e:
                logger.error("Thermal orchestrator failed to stop cleanly: %s", e)
        if _syscall_monitor:
            try:
                await _syscall_monitor.stop()
            except Exception as e:
                logger.error("Syscall monitor failed to stop cleanly: %s", e)
        if _memory_observer:
            try:
                await _memory_observer.stop()
            except Exception as e:
                logger.error("Memory observer failed to stop cleanly: %s", e)
        if _trust_observer:
            try:
                await _trust_observer.stop()
            except Exception as e:
                logger.error("Trust observer failed to stop cleanly: %s", e)
        # S74 integration: stop algedonic reader + cortex agent cleanly.
        if _algedonic_reader:
            try:
                await _algedonic_reader.stop()
            except Exception as e:
                logger.error("Algedonic reader failed to stop cleanly: %s", e)
        # S75 Agent B: library_census polling thread shutdown.
        if _library_census:
            try:
                _library_census.stop_polling()
            except Exception as e:
                logger.error("Library census failed to stop cleanly: %s", e)
        if _active_inference:
            try:
                _active_inference.stop()
            except Exception as e:
                logger.error("Active inference failed to stop cleanly: %s", e)
        # Close uinput devices to prevent resource leaks
        if _keyboard:
            try:
                _keyboard.close()
            except Exception as e:
                logger.error("Keyboard controller failed to close: %s", e)
        if _mouse:
            try:
                _mouse.close()
            except Exception as e:
                logger.error("Mouse controller failed to close: %s", e)
        # Close the shared cortex aiohttp session (opened lazily; may be None).
        _cx_session = _cortex_session_holder.get("session")
        if _cx_session is not None and not _cx_session.closed:
            try:
                await _cx_session.close()
            except Exception as e:
                logger.debug("cortex session close failed: %s", e)

    app = FastAPI(
        title="AI Control Daemon",
        description="Full system control API for AI agents",
        version="0.1.0",
        lifespan=lifespan,
    )

    # CORS middleware for local tools (control panel, web UI)
    try:
        from fastapi.middleware.cors import CORSMiddleware
        app.add_middleware(
            CORSMiddleware,
            # allow_origins does NOT support globs; use regex instead
            allow_origin_regex=r"^https?://(127\.0\.0\.1|localhost)(:\d+)?$",
            allow_methods=["*"],
            allow_headers=["*"],
        )
    except ImportError:
        logger.warning("CORS middleware not available")

    # ---- S74 cortex + observer integration (agents 6, 7 + Finding #1) ----
    #
    # Agent 6 (active_inference.py) uses trust_observer + memory_observer to
    # build a generative-model belief over the authority landscape and picks
    # actions by expected free energy minimisation. Agents 7 (entropy and
    # assembly) feed it Shannon / Assembly-Theory priors. Finding #1 closes
    # the producer-without-consumer loop on /dev/trust_algedonic.
    #
    # Registration order: entropy + assembly BEFORE active_inference so the
    # cortex can subscribe to their emissions through the shared bus.
    # Everything is fault-isolated: a failure in any one module leaves the
    # rest of the daemon functional.
    global _active_inference, _entropy_observer, _assembly_index
    global _algedonic_reader
    global _library_census

    # The daemon does not currently operate a cortex event_bus in-process
    # (that bus lives in ai-control/cortex/event_bus.py and may be remote).
    # For observer publishing we use the existing _broadcast_trust_event
    # WebSocket fan-out as a best-effort sink.  When the in-process event
    # bus lands (S75), wire it here.
    _daemon_event_sink = None  # Wired after _broadcast_trust_event is defined

    try:
        from entropy_observer import register_with_daemon as _reg_entropy
        _entropy_observer = _reg_entropy(
            app, _daemon_event_sink, trust_observer=_trust_observer,
        )
        logger.info("entropy_observer registered with daemon")
    except Exception as e:
        logger.error("Failed to register entropy_observer: %s", e)
        _entropy_observer = None

    try:
        from assembly_index import register_with_daemon as _reg_assembly
        _assembly_index = _reg_assembly(
            app, _daemon_event_sink, trust_observer=_trust_observer,
        )
        logger.info("assembly_index registered with daemon")
    except Exception as e:
        logger.error("Failed to register assembly_index: %s", e)
        _assembly_index = None

    try:
        # active_inference lives under ai-control/cortex/ so we have to
        # adjust sys.path before importing.
        import sys as _sys
        from pathlib import Path as _P
        _cortex_dir = str(_P(__file__).resolve().parent.parent / "cortex")
        if _cortex_dir not in _sys.path:
            _sys.path.insert(0, _cortex_dir)

        # S75 follow-up: register library_census BEFORE active_inference so the
        # cortex has the ecosystem census handle from start (BeliefState reads
        # library_census.snapshot() on every observation).
        try:
            from library_census import register_with_daemon as _reg_lc
            _library_census = _reg_lc(
                app, _daemon_event_sink, memory_observer=_memory_observer,
                poll_interval=config.get("library_census_poll_interval", 5.0),
            )
            logger.info("library_census registered with daemon")
        except Exception as e:
            logger.error("Failed to register library_census: %s", e)
            _library_census = None

        from active_inference import register_with_daemon as _reg_ai
        _active_inference = _reg_ai(
            app,
            {
                "trust_observer": _trust_observer,
                "memory_observer": _memory_observer,
                "event_bus": _daemon_event_sink,
                "library_census": _library_census,
            },
        )
        logger.info("active_inference registered with daemon")
    except Exception as e:
        logger.error("Failed to register active_inference: %s", e)
        _active_inference = None

    try:
        from algedonic_reader import register_with_daemon as _reg_alg
        _algedonic_reader = _reg_alg(
            app, _daemon_event_sink, cortex=_active_inference,
        )
        logger.info("algedonic_reader registered with daemon")
    except Exception as e:
        logger.error("Failed to register algedonic_reader: %s", e)
        _algedonic_reader = None

    # S75 Agent C: Monte-Carlo cortex.  Installs shared samplers
    # (ConfidenceSampler / RolloutSearch / FaultInjector /
    # StochasticRateLimiter) and registers:
    #   * GET  /metrics/monte_carlo
    #   * POST /cortex/monte_carlo/rollout
    # Best-effort: a failure here does not disrupt other controllers.
    global _monte_carlo
    try:
        from monte_carlo import (
            register_with_daemon as _reg_mc,
            get_confidence_sampler as _get_cs,
        )
        _monte_carlo = _reg_mc(app, _daemon_event_sink)
        # Attach the shared confidence sampler to any reachable DecisionEngine
        # singleton. Best-effort: if decision_engine exposes no default
        # instance we skip silently; the /cortex/monte_carlo/rollout endpoint
        # still works.
        try:
            import decision_engine as _de_mod  # type: ignore
            cs = _get_cs()
            eng = getattr(_de_mod, "_default_engine", None)
            if eng is not None and cs is not None and hasattr(eng, "set_confidence_sampler"):
                eng.set_confidence_sampler(cs)
        except Exception:
            pass
        logger.info("monte_carlo registered with daemon")
    except Exception as e:
        logger.error("Failed to register monte_carlo: %s", e)
        _monte_carlo = None

    # Log controller status
    _controllers = {
        "keyboard": _keyboard, "mouse": _mouse, "screen": _screen,
        "system": _system, "network": _network, "filesystem": _filesystem,
        "firewall": _firewall, "win_services": _win_services,
        "trust_observer": _trust_observer, "audit": _audit,
        "desktop": _desktop, "llm": _llm, "compositor": _compositor,
        "contusion": _contusion, "scanner": _scanner,
        "stub_discovery": _stub_discovery, "memory_observer": _memory_observer,
        "memory_diff": _memory_diff,
        "binary_signatures": _binary_signatures,
        "stub_generator": _stub_generator,
        "win_api_db": _win_api_db,
        "syscall_translator": _syscall_translator,
        "syscall_monitor": _syscall_monitor,
        "behavioral_model": _behavioral_model,
        "thermal": _thermal,
        "power": _power,
        # S74 integration
        "active_inference": _active_inference,
        "entropy_observer": _entropy_observer,
        "assembly_index": _assembly_index,
        "algedonic_reader": _algedonic_reader,
        # S75 Agent B
        "library_census": _library_census,
        # S75 Agent C
        "monte_carlo": _monte_carlo,
    }
    loaded = [n for n, c in _controllers.items() if c is not None]
    failed = [n for n, c in _controllers.items() if c is None]
    logger.info("Controllers loaded: %s", ", ".join(loaded) if loaded else "none")
    if failed:
        logger.warning("Controllers failed: %s", ", ".join(failed))

    def _require(controller, name: str):
        """Raise 503 if a controller is not available."""
        if controller is None:
            from fastapi import HTTPException
            raise HTTPException(status_code=503, detail=f"{name} not available")
        return controller

    # --- Auth middleware (enabled by default for security) ---
    if config.get("auth_enabled", True):
        from starlette.middleware.base import BaseHTTPMiddleware
        from starlette.requests import Request as StarletteRequest
        from auth import check_auth

        class TrustAuthMiddleware(BaseHTTPMiddleware):
            async def dispatch(self, request: StarletteRequest, call_next):
                token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip() or None
                client_ip = request.client.host if request.client else "unknown"
                allowed, identity, reason = check_auth(
                    request.url.path, request.method, token, _trust_observer,
                    client_ip=client_ip,
                )
                if not allowed:
                    status = 429 if reason == "rate_limited" else 403
                    if _audit:
                        _audit.log_auth_failure(
                            request.method, request.url.path, reason,
                            subject_id=identity.subject_id if identity else None,
                            subject_name=identity.name if identity else None,
                        )
                    return JSONResponse(
                        status_code=status,
                        content={"error": "forbidden", "reason": reason},
                    )
                # Attach identity to request state for audit
                request.state.identity = identity
                response = await call_next(request)
                # Audit successful request
                if _audit:
                    _audit.log(
                        method=request.method,
                        path=request.url.path,
                        subject_id=identity.subject_id if identity else None,
                        subject_name=identity.name if identity else None,
                        result="success",
                        status_code=response.status_code,
                    )
                return response

        app.add_middleware(TrustAuthMiddleware)

    # --- Pydantic Models ---

    class TypeTextRequest(BaseModel):
        text: str
        delay: float = Field(default=0.02, ge=0.0, le=1.0)

    class KeyRequest(BaseModel):
        key: str

    class KeyComboRequest(BaseModel):
        keys: list[str]

    class MouseMoveRequest(BaseModel):
        x: int
        y: int

    class MouseClickRequest(BaseModel):
        x: Optional[int] = None
        y: Optional[int] = None
        button: str = "left"

    class MouseDragRequest(BaseModel):
        from_x: int
        from_y: int
        to_x: int
        to_y: int
        button: str = "left"

    class ScrollRequest(BaseModel):
        amount: int
        horizontal: bool = False

    class ScreenRegionRequest(BaseModel):
        x: int
        y: int
        width: int
        height: int

    class CommandRequest(BaseModel):
        command: str
        timeout: int = Field(default=60, ge=1, le=3600)

    class PackageRequest(BaseModel):
        package: str

    class ServiceRequest(BaseModel):
        service: str

    class WifiConnectRequest(BaseModel):
        ssid: str
        password: Optional[str] = None

    class PingRequest(BaseModel):
        host: str
        count: int = Field(default=4, ge=1, le=100)

    class FileReadRequest(BaseModel):
        path: str
        encoding: str = "utf-8"

    class FileWriteRequest(BaseModel):
        path: str
        content: str
        encoding: str = "utf-8"

    class FileListRequest(BaseModel):
        path: str

    class FileDeleteRequest(BaseModel):
        path: str

    class FileMkdirRequest(BaseModel):
        path: str

    class AddPatternRequest(BaseModel):
        id: str
        bytes_hex: str
        category: str
        description: str
        severity: str = "info"
        metadata: dict = {}

    # --- Health ---

    @app.get("/health")
    async def health():
        return {
            "status": "ok",
            "daemon": "ai-control",
            "version": "0.1.0",
            "scanner": _scanner is not None,
            "memory_observer": _memory_observer is not None,
            "memory_diff": _memory_diff is not None,
            "stub_discovery": _stub_discovery is not None,
            "binary_signatures": _binary_signatures is not None,
            "win_api_db": _win_api_db is not None,
            "stub_generator": _stub_generator is not None,
            "syscall_monitor": _syscall_monitor is not None,
            "syscall_translator": _syscall_translator is not None,
            "behavioral_model": _behavioral_model is not None,
            "thermal": _thermal is not None,
            "power": _power is not None,
        }

    @app.get("/diagnostics")
    async def diagnostics():
        """Full system diagnostics across all 5 architecture layers."""
        try:
            from diagnostics import run_full_diagnostics
        except ImportError:
            return {"overall": "error", "detail": "diagnostics module not installed"}
        try:
            report = await run_full_diagnostics()
            return report
        except Exception as e:
            logger.error("Diagnostics failed: %s", e)
            return {"overall": "error", "detail": str(e)}

    @app.get("/system/overview")
    async def system_overview():
        """Quick system overview (controllers, platform, version)."""
        info = {}
        try:
            import platform
            info["hostname"] = platform.node()
            info["platform"] = platform.platform()
            info["python"] = platform.python_version()
        except Exception:
            pass
        info["controllers"] = {
            n: (c is not None) for n, c in _controllers.items()
        }
        info["api_version"] = "0.1.0"
        return info

    # /system/summary is served by the factory router registered below
    # (see system_summary.make_summary_router). The inline implementation
    # was removed in favour of the unit-tested, pure-introspection module.

    # --- Keyboard ---

    @app.post("/keyboard/type")
    async def keyboard_type(req: TypeTextRequest):
        kb = _require(_keyboard, "keyboard")
        success = kb.type_text(req.text, req.delay)
        return {"success": success}

    @app.post("/keyboard/press")
    async def keyboard_press(req: KeyRequest):
        kb = _require(_keyboard, "keyboard")
        success = kb.press_key(req.key)
        return {"success": success}

    @app.post("/keyboard/release")
    async def keyboard_release(req: KeyRequest):
        kb = _require(_keyboard, "keyboard")
        success = kb.release_key(req.key)
        return {"success": success}

    @app.post("/keyboard/tap")
    async def keyboard_tap(req: KeyRequest):
        kb = _require(_keyboard, "keyboard")
        kb.tap_key(req.key)
        return {"success": True}

    @app.post("/keyboard/combo")
    async def keyboard_combo(req: KeyComboRequest):
        kb = _require(_keyboard, "keyboard")
        kb.key_combo(*req.keys)
        return {"success": True}

    # --- Mouse ---

    @app.post("/mouse/move")
    async def mouse_move(req: MouseMoveRequest):
        m = _require(_mouse, "mouse")
        success = m.move_to(req.x, req.y)
        return {"success": success}

    @app.post("/mouse/click")
    async def mouse_click(req: MouseClickRequest):
        m = _require(_mouse, "mouse")
        if req.x is not None and req.y is not None:
            m.click_at(req.x, req.y, req.button)
        else:
            m.click(req.button)
        return {"success": True}

    @app.post("/mouse/double_click")
    async def mouse_double_click(req: MouseClickRequest):
        m = _require(_mouse, "mouse")
        if req.x is not None and req.y is not None:
            m.move_to(req.x, req.y)
        m.double_click(req.button)
        return {"success": True}

    @app.post("/mouse/drag")
    async def mouse_drag(req: MouseDragRequest):
        m = _require(_mouse, "mouse")
        success = m.drag(req.from_x, req.from_y, req.to_x, req.to_y, req.button)
        return {"success": success}

    @app.post("/mouse/scroll")
    async def mouse_scroll(req: ScrollRequest):
        m = _require(_mouse, "mouse")
        success = m.scroll(req.amount, req.horizontal)
        return {"success": success}

    # --- Screen ---

    @app.get("/screen/capture")
    async def screen_capture():
        sc = _require(_screen, "screen")
        # Screen capture runs sync subprocess (scrot/grim) -- offload to thread pool
        data = await asyncio.get_running_loop().run_in_executor(None, sc.capture_full)
        if data:
            return Response(content=data, media_type="image/png")
        raise HTTPException(status_code=500, detail="Screen capture failed")

    @app.get("/screen/capture/base64")
    async def screen_capture_base64():
        sc = _require(_screen, "screen")
        b64 = await asyncio.get_running_loop().run_in_executor(None, sc.capture_base64)
        if b64:
            return {"image": b64}
        raise HTTPException(status_code=500, detail="Screen capture failed")

    @app.post("/screen/capture/region")
    async def screen_capture_region(req: ScreenRegionRequest):
        sc = _require(_screen, "screen")
        loop = asyncio.get_running_loop()
        data = await loop.run_in_executor(
            None, sc.capture_region, req.x, req.y, req.width, req.height
        )
        if data:
            return Response(content=data, media_type="image/png")
        raise HTTPException(status_code=500, detail="Region capture failed")

    @app.get("/screen/size")
    async def screen_size():
        sc = _require(_screen, "screen")
        w, h = await asyncio.get_running_loop().run_in_executor(None, sc.get_screen_size)
        return {"width": w, "height": h}

    # --- System ---

    @app.get("/system/info")
    async def system_info():
        s = _require(_system, "system")
        return await s.get_system_info()

    @app.post("/system/command")
    async def system_command(req: CommandRequest):
        s = _require(_system, "system")
        return await s.run_command(req.command, req.timeout)

    @app.get("/system/processes")
    async def system_processes():
        s = _require(_system, "system")
        return await s.list_processes()

    @app.post("/system/kill/{pid}")
    async def system_kill(pid: int):
        s = _require(_system, "system")
        success = s.kill_process(pid)
        return {"success": success}

    # --- Packages ---

    @app.post("/packages/install")
    async def package_install(req: PackageRequest):
        s = _require(_system, "system")
        return await s.install_package(req.package)

    @app.post("/packages/remove")
    async def package_remove(req: PackageRequest):
        s = _require(_system, "system")
        return await s.remove_package(req.package)

    @app.post("/packages/update")
    async def package_update():
        s = _require(_system, "system")
        return await s.update_system()

    @app.get("/packages/search/{query}")
    async def package_search(query: str):
        s = _require(_system, "system")
        return await s.search_packages(query)

    @app.get("/packages/installed")
    async def packages_installed():
        s = _require(_system, "system")
        return await s.list_installed()

    @app.get("/system/updates")
    async def check_updates():
        s = _require(_system, "system")
        updates = await s.check_updates()
        return {"status": "ok", "count": len(updates), "updates": updates}

    # --- Services ---

    @app.get("/services")
    async def services_list():
        s = _require(_system, "system")
        return await s.list_services()

    @app.post("/services/start")
    async def service_start(req: ServiceRequest):
        s = _require(_system, "system")
        return await s.start_service(req.service)

    @app.post("/services/stop")
    async def service_stop(req: ServiceRequest):
        s = _require(_system, "system")
        return await s.stop_service(req.service)

    @app.post("/services/restart")
    async def service_restart(req: ServiceRequest):
        s = _require(_system, "system")
        return await s.restart_service(req.service)

    @app.get("/services/status/{service}")
    async def service_status(service: str):
        s = _require(_system, "system")
        return await s.service_status(service)

    # --- Network ---

    @app.get("/network/connections")
    async def network_connections():
        n = _require(_network, "network")
        return await n.get_connections()

    @app.get("/network/wifi")
    async def network_wifi():
        n = _require(_network, "network")
        return await n.get_wifi_list()

    @app.get("/network/wifi/scan")
    async def network_wifi_scan():
        """Scan for available WiFi networks with full details."""
        n = _require(_network, "network")
        return await n.wifi_scan()

    @app.post("/network/wifi/connect")
    async def network_wifi_connect(req: WifiConnectRequest):
        """Connect to a WiFi network."""
        n = _require(_network, "network")
        return await n.connect_wifi(req.ssid, req.password)

    @app.post("/network/wifi/disconnect")
    async def network_wifi_disconnect():
        """Disconnect from the current WiFi network."""
        n = _require(_network, "network")
        return await n.disconnect_wifi()

    @app.get("/network/wifi/saved")
    async def network_wifi_saved():
        """List saved/known WiFi connections."""
        n = _require(_network, "network")
        return await n.wifi_saved()

    @app.delete("/network/wifi/saved/{name}")
    async def network_wifi_forget(name: str):
        """Forget a saved WiFi network."""
        n = _require(_network, "network")
        return await n.wifi_forget(name)

    @app.get("/network/wifi/status")
    async def network_wifi_status():
        """Get current WiFi connection status."""
        n = _require(_network, "network")
        return await n.wifi_status()

    @app.get("/network/ip")
    async def network_ip():
        n = _require(_network, "network")
        return await n.get_ip_addresses()

    @app.get("/network/routes")
    async def network_routes():
        n = _require(_network, "network")
        return await n.get_routes()

    @app.get("/network/dns")
    async def network_dns():
        n = _require(_network, "network")
        return await n.get_dns_servers()

    @app.post("/network/ping")
    async def network_ping(req: PingRequest):
        n = _require(_network, "network")
        return await n.ping(req.host, req.count)

    # --- Filesystem ---

    @app.post("/filesystem/read")
    async def filesystem_read(req: FileReadRequest):
        fs = _require(_filesystem, "filesystem")
        # Sync file I/O -- offload to thread pool to avoid blocking event loop
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, fs.read_file, req.path, req.encoding)

    @app.post("/filesystem/write")
    async def filesystem_write(req: FileWriteRequest):
        fs = _require(_filesystem, "filesystem")
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, fs.write_file, req.path, req.content, req.encoding
        )

    @app.post("/filesystem/list")
    async def filesystem_list(req: FileListRequest):
        fs = _require(_filesystem, "filesystem")
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, fs.list_directory, req.path)

    @app.post("/filesystem/delete")
    async def filesystem_delete(req: FileDeleteRequest):
        fs = _require(_filesystem, "filesystem")
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, fs.delete_file, req.path)

    @app.post("/filesystem/mkdir")
    async def filesystem_mkdir(req: FileMkdirRequest):
        fs = _require(_filesystem, "filesystem")
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, fs.create_directory, req.path)

    # --- Firewall ---

    class FirewallRuleRequest(BaseModel):
        chain: str = "input_filter"
        # rule is the raw nft expression. If omitted, the handler builds
        # a rule from (protocol, port, remote_address, direction). The
        # old required-string schema made the structured form unreachable
        # because Pydantic 422'd before the handler could construct it.
        rule: Optional[str] = None
        direction: str = "inbound"
        protocol: str = "any"
        port: Optional[int] = None
        remote_address: Optional[str] = None

    @app.get("/firewall/status")
    async def firewall_status():
        fw = _require(_firewall, "firewall")
        return await fw.get_status()

    @app.get("/firewall/rules")
    async def firewall_rules():
        fw = _require(_firewall, "firewall")
        return await fw.list_rules()

    @app.post("/firewall/rules")
    async def firewall_add_rule(req: FirewallRuleRequest):
        # Build nft rule string from structured request fields if rule not explicit
        rule = req.rule
        if not rule:
            parts = []
            if req.protocol != "any":
                parts.append(req.protocol)
            if req.port:
                parts.append(f"dport {req.port}")
            if req.remote_address:
                # Validate as IP address or CIDR network
                try:
                    ipaddress.ip_network(req.remote_address, strict=False)
                except ValueError:
                    try:
                        ipaddress.ip_address(req.remote_address)
                    except ValueError:
                        # 400 (client sent bad data) — previously returned 200
                        # with an error body, hiding the failure from naive
                        # clients that only checked HTTP status.
                        raise HTTPException(
                            status_code=400,
                            detail=f"Invalid address: {req.remote_address}",
                        )
                prefix = "ip saddr" if req.direction == "inbound" else "ip daddr"
                parts.append(f"{prefix} {req.remote_address}")
            parts.append("accept")
            rule = " ".join(parts).strip()
            if not rule or rule == "accept":
                raise HTTPException(
                    status_code=422,
                    detail="Provide 'rule' or at least one of protocol/port/remote_address",
                )
        fw = _require(_firewall, "firewall")
        return await fw.add_rule(req.chain, rule)

    @app.delete("/firewall/rules/{chain}/{handle}")
    async def firewall_delete_rule(chain: str, handle: int):
        fw = _require(_firewall, "firewall")
        return await fw.delete_rule(chain, handle)

    @app.post("/firewall/enable")
    async def firewall_enable():
        fw = _require(_firewall, "firewall")
        return await fw.enable()

    @app.post("/firewall/disable")
    async def firewall_disable():
        fw = _require(_firewall, "firewall")
        return await fw.disable()

    @app.post("/firewall/reload")
    async def firewall_reload():
        fw = _require(_firewall, "firewall")
        return await fw.reload()

    # --- Windows Services (PE-compat SCM) ---

    class WinServiceInstallRequest(BaseModel):
        name: str
        binary_path: str
        display_name: Optional[str] = None

    @app.get("/win-services")
    async def win_services_list():
        ws = _require(_win_services, "win_services")
        return await ws.list_services()

    @app.get("/win-services-scm/status")
    async def scm_status():
        ws = _require(_win_services, "win_services")
        return await ws.scm_status()

    # Static-segment routes MUST be registered before /{name} to avoid
    # FastAPI capturing "details", "logs", "install" as a service name.
    @app.get("/win-services/details/{name}")
    async def win_service_details(name: str):
        """Get detailed info about a Windows service.

        Returns name, display_name, description, type, state, pid,
        start_type (auto/manual/disabled), dependencies,
        dependent_services, exe_path, and uptime.
        """
        ws = _require(_win_services, "win_services")
        return await ws.get_service_details(name)

    @app.get("/win-services/logs/{name}")
    async def win_service_logs(name: str, lines: int = 50):
        """Get recent log output for a Windows service."""
        ws = _require(_win_services, "win_services")
        return await ws.get_service_logs(name, lines)

    @app.post("/win-services/install")
    async def win_service_install(req: WinServiceInstallRequest):
        ws = _require(_win_services, "win_services")
        return await ws.install_service(req.name, req.binary_path, req.display_name)

    # Generic {name} routes come after all fixed-segment routes
    @app.get("/win-services/{name}")
    async def win_service_get(name: str):
        ws = _require(_win_services, "win_services")
        return await ws.get_service(name)

    @app.post("/win-services/{name}/start")
    async def win_service_start(name: str):
        ws = _require(_win_services, "win_services")
        return await ws.start_service(name)

    @app.post("/win-services/{name}/stop")
    async def win_service_stop(name: str):
        ws = _require(_win_services, "win_services")
        return await ws.stop_service(name)

    @app.post("/win-services/{name}/restart")
    async def win_service_restart(name: str):
        """Restart a Windows service (stop + start)."""
        ws = _require(_win_services, "win_services")
        return await ws.restart_service(name)

    @app.delete("/win-services/{name}")
    async def win_service_delete(name: str):
        ws = _require(_win_services, "win_services")
        return await ws.delete_service(name)

    # --- Combined Services (Windows + Linux) ---

    @app.get("/services/all")
    async def all_services():
        """List ALL services -- both Windows (SCM) and Linux (systemd)."""
        linux_services = []
        windows_services = {}

        # Gather Linux (systemd) services
        if _system:
            try:
                linux_services = await _system.list_services()
            except Exception as e:
                logger.error("Failed to list Linux services: %s", e)
                linux_services = [{"error": str(e)}]

        # Gather Windows (SCM) services
        if _win_services:
            try:
                windows_services = await _win_services.list_services()
            except Exception as e:
                logger.error("Failed to list Windows services: %s", e)
                windows_services = {"error": str(e)}

        return {
            "status": "ok",
            "linux": linux_services,
            "windows": windows_services,
        }

    # --- Drivers / Kernel Modules ---
    #
    # /drivers/loaded was calling `lsmod` via subprocess every request. That
    # command forks, reads /proc/modules, formats a table, and returns — all
    # of which we can do ourselves in pure Python without the fork cost.
    # Plus kernel modules rarely change between requests, so we cache the
    # parsed result for a few seconds.

    _pe_related_module_names = frozenset({"trust", "pe_compat", "binfmt_misc"})
    _gpu_module_prefixes = ("nvidia", "amdgpu", "i915", "nouveau")
    _drivers_cache: dict = {"data": None, "ts": 0.0}
    _DRIVERS_TTL = 5.0
    # asyncio.Lock: uvicorn runs FastAPI endpoints on a single event loop,
    # but async cache-miss handling awaits run_in_executor() so other
    # coroutines can interleave and each launch their own /proc/modules
    # parse.  This lock coalesces concurrent misses into one.  Cheap
    # on the hit path because we lookup-without-await.
    _drivers_cache_lock = asyncio.Lock()

    def _parse_proc_modules_sync() -> list:
        modules = []
        try:
            with open("/proc/modules", "r") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) < 3:
                        continue
                    name = parts[0]
                    try:
                        size = int(parts[1])
                        used_by = int(parts[2])
                    except (ValueError, IndexError):
                        continue
                    modules.append({
                        "name": name,
                        "size": size,
                        "used_by": used_by,
                        "pe_related": name in _pe_related_module_names,
                        "gpu": name.startswith(_gpu_module_prefixes),
                    })
        except (FileNotFoundError, PermissionError):
            pass
        return modules

    @app.get("/drivers/loaded")
    async def drivers_loaded():
        """List loaded kernel modules with PE-relevant ones highlighted.

        Reads /proc/modules directly (no subprocess) and caches the result
        for _DRIVERS_TTL seconds. Modules load/unload rarely, so a ~5s TTL
        is invisible to callers.
        """
        now = time.monotonic()
        # Fast path: attribute reads are atomic under GIL.
        cached = _drivers_cache["data"]
        if cached is not None and (now - _drivers_cache["ts"]) < _DRIVERS_TTL:
            return cached
        # Slow path: serialize cache refill so concurrent requests don't
        # each launch a /proc/modules walk in the executor pool.
        async with _drivers_cache_lock:
            # Re-check under the lock; another coroutine may have already
            # refreshed the cache while we were awaiting acquisition.
            cached = _drivers_cache["data"]
            if cached is not None and (now - _drivers_cache["ts"]) < _DRIVERS_TTL:
                return cached
            modules = await asyncio.get_running_loop().run_in_executor(
                None, _parse_proc_modules_sync)
            if not modules:
                # /proc/modules absent (extremely unusual) — fall back to lsmod.
                proc = None
                try:
                    proc = await asyncio.create_subprocess_exec(
                        "lsmod",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
                except asyncio.TimeoutError:
                    if proc is not None:
                        try:
                            proc.kill()
                            await proc.wait()
                        except (ProcessLookupError, OSError):
                            pass
                    raise HTTPException(status_code=504, detail="lsmod timed out")
                except FileNotFoundError:
                    raise HTTPException(status_code=503, detail="lsmod not found")
                for line in stdout.decode(errors="replace").split("\n")[1:]:
                    parts = line.split()
                    if len(parts) >= 3:
                        name = parts[0]
                        try:
                            size = int(parts[1])
                            used_by = int(parts[2])
                        except (ValueError, IndexError):
                            continue
                        modules.append({
                            "name": name,
                            "size": size,
                            "used_by": used_by,
                            "pe_related": name in _pe_related_module_names,
                            "gpu": name.startswith(_gpu_module_prefixes),
                        })
            result = {"status": "ok", "modules": modules, "count": len(modules)}
            _drivers_cache["data"] = result
            _drivers_cache["ts"] = now
            return result

    # --- Hardware Summary ---
    #
    # CPU/GPU/storage topology is effectively immutable for the daemon's
    # lifetime. Memory pressure changes, so we update /proc/meminfo every
    # call but cache the subprocess-heavy bits (lscpu/lspci/lsblk, ~3 forks,
    # ~50-200 ms total on slow hardware).
    _hw_cache: dict = {"static": None, "ts": 0.0}
    _HW_STATIC_TTL = 60.0  # lscpu/lspci/lsblk refresh every 60s

    @app.get("/hardware/summary")
    async def hardware_summary():
        """System hardware summary -- GPU, CPU, memory, storage."""
        now = time.monotonic()
        cached_static = _hw_cache["static"]
        use_cache = (cached_static is not None
                     and (now - _hw_cache["ts"]) < _HW_STATIC_TTL)
        result: dict = dict(cached_static) if use_cache else {}

        # CPU info via lscpu (cached, topology is immutable)
        if not use_cache:
            proc_cpu = None
            try:
                proc_cpu = await asyncio.create_subprocess_exec(
                    "lscpu",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc_cpu.communicate(), timeout=10)
                cpu_info = {}
                for line in stdout.decode(errors="replace").split("\n"):
                    if ":" in line:
                        key, val = line.split(":", 1)
                        cpu_info[key.strip()] = val.strip()
                result["cpu"] = {
                    "model": cpu_info.get("Model name", "unknown"),
                    "architecture": cpu_info.get("Architecture", "unknown"),
                    "cores": cpu_info.get("CPU(s)", "unknown"),
                    "threads_per_core": cpu_info.get("Thread(s) per core", "unknown"),
                    "max_mhz": cpu_info.get("CPU max MHz", "unknown"),
                    "min_mhz": cpu_info.get("CPU min MHz", "unknown"),
                }
            except asyncio.TimeoutError:
                if proc_cpu is not None:
                    try:
                        proc_cpu.kill()
                        await proc_cpu.wait()
                    except (ProcessLookupError, OSError):
                        pass
                result["cpu"] = {"error": "lscpu unavailable"}
            except FileNotFoundError:
                result["cpu"] = {"error": "lscpu unavailable"}

        # Memory via /proc/meminfo (fast, no subprocess needed)
        try:
            with open("/proc/meminfo", "r") as f:
                meminfo = {}
                for line in f:
                    parts = line.split(":")
                    if len(parts) == 2:
                        key = parts[0].strip()
                        val_parts = parts[1].strip().split()
                        meminfo[key] = int(val_parts[0]) if val_parts else 0
            total_kb = meminfo.get("MemTotal", 0)
            available_kb = meminfo.get("MemAvailable", 0)
            swap_total_kb = meminfo.get("SwapTotal", 0)
            swap_free_kb = meminfo.get("SwapFree", 0)
            result["memory"] = {
                "total_mb": total_kb // 1024,
                "available_mb": available_kb // 1024,
                "used_mb": (total_kb - available_kb) // 1024,
                "swap_total_mb": swap_total_kb // 1024,
                "swap_used_mb": (swap_total_kb - swap_free_kb) // 1024,
            }
        except OSError:
            result["memory"] = {"error": "meminfo unavailable"}

        # GPU via lspci (cached; PCI topology is immutable)
        if not use_cache:
            proc_gpu = None
            try:
                proc_gpu = await asyncio.create_subprocess_exec(
                    "lspci", "-nn",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc_gpu.communicate(), timeout=10)
                gpus = []
                for line in stdout.decode(errors="replace").split("\n"):
                    lower = line.lower()
                    if "vga" in lower or "3d controller" in lower or "display" in lower:
                        gpus.append(line.strip())
                result["gpu"] = gpus if gpus else ["No GPU detected"]
            except asyncio.TimeoutError:
                if proc_gpu is not None:
                    try:
                        proc_gpu.kill()
                        await proc_gpu.wait()
                    except (ProcessLookupError, OSError):
                        pass
                result["gpu"] = ["lspci unavailable"]
            except FileNotFoundError:
                result["gpu"] = ["lspci unavailable"]

        # Storage via lsblk (cached; partition table changes rarely)
        if not use_cache:
            proc_stor = None
            try:
                proc_stor = await asyncio.create_subprocess_exec(
                    "lsblk", "-J", "-o", "NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc_stor.communicate(), timeout=10)
                try:
                    storage_data = json.loads(stdout.decode(errors="replace"))
                    result["storage"] = storage_data.get("blockdevices", [])
                except json.JSONDecodeError:
                    result["storage"] = {"error": "failed to parse lsblk output"}
            except asyncio.TimeoutError:
                if proc_stor is not None:
                    try:
                        proc_stor.kill()
                        await proc_stor.wait()
                    except (ProcessLookupError, OSError):
                        pass
                result["storage"] = {"error": "lsblk unavailable"}
            except FileNotFoundError:
                result["storage"] = {"error": "lsblk unavailable"}

            # Freeze the static parts (cpu/gpu/storage) into the cache so the
            # next request only pays for the fast /proc/meminfo read.
            _hw_cache["static"] = {
                k: result[k] for k in ("cpu", "gpu", "storage") if k in result
            }
            _hw_cache["ts"] = now

        return {"status": "ok", "hardware": result}

    # --- Thermal + Power -------------------------------------------------
    #
    # /thermal/current    snapshot of temps/frequencies/load/battery
    # /thermal/packed     24-byte binary event (for subscribers that stream)
    # /thermal/events     recent packed events, hex-encoded
    # /power/current      governor + PE-boost + throttling state
    # /power/governor     GET list / POST set governor (admin-only)

    @app.get("/thermal/current")
    async def thermal_current():
        """Live thermal snapshot: CPU+GPU temps, freq, load, RAPL, battery."""
        t = _require(_thermal, "thermal")
        return await t.snapshot()

    @app.get("/thermal/packed")
    async def thermal_packed():
        """Return the 24-byte packed event for the latest snapshot.

        Response is ``application/octet-stream`` for low-overhead polling
        from embedded dashboards — 24 bytes vs 150+ bytes of JSON.
        """
        t = _require(_thermal, "thermal")
        buf = await t.snapshot_packed()
        return Response(content=buf, media_type="application/octet-stream")

    @app.get("/thermal/events")
    async def thermal_events(count: int = 32):
        """Recent packed thermal events (hex-encoded for JSON transport)."""
        t = _require(_thermal, "thermal")
        if count <= 0:
            count = 32
        if count > 1024:
            count = 1024
        events = t.recent_events(count)
        return {
            "count": len(events),
            "event_size": 24,
            "events_hex": [e.hex() for e in events],
        }

    @app.get("/power/current")
    async def power_current():
        """Governor + CPU/GPU state + throttling status."""
        p = _require(_power, "power")
        return await p.snapshot()

    @app.get("/power/governor")
    async def power_governor():
        """List available governors and current setting."""
        p = _require(_power, "power")
        snap = await p.snapshot()
        return snap.get("governor", {})

    class GovernorRequest(BaseModel):
        governor: str

    @app.post("/power/governor")
    async def power_governor_set(req: GovernorRequest):
        """Manually set the CPU governor (root-only; audited)."""
        p = _require(_power, "power")
        result = await p.set_governor(req.governor, reason="api")
        if not result.get("success"):
            # 400 keeps the error payload but signals invalid input.
            raise HTTPException(status_code=400, detail=result)
        return result

    # --- Trust System ---

    @app.get("/trust/subjects")
    async def trust_subjects():
        to = _require(_trust_observer, "trust_observer")
        return to.get_all_subjects()

    @app.get("/trust/subjects/{subject_id}")
    async def trust_subject(subject_id: int):
        to = _require(_trust_observer, "trust_observer")
        info = to.get_subject(subject_id)
        if info is None:
            raise HTTPException(status_code=404, detail="Subject not found")
        return info

    @app.post("/trust/observe/{subject_id}")
    async def trust_observe(subject_id: int, domain: int = 0):
        to = _require(_trust_observer, "trust_observer")
        to.register_subject(subject_id, domain)
        return {"success": True, "subject_id": subject_id}

    @app.delete("/trust/observe/{subject_id}")
    async def trust_unobserve(subject_id: int):
        to = _require(_trust_observer, "trust_observer")
        to.unregister_subject(subject_id)
        return {"success": True}

    @app.get("/trust/anomalies")
    async def trust_anomalies():
        """Return anomaly detection state: frozen subjects, oscillations, risk distribution.
        Includes Root of Authority fields: immune distribution, sex determination, token starvation."""
        to = _require(_trust_observer, "trust_observer")
        return to.get_anomaly_status()

    @app.get("/trust/architecture")
    async def trust_architecture():
        """Return Root of Authority architecture information."""
        return {
            "name": "Root of Authority (Dynamic Hyperlation)",
            "version": "1.0.0",
            "paper": "Root of Authority: A Biologically-Inspired Dynamic Trust Architecture "
                     "for Hardware-Rooted Privilege Metabolism",
            "author": "Elijah Isaiah Roberts",
            "subsystems": {
                "proof_chain": "Self-Consuming Proof Chain (APE)",
                "chromosomes": "23-pair Chromosomal Authority Model",
                "sex_determination": "XY Sex Determination (conformant/divergent)",
                "token_economy": "Metabolic Token Economy (bounded damage)",
                "lifecycle": "Mitotic/Meiotic Lifecycle (generational decay)",
                "immune_response": "Cancer Detection + Apoptotic Cascade",
                "trc": "Trust Regulation Core (R, Th, C, S, F)",
            },
            "theorems": [
                "Non-Static Secrets",
                "Non-Replayability",
                "Reconfiguration Unpredictability",
                "Bounded Authority Inheritance",
                "Guaranteed Revocation",
                "Metabolic Fairness",
                "Chromosomal Completeness",
            ],
        }

    # --- Audit ---

    @app.get("/audit/recent")
    async def audit_recent(count: int = 50):
        # Clamp count to sane bounds. Negative/zero values used to hit
        # _audit.get_recent(count) which returns list[-N:] (i.e. tail N
        # with negative index wrap) — silently returning the wrong slice.
        if count <= 0:
            count = 50
        if count > 1000:
            count = 1000
        if _audit:
            return _audit.get_recent(count)
        return []

    # --- Desktop Automation ---

    class LaunchAppRequest(BaseModel):
        command: str
        args: list[str] = []
        working_dir: Optional[str] = None

    class LaunchExeRequest(BaseModel):
        exe_path: str
        args: list[str] = []
        diag: bool = False

    class WindowActionRequest(BaseModel):
        window_id: str
        x: Optional[int] = None
        y: Optional[int] = None
        width: Optional[int] = None
        height: Optional[int] = None

    class CreateShortcutRequest(BaseModel):
        name: str
        command: str
        icon: str = "application-x-executable"
        comment: str = ""

    class GameShortcutRequest(BaseModel):
        exe_path: str
        name: Optional[str] = None
        icon: Optional[str] = None

    class NotificationRequest(BaseModel):
        title: str
        message: str
        icon: str = "dialog-information"
        urgency: str = "normal"

    class ScheduledTaskRequest(BaseModel):
        schedule: str
        command: str

    class SetWallpaperRequest(BaseModel):
        path: str

    class SetResolutionRequest(BaseModel):
        width: int
        height: int

    class ClipboardRequest(BaseModel):
        text: str

    @app.post("/desktop/launch")
    async def desktop_launch(req: LaunchAppRequest):
        dt = _require(_desktop, "desktop")
        return await dt.launch_app(req.command, req.args, req.working_dir)

    @app.post("/desktop/launch-exe")
    async def desktop_launch_exe(req: LaunchExeRequest):
        dt = _require(_desktop, "desktop")
        return await dt.launch_exe(req.exe_path, req.args, req.diag)

    @app.get("/desktop/windows")
    async def desktop_windows():
        dt = _require(_desktop, "desktop")
        return await dt.list_running_apps()

    @app.get("/desktop/active-window")
    async def desktop_active_window():
        dt = _require(_desktop, "desktop")
        return await dt.get_active_window()

    @app.post("/desktop/window/focus")
    async def desktop_window_focus(req: WindowActionRequest):
        dt = _require(_desktop, "desktop")
        return await dt.focus_window(req.window_id)

    @app.post("/desktop/window/move")
    async def desktop_window_move(req: WindowActionRequest):
        dt = _require(_desktop, "desktop")
        if req.x is None or req.y is None:
            raise HTTPException(status_code=422, detail="x and y are required for move")
        return await dt.move_window(req.window_id, req.x, req.y)

    @app.post("/desktop/window/resize")
    async def desktop_window_resize(req: WindowActionRequest):
        dt = _require(_desktop, "desktop")
        if req.width is None or req.height is None:
            raise HTTPException(status_code=422, detail="width and height are required for resize")
        return await dt.resize_window(req.window_id, req.width, req.height)

    @app.post("/desktop/window/minimize")
    async def desktop_window_minimize(req: WindowActionRequest):
        dt = _require(_desktop, "desktop")
        return await dt.minimize_window(req.window_id)

    @app.post("/desktop/window/maximize")
    async def desktop_window_maximize(req: WindowActionRequest):
        dt = _require(_desktop, "desktop")
        return await dt.maximize_window(req.window_id)

    @app.post("/desktop/window/close")
    async def desktop_window_close(req: WindowActionRequest):
        dt = _require(_desktop, "desktop")
        return await dt.close_app(window_id=req.window_id)

    @app.post("/desktop/notify")
    async def desktop_notify(req: NotificationRequest):
        dt = _require(_desktop, "desktop")
        return await dt.send_notification(req.title, req.message, req.icon, req.urgency)

    @app.get("/desktop/clipboard")
    async def desktop_clipboard_get():
        dt = _require(_desktop, "desktop")
        return await dt.get_clipboard()

    @app.post("/desktop/clipboard")
    async def desktop_clipboard_set(req: ClipboardRequest):
        dt = _require(_desktop, "desktop")
        return await dt.set_clipboard(req.text)

    @app.post("/desktop/wallpaper")
    async def desktop_wallpaper(req: SetWallpaperRequest):
        dt = _require(_desktop, "desktop")
        return await dt.set_wallpaper(req.path)

    @app.get("/desktop/resolution")
    async def desktop_resolution():
        dt = _require(_desktop, "desktop")
        return await dt.get_screen_resolution()

    @app.post("/desktop/resolution")
    async def desktop_set_resolution(req: SetResolutionRequest):
        dt = _require(_desktop, "desktop")
        return await dt.set_screen_resolution(req.width, req.height)

    # --- Games ---

    @app.get("/games")
    async def games_list():
        dt = _require(_desktop, "desktop")
        return await dt.scan_games()

    @app.post("/games/launch")
    async def games_launch(req: LaunchExeRequest):
        dt = _require(_desktop, "desktop")
        return await dt.launch_game(req.exe_path, req.args)

    @app.post("/games/shortcut")
    async def games_create_shortcut(req: GameShortcutRequest):
        dt = _require(_desktop, "desktop")
        return await dt.create_game_shortcut(req.exe_path, req.name, req.icon)

    @app.get("/games/info")
    async def games_info(exe_path: str):
        dt = _require(_desktop, "desktop")
        return await dt.get_game_info(exe_path)

    # --- Desktop Shortcuts ---

    @app.get("/desktop/shortcuts")
    async def desktop_shortcuts():
        dt = _require(_desktop, "desktop")
        return await dt.list_shortcuts()

    @app.post("/desktop/shortcuts")
    async def desktop_create_shortcut(req: CreateShortcutRequest):
        dt = _require(_desktop, "desktop")
        return await dt.create_shortcut(req.name, req.command, req.icon, req.comment)

    @app.delete("/desktop/shortcuts/{name}")
    async def desktop_delete_shortcut(name: str):
        dt = _require(_desktop, "desktop")
        return await dt.delete_shortcut(name)

    # --- Scheduled Tasks ---

    @app.get("/desktop/scheduled-tasks")
    async def desktop_scheduled_tasks():
        dt = _require(_desktop, "desktop")
        return await dt.list_scheduled_tasks()

    @app.post("/desktop/scheduled-tasks")
    async def desktop_add_scheduled_task(req: ScheduledTaskRequest):
        dt = _require(_desktop, "desktop")
        return await dt.add_scheduled_task(req.schedule, req.command)

    # ---- LLM / AI endpoints ----

    @app.get("/ai/status")
    async def ai_status():
        llm = _require(_llm, "llm")
        # get_status() does sync os.listdir on model dir -- offload
        return await asyncio.get_running_loop().run_in_executor(None, llm.get_status)

    @app.get("/ai/models")
    async def ai_models():
        llm = _require(_llm, "llm")
        return await asyncio.get_running_loop().run_in_executor(None, llm.list_models)

    @app.post("/ai/load")
    async def ai_load(body: dict):
        llm = _require(_llm, "llm")
        model_path = body.get("model_path", "")
        if not model_path or not isinstance(model_path, str):
            raise HTTPException(
                status_code=422,
                detail="model_path is required (path to a .gguf file)",
            )
        n_ctx = body.get("n_ctx", 2048)
        n_gpu_layers = body.get("n_gpu_layers", -1)
        if not isinstance(n_ctx, int) or n_ctx <= 0:
            raise HTTPException(status_code=422, detail="n_ctx must be a positive integer")
        if not isinstance(n_gpu_layers, int):
            raise HTTPException(status_code=422, detail="n_gpu_layers must be an integer")
        return await llm.load_model(model_path, n_ctx, n_gpu_layers)

    @app.post("/ai/unload")
    async def ai_unload():
        llm = _require(_llm, "llm")
        return await llm.unload_model()

    @app.post("/ai/query")
    async def ai_query(body: dict):
        llm = _require(_llm, "llm")
        prompt = body.get("prompt", "")
        if not prompt or not isinstance(prompt, str):
            raise HTTPException(status_code=422, detail="prompt is required")
        max_tokens = body.get("max_tokens", 512)
        temperature = body.get("temperature", 0.7)
        stop = body.get("stop", None)
        if not isinstance(max_tokens, int) or max_tokens <= 0:
            raise HTTPException(status_code=422, detail="max_tokens must be a positive integer")
        if not isinstance(temperature, (int, float)) or temperature < 0:
            raise HTTPException(status_code=422, detail="temperature must be a non-negative number")
        return await llm.query(prompt, max_tokens, temperature, stop)

    # ---- Compositor endpoints ----

    @app.get("/compositor/info")
    async def compositor_info():
        comp = _require(_compositor, "compositor")
        # get_info() is pure env reads -- cheap, no I/O
        return comp.get_info()

    @app.get("/compositor/windows")
    async def compositor_windows():
        comp = _require(_compositor, "compositor")
        # Sync subprocess call -- offload to thread pool to avoid blocking event loop
        return await asyncio.get_running_loop().run_in_executor(None, comp.get_windows)

    @app.get("/compositor/active")
    async def compositor_active():
        comp = _require(_compositor, "compositor")
        result = await asyncio.get_running_loop().run_in_executor(None, comp.get_active_window)
        if result is None:
            return {"error": "no active window", "title": None}
        return result

    @app.post("/compositor/focus")
    async def compositor_focus(body: dict):
        comp = _require(_compositor, "compositor")
        wid = body.get("id", "")
        if not wid or not isinstance(wid, str):
            raise HTTPException(status_code=422, detail="Field 'id' (window identifier) is required")
        ok = await asyncio.get_running_loop().run_in_executor(None, comp.focus_window, wid)
        return {"success": ok}

    @app.post("/compositor/close")
    async def compositor_close(body: dict):
        comp = _require(_compositor, "compositor")
        wid = body.get("id", "")
        if not wid or not isinstance(wid, str):
            raise HTTPException(status_code=422, detail="Field 'id' (window identifier) is required")
        ok = await asyncio.get_running_loop().run_in_executor(None, comp.close_window, wid)
        return {"success": ok}

    @app.post("/compositor/layout")
    async def compositor_layout(body: dict):
        comp = _require(_compositor, "compositor")
        layout = body.get("layout", "productivity")
        return await asyncio.get_running_loop().run_in_executor(None, comp.set_layout, layout)

    @app.get("/compositor/workspaces")
    async def compositor_workspaces():
        comp = _require(_compositor, "compositor")
        return await asyncio.get_running_loop().run_in_executor(None, comp.get_workspaces)

    # --- Auth token management ---

    class TokenRequest(BaseModel):
        subject_id: int
        name: str
        # Trust levels in this system fit comfortably under 1000
        # (root-of-authority bands: 100/200/400/600/800). Cap at 1000
        # to prevent a compromised 600-level remote admin from issuing
        # an unbounded super-admin token.
        trust_level: int = Field(default=1, ge=0, le=1000)
        # Cap TTL at 30 days. Long-lived tokens defeat the revocation
        # model — the daemon keeps the revocation list in memory and
        # operators rotate it.
        ttl: int = Field(default=3600, ge=1, le=86400 * 30)

    from fastapi import Request as _FastAPIRequest

    @app.post("/auth/token")
    async def create_auth_token(req: TokenRequest, request: _FastAPIRequest):
        # Security: token creation is sensitive — restrict access.
        # Allow from localhost unconditionally (daemon bootstrap).
        # Remote callers must present a valid admin-level token.
        client_host = getattr(request.client, "host", None) if request.client else None
        is_local = client_host in ("127.0.0.1", "::1", "localhost", None)
        if not is_local:
            if config.get("auth_enabled", True):
                from auth import check_auth
                raw_token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip() or None
                allowed, identity, reason = check_auth(
                    "/auth/token", request.method, raw_token, _trust_observer
                )
                if not allowed:
                    raise HTTPException(status_code=403, detail=f"Token creation denied: {reason}")
                if identity and identity.trust_level < 600:
                    raise HTTPException(status_code=403, detail="Admin trust level required for remote token creation")
            else:
                raise HTTPException(status_code=403, detail="Remote token creation requires auth to be enabled")
        from auth import create_token
        token = create_token(req.subject_id, req.name, req.trust_level, req.ttl)
        return {"token": token}

    class RevokeRequest(BaseModel):
        token: str

    @app.post("/auth/revoke")
    async def auth_revoke(req: RevokeRequest):
        """Revoke an auth token by verifying it and adding its jti to the revocation list.

        Returns ``revoked=True`` if the token was valid and its ``jti`` was
        placed on the revocation list. ``revoked=False`` means the caller
        submitted an invalid / expired / already-revoked token, or the
        token had no ``jti``. Clients relying on revocation MUST check
        ``revoked`` — a blanket ``status=ok`` previously hid silent
        failures where a typoed token looked successfully revoked.
        """
        from auth import verify_token, revoke_token
        identity = verify_token(req.token)
        if identity and identity.jti:
            revoke_token(identity.jti)
            return {"status": "ok", "revoked": True, "jti": identity.jti}
        return {"status": "ok", "revoked": False,
                "reason": "invalid_or_expired_token"}

    @app.post("/auth/refresh")
    async def auth_refresh(request: _FastAPIRequest):
        """Refresh an auth token (extends expiry by issuing a new one)."""
        identity = getattr(request.state, "identity", None)
        if not identity:
            raise HTTPException(status_code=403, detail="Valid token required for refresh")
        from auth import create_token
        new_token = create_token(
            identity.subject_id, identity.name,
            identity.trust_level, ttl=86400
        )
        return {"status": "ok", "token": new_token}

    # --- WebSocket for real-time trust events ---

    def _broadcast_trust_event(event: dict):
        """Enqueue a trust event for all connected WebSocket clients.

        May be called from a background thread (trust observer polling
        via run_in_executor) or from the event loop thread, so we detect
        which case applies and schedule sends appropriately.
        """
        nonlocal _main_loop

        try:
            msg = json.dumps(event, default=str)
        except (TypeError, ValueError):
            logger.debug("Failed to serialize trust event for WebSocket broadcast")
            return

        if not _ws_clients:
            return

        async def _enqueue_all(text):
            for ws in list(_ws_clients):
                q = _ws_queues.get(ws)
                if q is None:
                    continue
                if q.full():
                    # Drop oldest message to prevent slow-client backpressure
                    try:
                        q.get_nowait()
                    except asyncio.QueueEmpty:
                        pass
                try:
                    q.put_nowait(text)
                except asyncio.QueueFull:
                    pass

        # Detect whether we are on the event loop thread or a background thread
        try:
            running_loop = asyncio.get_running_loop()
        except RuntimeError:
            running_loop = None

        if running_loop is not None:
            # Called from the event loop thread -- schedule directly.
            # Hold a strong reference to the task until it finishes so the
            # GC cannot collect it mid-run.
            _main_loop = running_loop
            t = asyncio.ensure_future(_enqueue_all(msg))
            _bg_broadcast_tasks.add(t)
            t.add_done_callback(_bg_broadcast_tasks.discard)
        elif _main_loop is not None and _main_loop.is_running():
            # Called from a background thread -- use thread-safe scheduling
            def _schedule(text=msg):
                t2 = asyncio.ensure_future(_enqueue_all(text))
                _bg_broadcast_tasks.add(t2)
                t2.add_done_callback(_bg_broadcast_tasks.discard)
            _main_loop.call_soon_threadsafe(_schedule)

    if _trust_observer:
        _trust_observer.add_event_callback(_broadcast_trust_event)

    # Wire audit events to WebSocket too
    if _audit:
        _audit._ws_callback = _broadcast_trust_event

    try:
        from starlette.websockets import WebSocket as StarletteWS, WebSocketDisconnect

        async def _ws_sender(ws, q: asyncio.Queue):
            """Drain the per-client queue and send messages."""
            try:
                while True:
                    msg = await q.get()
                    await ws.send_text(msg)
            except Exception:
                # Connection lost or closed; cleanup handled in finally of endpoint
                pass

        @app.websocket("/ws")
        async def websocket_endpoint(ws: StarletteWS):
            # Authenticate before accepting the WebSocket connection
            token = ws.headers.get("Authorization", "").removeprefix("Bearer ").strip() or ws.query_params.get("token")
            if not token:
                await ws.close(code=4001, reason="Missing auth token")
                return
            from auth import verify_token
            identity = verify_token(token)
            if not identity:
                await ws.close(code=4003, reason="Invalid token")
                return
            await ws.accept()
            q: asyncio.Queue = asyncio.Queue(maxsize=_WS_QUEUE_MAX)
            _ws_clients.add(ws)
            _ws_queues[ws] = q
            sender_task = asyncio.create_task(_ws_sender(ws, q))
            logger.info("WebSocket client connected (%d total)", len(_ws_clients))
            try:
                while True:
                    # Keep connection alive; clients can send commands later
                    data = await ws.receive_text()
                    # Echo acknowledgement
                    await ws.send_text('{"ack": true}')
            except WebSocketDisconnect:
                pass
            except Exception:
                logger.debug("WebSocket error, disconnecting client")
            finally:
                sender_task.cancel()
                _ws_clients.discard(ws)
                _ws_queues.pop(ws, None)
                logger.info("WebSocket client disconnected (%d remaining)", len(_ws_clients))
    except ImportError:
        logger.warning("Starlette WebSocket not available — /ws endpoint disabled")

    # --- Automation Engine ---

    _automation = None
    try:
        from automation import AutomationEngine
        _automation = AutomationEngine()
        logger.info("Automation engine initialized")
    except Exception as e:
        logger.warning("Automation engine unavailable: %s", e)

    class WorkflowRequest(BaseModel):
        name: str
        steps: list[dict]
        description: str = ""

    class QuickCommandRequest(BaseModel):
        command: str
        timeout: int = 60

    class ScriptRequest(BaseModel):
        script: str
        interpreter: str = "/bin/bash"
        timeout: int = 300

    @app.get("/automation/capabilities")
    async def automation_capabilities():
        """What the automation engine can do."""
        if _automation:
            return _automation.get_capabilities()
        raise HTTPException(status_code=503, detail="Automation engine not available")

    @app.post("/automation/task")
    async def automation_submit_task(req: WorkflowRequest):
        """Submit a multi-step automation workflow."""
        auto = _require(_automation, "automation")
        task_id = await auto.submit_task(req.name, req.steps, req.description)
        return {"task_id": task_id, "status": "submitted"}

    @app.post("/automation/quick")
    async def automation_quick(req: QuickCommandRequest):
        """Execute a single command immediately."""
        auto = _require(_automation, "automation")
        return await auto.submit_quick(req.command, req.timeout)

    @app.post("/automation/script")
    async def automation_script(req: ScriptRequest):
        """Execute a multi-line script."""
        auto = _require(_automation, "automation")
        return await auto.submit_script(req.script, req.interpreter, req.timeout)

    @app.get("/automation/tasks")
    async def automation_list_tasks(status: Optional[str] = None):
        """List all automation tasks."""
        auto = _require(_automation, "automation")
        return auto.list_tasks(status)

    @app.get("/automation/tasks/{task_id}")
    async def automation_get_task(task_id: str):
        """Get task status and output."""
        auto = _require(_automation, "automation")
        result = auto.get_task(task_id)
        if result is None:
            raise HTTPException(status_code=404, detail="Task not found")
        return result

    @app.post("/automation/tasks/{task_id}/cancel")
    async def automation_cancel_task(task_id: str):
        """Cancel a running task."""
        auto = _require(_automation, "automation")
        return await auto.cancel_task(task_id)

    @app.get("/automation/history")
    async def automation_history(count: int = 50):
        """Get recent task execution history."""
        auto = _require(_automation, "automation")
        return auto.get_history(count)

    # --- Cortex integration: proxy status from cortex (port 8421) ---
    #
    # Reuse a single aiohttp.ClientSession across cortex proxy calls. Creating
    # a new session per call (old behavior) did a full connection-pool setup,
    # SSL ctx probe, and TCP handshake every time — ~5 ms on each hit, on top
    # of the actual cortex request. A shared session is ~20× faster for the
    # /dashboard fanout which issues 3 cortex calls back-to-back.
    # (_cortex_session_holder is declared near the top of create_app so the
    # lifespan shutdown hook can close it.)
    _cortex_session_lock = asyncio.Lock()

    async def _get_cortex_session():
        """Return a shared aiohttp.ClientSession, creating it lazily."""
        async with _cortex_session_lock:
            session = _cortex_session_holder["session"]
            if session is not None and not session.closed:
                return session, _cortex_session_holder["aiohttp"]
            try:
                import aiohttp
            except ImportError:
                return None, None
            # Short-TTL keepalive connector so stale cortex restarts don't
            # wedge this pool forever.
            connector = aiohttp.TCPConnector(limit=4, ttl_dns_cache=30, enable_cleanup_closed=True)
            session = aiohttp.ClientSession(
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=2),
            )
            _cortex_session_holder["session"] = session
            _cortex_session_holder["aiohttp"] = aiohttp
            return session, aiohttp

    async def _cortex_get(path: str, default: dict) -> dict:
        session, _ah = await _get_cortex_session()
        if session is None:
            return {**default, "error": "aiohttp not installed"}
        try:
            async with session.get(f"http://127.0.0.1:8421{path}") as resp:
                return await resp.json()
        except (asyncio.TimeoutError, OSError):
            return default
        except Exception:
            return default

    @app.get("/cortex/status")
    async def cortex_status():
        """Proxy cortex status from its REST API on port 8421."""
        return await _cortex_get("/status",
                                 {"status": "unavailable",
                                  "error": "cortex not reachable on port 8421"})

    @app.get("/cortex/autonomy")
    async def cortex_autonomy():
        """Proxy cortex autonomy level."""
        return await _cortex_get("/autonomy", {"status": "unavailable"})

    @app.get("/cortex/decisions")
    async def cortex_decisions():
        """Proxy pending cortex decisions."""
        return await _cortex_get("/decisions/pending",
                                 {"decisions": [], "status": "unavailable"})

    # --- AI Assistant Automation Endpoints (/auto/*) ---

    import os as _os
    import shlex as _shlex
    import subprocess as _sp
    import functools as _functools

    _BLOCKED_COMMANDS = [
        "rm -rf /", "rm -rf /*", "mkfs", "dd if=", "shutdown", "reboot",
        "poweroff", "halt", "init 0", "init 6", ":(){", "fork bomb",
        "chmod -R 777 /", "chown -R", "mv / ", "> /dev/sda",
        "wget|sh", "curl|sh",
    ]

    def _audit_auto(action: str, detail: str, ok: bool):
        if _audit:
            _audit.log("POST", f"/auto/{action}", result="success" if ok else "error", detail=detail)

    def _is_blocked(cmd: str) -> bool:
        low = cmd.lower().strip()
        return any(b in low for b in _BLOCKED_COMMANDS)

    async def _run_subprocess_async(cmd, **kwargs):
        """Run subprocess.run in a thread executor to avoid blocking the event loop."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, _functools.partial(_sp.run, cmd, **kwargs)
        )

    async def _read_file_async(path, max_size=1_000_000):
        """Read a file in a thread executor to avoid blocking the event loop."""
        loop = asyncio.get_running_loop()
        def _read():
            with open(path, "r") as f:
                return f.read(max_size)
        return await loop.run_in_executor(None, _read)

    async def _write_file_async(path, content):
        """Write a file in a thread executor to avoid blocking the event loop."""
        loop = asyncio.get_running_loop()
        def _write():
            _os.makedirs(_os.path.dirname(path), exist_ok=True)
            with open(path, "w") as f:
                f.write(content)
        return await loop.run_in_executor(None, _write)

    async def _listdir_async(path):
        """List directory in a thread executor to avoid blocking the event loop."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _os.listdir, path)

    async def _glob_async(pattern, recursive=True, limit=500):
        """Run glob in a thread executor to avoid blocking the event loop."""
        import glob as _glob
        loop = asyncio.get_running_loop()
        def _do_glob():
            return _glob.glob(pattern, recursive=recursive)[:limit]
        return await loop.run_in_executor(None, _do_glob)

    async def _compress_async(path):
        """Compress a path into a tar.gz in a thread executor."""
        import tarfile as _tarfile
        loop = asyncio.get_running_loop()
        tar_path = path + ".tar.gz"
        def _do_compress():
            with _tarfile.open(tar_path, "w:gz") as tar:
                tar.add(path, arcname=_os.path.basename(path))
            return tar_path
        return await loop.run_in_executor(None, _do_compress)

    class AutoPackageRequest(BaseModel):
        action: str  # install|remove|search|update
        package: str = ""

    class AutoCommandRequest(BaseModel):
        command: str
        cwd: str = "/home/arch"

    class AutoServiceRequest(BaseModel):
        action: str  # start|stop|restart|status|enable|disable
        service: str

    class AutoFileRequest(BaseModel):
        action: str  # read|write|list|find|compress
        path: str
        content: str = ""

    class AutoGitRequest(BaseModel):
        action: str  # init|clone|commit|push|pull|status
        repo: str = "."
        message: str = ""
        url: str = ""

    @app.post("/auto/package")
    async def auto_package(req: AutoPackageRequest):
        actions = {
            "install": ["pacman", "-S", "--noconfirm", req.package],
            "remove": ["pacman", "-R", "--noconfirm", req.package],
            "search": ["pacman", "-Ss", req.package],
            "update": ["pacman", "-Syu", "--noconfirm"],
        }
        if req.action not in actions:
            raise HTTPException(status_code=422, detail=f"Invalid action: {req.action}")
        if req.action in ("install", "remove", "search") and not req.package:
            raise HTTPException(status_code=422, detail="package is required")
        try:
            r = await _run_subprocess_async(actions[req.action], capture_output=True, text=True, timeout=300)
            _audit_auto("package", f"{req.action} {req.package}", r.returncode == 0)
            return {"status": "ok" if r.returncode == 0 else "error",
                    "output": r.stdout, "error": r.stderr, "exit_code": r.returncode}
        except Exception as e:
            _audit_auto("package", f"{req.action} failed: {e}", False)
            return {"status": "error", "output": "", "error": str(e), "exit_code": -1}

    @app.post("/auto/command")
    async def auto_command(req: AutoCommandRequest):
        if _is_blocked(req.command):
            _audit_auto("command", f"BLOCKED: {req.command}", False)
            raise HTTPException(status_code=403, detail="Command is blocked by safety policy")
        try:
            argv = _shlex.split(req.command)
        except ValueError as e:
            raise HTTPException(status_code=422, detail=f"Bad command syntax: {e}")
        try:
            r = await _run_subprocess_async(argv, capture_output=True, text=True, timeout=120,
                        cwd=req.cwd if _os.path.isdir(req.cwd) else "/home/arch")
            _audit_auto("command", req.command, r.returncode == 0)
            return {"status": "ok" if r.returncode == 0 else "error",
                    "output": r.stdout, "error": r.stderr, "exit_code": r.returncode}
        except Exception as e:
            _audit_auto("command", f"exec failed: {e}", False)
            return {"status": "error", "output": "", "error": str(e), "exit_code": -1}

    @app.post("/auto/service")
    async def auto_service(req: AutoServiceRequest):
        valid = ("start", "stop", "restart", "status", "enable", "disable")
        if req.action not in valid:
            raise HTTPException(status_code=422, detail=f"Invalid action, must be one of {valid}")
        try:
            r = await _run_subprocess_async(["systemctl", req.action, req.service],
                        capture_output=True, text=True, timeout=30)
            _audit_auto("service", f"{req.action} {req.service}", r.returncode == 0)
            return {"status": "ok" if r.returncode == 0 else "error",
                    "output": r.stdout, "error": r.stderr, "exit_code": r.returncode}
        except Exception as e:
            _audit_auto("service", f"{req.action} {req.service} failed: {e}", False)
            return {"status": "error", "output": "", "error": str(e), "exit_code": -1}

    @app.post("/auto/file")
    async def auto_file(req: AutoFileRequest):
        path = _os.path.abspath(req.path)
        # Block access to sensitive paths
        _blocked_paths = ['/etc/shadow', '/etc/passwd', '/boot/', '/root/.ssh/', '/var/lib/ai-control/']
        if any(path == b or path.startswith(b) for b in _blocked_paths):
            raise HTTPException(status_code=403, detail="Path is restricted")
        try:
            if req.action == "read":
                data = await _read_file_async(path)
                _audit_auto("file", f"read {path}", True)
                return {"status": "ok", "output": data, "error": ""}
            elif req.action == "write":
                await _write_file_async(path, req.content)
                _audit_auto("file", f"write {path}", True)
                return {"status": "ok", "output": f"Wrote {len(req.content)} bytes", "error": ""}
            elif req.action == "list":
                entries = await _listdir_async(path)
                _audit_auto("file", f"list {path}", True)
                return {"status": "ok", "output": entries, "error": ""}
            elif req.action == "find":
                matches = await _glob_async(path)
                _audit_auto("file", f"find {path}", True)
                return {"status": "ok", "output": matches, "error": ""}
            elif req.action == "compress":
                tar_path = await _compress_async(path)
                _audit_auto("file", f"compress {path}", True)
                return {"status": "ok", "output": tar_path, "error": ""}
            else:
                raise HTTPException(status_code=422, detail=f"Invalid action: {req.action}")
        except HTTPException:
            raise
        except Exception as e:
            _audit_auto("file", f"{req.action} {path} failed: {e}", False)
            return {"status": "error", "output": "", "error": str(e)}

    @app.get("/auto/system")
    async def auto_system():
        import platform as _plat
        info = {"hostname": _plat.node(), "platform": _plat.platform(),
                "uptime": "", "cpu": {}, "memory": {}, "disk": {},
                "network": [], "packages": 0, "services": []}
        try:
            uptime_data = await _read_file_async("/proc/uptime")
            info["uptime"] = f"{float(uptime_data.split()[0]):.0f}s"
        except Exception:
            pass
        try:
            r = await _run_subprocess_async(["nproc"], capture_output=True, text=True, timeout=5)
            info["cpu"]["cores"] = r.stdout.strip()
            loadavg_data = await _read_file_async("/proc/loadavg")
            info["cpu"]["load"] = loadavg_data.strip()
        except Exception:
            pass
        try:
            r = await _run_subprocess_async(["free", "-b"], capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                if line.startswith("Mem:"):
                    parts = line.split()
                    info["memory"] = {"total": int(parts[1]), "used": int(parts[2]),
                                      "free": int(parts[3])}
        except Exception:
            pass
        try:
            r = await _run_subprocess_async(["df", "-B1", "/"], capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines()[1:]:
                parts = line.split()
                info["disk"] = {"total": int(parts[1]), "used": int(parts[2]),
                                "free": int(parts[3]), "mount": parts[5]}
                break
        except Exception:
            pass
        try:
            r = await _run_subprocess_async(["ip", "-j", "addr"], capture_output=True, text=True, timeout=5)
            info["network"] = json.loads(r.stdout) if r.returncode == 0 else []
        except Exception:
            pass
        try:
            r = await _run_subprocess_async(["pacman", "-Q"], capture_output=True, text=True, timeout=10)
            info["packages"] = len(r.stdout.strip().splitlines())
        except Exception:
            pass
        try:
            r = await _run_subprocess_async(["systemctl", "list-units", "--type=service", "--state=running",
                         "--no-pager", "--plain", "--no-legend"],
                        capture_output=True, text=True, timeout=10)
            info["services"] = [ln.split()[0] for ln in r.stdout.strip().splitlines()[:50]]
        except Exception:
            pass
        _audit_auto("system", "overview", True)
        return info

    @app.post("/auto/git")
    async def auto_git(req: AutoGitRequest):
        repo = _os.path.abspath(req.repo)
        cmds = {
            "init": ["git", "init"],
            "clone": ["git", "clone", req.url, repo],
            "commit": ["git", "commit", "-m", req.message or "auto-commit"],
            "push": ["git", "push"],
            "pull": ["git", "pull"],
            "status": ["git", "status", "--porcelain"],
        }
        if req.action not in cmds:
            raise HTTPException(status_code=422, detail=f"Invalid action: {req.action}")
        if req.action == "clone" and not req.url:
            raise HTTPException(status_code=422, detail="url is required for clone")
        cwd = _os.path.dirname(repo) if req.action == "clone" else repo
        if not _os.path.isdir(cwd):
            cwd = "/home/arch"
        try:
            r = await _run_subprocess_async(cmds[req.action], capture_output=True, text=True, timeout=120, cwd=cwd)
            _audit_auto("git", f"{req.action} {repo}", r.returncode == 0)
            return {"status": "ok" if r.returncode == 0 else "error",
                    "output": r.stdout, "error": r.stderr, "exit_code": r.returncode}
        except Exception as e:
            _audit_auto("git", f"{req.action} failed: {e}", False)
            return {"status": "error", "output": "", "error": str(e), "exit_code": -1}

    # --- Contusion Automation Engine ---

    def _audit_contusion(action: str, detail: str, ok: bool):
        if _audit:
            _audit.log("POST", f"/contusion/{action}",
                       result="success" if ok else "error", detail=detail)

    class ContusionRunRequest(BaseModel):
        action: str
        params: dict = {}

    class ContusionPipelineRequest(BaseModel):
        steps: list[dict]

    class ContusionMacroNameRequest(BaseModel):
        name: str

    class ContusionSearchRequest(BaseModel):
        query: str

    class ContusionConfirmRequest(BaseModel):
        command: str

    class ContusionContextRequest(BaseModel):
        # Accept any of these field names from clients. The GTK Contusion
        # app sends "prompt", the `ai automate` shell sends "description",
        # scripts/set_smoke.py sends "text", and the canonical API is
        # "request". Without multi-alias handling Pydantic returns 422
        # and the UI silently fails with "does not open".
        request: Optional[str] = None
        prompt: Optional[str] = None
        description: Optional[str] = None
        text: Optional[str] = None

        def resolve(self) -> str:
            return self.request or self.prompt or self.description or self.text or ""

    class ContusionLaunchRequest(BaseModel):
        app: str
        args: Optional[list[str]] = None

    @app.post("/contusion/run")
    async def contusion_run(req: ContusionRunRequest):
        """Run a single Contusion automation action."""
        cn = _require(_contusion, "contusion")
        try:
            result = await cn._dispatch_action(req.action, req.params)
            _audit_contusion("run", f"{req.action}", result.get("success", False))
            return {"status": "ok", "result": result}
        except Exception as e:
            _audit_contusion("run", f"{req.action} failed: {e}", False)
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/contusion/pipeline")
    async def contusion_pipeline(req: ContusionPipelineRequest):
        """Execute an ordered pipeline of actions."""
        cn = _require(_contusion, "contusion")
        try:
            from contusion import Action, Pipeline
            actions = []
            for step in req.steps:
                kind = step.pop("kind", step.pop("action", ""))
                actions.append(Action(kind, **step))
            pipeline = Pipeline(actions=actions)
            result = await cn.run_pipeline(pipeline)
            _audit_contusion("pipeline", f"{len(req.steps)} steps", result.get("success", False))
            return {"status": "ok", "result": result}
        except Exception as e:
            _audit_contusion("pipeline", f"failed: {e}", False)
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/contusion/macro/record")
    async def contusion_macro_record(req: ContusionMacroNameRequest):
        """Start recording a macro."""
        cn = _require(_contusion, "contusion")
        result = cn.record_macro(req.name)
        _audit_contusion("macro/record", req.name, True)
        return {"status": "ok", "result": result}

    @app.post("/contusion/macro/stop")
    async def contusion_macro_stop():
        """Stop recording the current macro."""
        cn = _require(_contusion, "contusion")
        result = cn.stop_recording()
        _audit_contusion("macro/stop", "", result.get("success", False))
        return {"status": "ok", "result": result}

    @app.post("/contusion/macro/play")
    async def contusion_macro_play(req: ContusionMacroNameRequest):
        """Play back a saved macro."""
        cn = _require(_contusion, "contusion")
        try:
            result = await cn.play_macro(req.name)
            _audit_contusion("macro/play", req.name, result.get("success", False))
            return {"status": "ok", "result": result}
        except Exception as e:
            _audit_contusion("macro/play", f"{req.name} failed: {e}", False)
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/contusion/macro/list")
    async def contusion_macro_list():
        """List all saved macros."""
        cn = _require(_contusion, "contusion")
        macros = cn.list_macros()
        return {"status": "ok", "macros": macros}

    @app.get("/contusion/apps")
    async def contusion_apps():
        """List available apps from the Contusion launch library.

        Returns a JSON envelope with ``{status, apps, count}``. When the
        Contusion engine failed to load at startup this endpoint degrades
        to ``{status: "unavailable", apps: [], count: 0}`` rather than 503
        so the desktop launcher + test harness can probe safely without
        handling an error path.
        """
        if _contusion is None:
            return {"status": "unavailable", "apps": [], "count": 0}
        try:
            library = _contusion.get_app_library() or {}
            apps = [{"name": name, **info} for name, info in sorted(library.items())]
            return {"status": "ok", "apps": apps, "count": len(apps)}
        except Exception as e:
            logger.warning("contusion/apps failed: %s", e)
            return {"status": "error", "apps": [], "count": 0, "error": str(e)}

    @app.post("/contusion/context")
    async def contusion_context(req: ContusionContextRequest):
        """Parse a natural language request via dictionary engine and execute.

        The dictionary engine parses the NL instruction into executable
        actions with security classification. Actions requiring higher
        trust than the caller has (400 for this endpoint) are blocked.
        Dangerous actions requiring confirmation are returned as
        needs_confirmation=True without executing.
        """
        cn = _require(_contusion, "contusion")
        instruction = req.resolve()
        if not instruction:
            raise HTTPException(
                status_code=422,
                detail="Missing instruction (field 'request', 'prompt', or 'description')",
            )
        try:
            result = await cn.route(instruction, caller_trust=400)
            _audit_contusion("context", instruction[:120], result.get("success", False))
            return {"status": "ok", "result": result}
        except Exception as e:
            _audit_contusion("context", f"failed: {e}", False)
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/contusion/execute")
    async def contusion_execute(req: ContusionContextRequest):
        """Alias for /contusion/context. The `ai automate` shell helper
        calls this path after a preview round-trip."""
        return await contusion_context(req)

    @app.post("/contusion/launch")
    async def contusion_launch(req: ContusionLaunchRequest):
        """Launch an app from the Contusion app library by name.

        Used by `ai launch <app>` and the right-click menu. Without this
        endpoint the shell falls back to a blind gtk-launch which usually
        fails inside QEMU/headless sessions.
        """
        cn = _require(_contusion, "contusion")
        try:
            result = await cn.launch_app(req.app, req.args)
            _audit_contusion("launch", req.app, result.get("success", False))
            return {"status": "ok", "result": result}
        except Exception as e:
            _audit_contusion("launch", f"{req.app} failed: {e}", False)
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/contusion")
    async def contusion_root():
        """Root Contusion status endpoint.

        The desktop right-click menu uses `xdg-open http://127.0.0.1:8420/contusion`;
        without this route the browser would 404 and users would think
        "contusion does not open".
        """
        if _contusion is None:
            return {"status": "unavailable",
                    "error": "Contusion engine failed to initialize",
                    "hint": "Check /var/log/ai-control-daemon.log"}
        try:
            stats = _contusion.get_dictionary_stats()
            apps = len(_contusion.get_app_library())
            macros = len(_contusion.list_macros())
        except Exception as e:
            stats, apps, macros = {"error": str(e)}, -1, -1
        return {
            "status": "ok",
            "engine": "contusion",
            "apps": apps,
            "macros": macros,
            "dictionary": stats,
            "endpoints": [
                "/contusion/context", "/contusion/execute", "/contusion/launch",
                "/contusion/run", "/contusion/pipeline", "/contusion/apps",
                "/contusion/processes", "/contusion/macro/record",
                "/contusion/macro/stop", "/contusion/macro/play",
                "/contusion/macro/list", "/contusion/workflows",
                "/contusion/dictionary/search", "/contusion/dictionary/stats",
            ],
        }

    @app.post("/contusion/confirm")
    async def contusion_confirm(req: ContusionConfirmRequest):
        """Execute a previously-blocked dangerous action after user confirmation.

        Only call this after /contusion/context returned an action with
        needs_confirmation=True and the user has explicitly approved it.
        """
        cn = _require(_contusion, "contusion")
        try:
            result = await cn.confirm_and_execute(req.command, caller_trust=600)
            _audit_contusion("confirm", req.command[:120], result.get("returncode", -1) == 0)
            return {"status": "ok", "result": result}
        except Exception as e:
            _audit_contusion("confirm", f"failed: {e}", False)
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/contusion/dictionary/search")
    async def contusion_dict_search(req: ContusionSearchRequest):
        """Search the command dictionary by keyword."""
        cn = _require(_contusion, "contusion")
        matches = cn.search_commands(req.query)
        return {"status": "ok", "query": req.query, "results": matches}

    @app.get("/contusion/dictionary/stats")
    async def contusion_dict_stats():
        """Return dictionary statistics (total commands, categories, security breakdown)."""
        cn = _require(_contusion, "contusion")
        return {"status": "ok", "stats": cn.get_dictionary_stats()}

    @app.get("/contusion/dictionary/app/{name}")
    async def contusion_dict_app(name: str):
        """Get detailed application profile from the dictionary."""
        cn = _require(_contusion, "contusion")
        profile = cn.get_app_profile(name)
        if not profile:
            raise HTTPException(status_code=404, detail=f"App not found: {name}")
        return {"status": "ok", "app": profile}

    @app.get("/contusion/processes")
    async def contusion_processes():
        """List running processes."""
        cn = _require(_contusion, "contusion")
        try:
            procs = await cn.get_running_processes()
            return {"status": "ok", "processes": procs}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    # --- Contusion: Workflow Templates ---

    @app.get("/contusion/workflows")
    async def contusion_workflows():
        """List all available workflow templates."""
        cn = _require(_contusion, "contusion")
        wfs = cn.get_workflows()
        return {"status": "ok", "workflows": {
            name: {"name": wf["name"], "description": wf["description"],
                   "steps": len(wf["steps"])}
            for name, wf in wfs.items()
        }}

    @app.get("/contusion/workflows/{name}")
    async def contusion_workflow_detail(name: str):
        """Get details of a specific workflow template."""
        cn = _require(_contusion, "contusion")
        wf = cn.get_workflow(name)
        if not wf:
            raise HTTPException(status_code=404,
                                detail=f"Unknown workflow: {name}. "
                                       f"Available: {list(cn.get_workflows().keys())}")
        return {"status": "ok", "workflow": wf}

    @app.post("/contusion/workflows/{name}/run")
    async def contusion_workflow_run(name: str):
        """Run a named workflow template."""
        cn = _require(_contusion, "contusion")
        try:
            result = await cn.run_workflow(name, caller_trust=400)
            _audit_contusion("workflow/run", f"{name}", result.get("success", False))
            return {"status": "ok", "result": result}
        except Exception as e:
            _audit_contusion("workflow/run", f"{name} failed: {e}", False)
            raise HTTPException(status_code=500, detail=str(e))

    # --- Contusion: Window-Aware Automation ---

    class ContusionWindowAutomateRequest(BaseModel):
        name: str
        actions: list[dict] = []

    @app.post("/contusion/window/automate")
    async def contusion_window_automate(req: ContusionWindowAutomateRequest):
        """Find a window by name and perform a sequence of actions on it."""
        cn = _require(_contusion, "contusion")
        try:
            result = await cn.automate_window(req.name, req.actions)
            _audit_contusion("window/automate", f"{req.name}: {len(req.actions)} actions",
                             result.get("success", False))
            return {"status": "ok", "result": result}
        except Exception as e:
            _audit_contusion("window/automate", f"{req.name} failed: {e}", False)
            raise HTTPException(status_code=500, detail=str(e))

    # --- Contusion: Clipboard ---

    @app.get("/contusion/clipboard")
    async def contusion_clipboard_get():
        """Get the current clipboard contents."""
        cn = _require(_contusion, "contusion")
        try:
            result = await cn.get_clipboard()
            return {"status": "ok", "result": result}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    class ContusionClipboardSetRequest(BaseModel):
        text: str

    @app.post("/contusion/clipboard")
    async def contusion_clipboard_set(req: ContusionClipboardSetRequest):
        """Set the clipboard contents."""
        cn = _require(_contusion, "contusion")
        try:
            result = await cn.set_clipboard(req.text)
            _audit_contusion("clipboard/set", f"{len(req.text)} chars",
                             result.get("success", False))
            return {"status": "ok", "result": result}
        except Exception as e:
            _audit_contusion("clipboard/set", f"failed: {e}", False)
            raise HTTPException(status_code=500, detail=str(e))

    # --- Contusion: Screen OCR ---

    class ContusionScreenReadRequest(BaseModel):
        region: Optional[dict] = None

    @app.post("/contusion/screen/read")
    async def contusion_screen_read(req: ContusionScreenReadRequest):
        """OCR a screen region to extract text (requires tesseract)."""
        cn = _require(_contusion, "contusion")
        try:
            result = await cn.read_screen_text(region=req.region)
            _audit_contusion("screen/read", f"region={req.region}",
                             result.get("success", False))
            return {"status": "ok", "result": result}
        except Exception as e:
            _audit_contusion("screen/read", f"failed: {e}", False)
            raise HTTPException(status_code=500, detail=str(e))

    # --- Contusion: Wait for Window ---

    class ContusionWaitWindowRequest(BaseModel):
        name: str
        timeout: int = 30

    @app.post("/contusion/window/wait")
    async def contusion_window_wait(req: ContusionWaitWindowRequest):
        """Wait for a window with the given name to appear."""
        cn = _require(_contusion, "contusion")
        try:
            result = await cn.wait_for_window(req.name, timeout=req.timeout)
            _audit_contusion("window/wait", f"{req.name} timeout={req.timeout}s",
                             result.get("success", False))
            return {"status": "ok", "result": result}
        except Exception as e:
            _audit_contusion("window/wait", f"{req.name} failed: {e}", False)
            raise HTTPException(status_code=500, detail=str(e))

    # --- Trust History ---

    @app.get("/trust-history")
    async def trust_history_list(limit: int = 50):
        """List trust history records for all PE executables."""
        history_dir = "/var/lib/pe-compat/trust-history"

        def _load_records():
            out = []
            for f in sorted(
                glob.glob(os.path.join(history_dir, "*.json")),
                key=os.path.getmtime,
                reverse=True,
            )[:limit]:
                try:
                    with open(f) as fh:
                        out.append(json.load(fh))
                except (json.JSONDecodeError, OSError):
                    continue
            return out

        records = await asyncio.get_running_loop().run_in_executor(None, _load_records)
        return {"status": "ok", "records": records}

    @app.get("/trust-history/{path_hash}")
    async def trust_history_detail(path_hash: str):
        """Get detailed trust history for a specific executable."""
        # Sanitize path_hash to prevent directory traversal: allow only
        # hex / alnum / dash / underscore. A path_hash is produced from
        # sha256/xxhash digests, so real values never contain '/'. '.', etc.
        import re
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", path_hash):
            raise HTTPException(status_code=400, detail="Invalid path_hash")
        history_file = f"/var/lib/pe-compat/trust-history/{path_hash}.json"
        if not os.path.exists(history_file):
            raise HTTPException(status_code=404, detail="Record not found")

        def _load():
            with open(history_file) as f:
                return json.load(f)
        try:
            record = await asyncio.get_running_loop().run_in_executor(None, _load)
        except (json.JSONDecodeError, OSError) as e:
            raise HTTPException(status_code=500, detail=f"Failed to read trust history: {e}")
        return {"status": "ok", "record": record}

    # --- Dashboard ---

    @app.get("/dashboard")
    async def system_dashboard():
        """Comprehensive system dashboard with all status info."""
        dashboard = {
            "daemon": {"status": "online", "uptime_seconds": int(time.time() - _start_time)},
            "controllers": {},
            "contusion": None,
            "trust": None,
        }
        # Controller status
        for name, ctrl in _controllers.items():
            dashboard["controllers"][name] = ctrl is not None
        # Contusion stats
        if _contusion:
            try:
                dashboard["contusion"] = {
                    "dictionary": _contusion.get_dictionary_stats(),
                    "macros": len(_contusion.list_macros()),
                    "apps": len(_contusion.get_app_library()),
                }
            except Exception:
                dashboard["contusion"] = {"error": "unavailable"}
        # Trust stats
        if _trust_observer:
            try:
                dashboard["trust"] = _trust_observer.get_summary()
            except Exception:
                dashboard["trust"] = {"error": "unavailable"}
        # Scanner stats
        if _scanner:
            try:
                dashboard["scanner"] = _scanner.get_stats()
            except Exception:
                dashboard["scanner"] = {"error": "unavailable"}
        # Stub discovery stats
        if _stub_discovery:
            try:
                dashboard["stub_discovery"] = {
                    "profiles": len(_stub_discovery.get_all_profiles()),
                    "coverage": _stub_discovery.get_dll_coverage(),
                }
            except Exception:
                dashboard["stub_discovery"] = {"error": "unavailable"}
        # Memory observer stats
        if _memory_observer:
            try:
                dashboard["memory_observer"] = _memory_observer.get_stats()
            except Exception:
                dashboard["memory_observer"] = {"error": "unavailable"}
        # Memory diff stats
        if _memory_diff:
            try:
                dashboard["memory_diff"] = _memory_diff.get_stats()
            except Exception:
                dashboard["memory_diff"] = {"error": "unavailable"}
        # Win API database stats
        if _win_api_db:
            try:
                dashboard["win_api_db"] = _win_api_db.get_stats()
            except Exception:
                dashboard["win_api_db"] = {"error": "unavailable"}
        # Stub generator stats
        if _stub_generator:
            try:
                dashboard["stub_generator"] = {
                    "generated": len(_stub_generator.get_generated()),
                    "templates": list(_stub_generator.list_templates().get("families", {}).keys()),
                }
            except Exception:
                dashboard["stub_generator"] = {"error": "unavailable"}
        # Binary signature database stats
        if _binary_signatures:
            try:
                dashboard["binary_signatures"] = _binary_signatures.get_stats()
            except Exception:
                dashboard["binary_signatures"] = {"error": "unavailable"}
        # Syscall monitor stats
        if _syscall_monitor:
            try:
                dashboard["syscall_monitor"] = _syscall_monitor.get_global_stats()
            except Exception:
                dashboard["syscall_monitor"] = {"error": "unavailable"}
        # Behavioral model stats
        if _behavioral_model:
            try:
                dashboard["behavioral_model"] = _behavioral_model.get_stats()
            except Exception:
                dashboard["behavioral_model"] = {"error": "unavailable"}
        return {"status": "ok", "dashboard": dashboard}

    # --- Audit Stats ---

    @app.get("/audit/stats")
    async def audit_stats():
        """Get audit statistics summary."""
        if not _audit:
            return {"status": "ok", "stats": {"available": False}}
        recent = _audit.get_recent(100)
        # Count by method, path, result
        by_method = {}
        by_result = {}
        for entry in recent:
            m = entry.get("method", "?")
            r = entry.get("result", "?")
            by_method[m] = by_method.get(m, 0) + 1
            by_result[r] = by_result.get(r, 0) + 1
        return {"status": "ok", "stats": {
            "total_recent": len(recent),
            "by_method": by_method,
            "by_result": by_result,
        }}

    # --- Pattern Scanner ---

    @app.get("/scanner/patterns")
    async def scanner_patterns():
        """List all scan patterns grouped by category."""
        sc = _require(_scanner, "scanner")
        groups = sc._group_by_category()
        result = {}
        for cat, pats in groups.items():
            result[cat] = [
                {
                    "id": p.id,
                    "bytes_hex": p.bytes_hex,
                    "description": p.description,
                    "severity": p.severity,
                    "metadata": p.metadata,
                }
                for p in pats
            ]
        return {"status": "ok", "categories": result,
                "total": len(sc.db.patterns)}

    @app.post("/scanner/scan/{pid}")
    async def scanner_scan(pid: int):
        """Scan a specific process's memory for all known patterns."""
        sc = _require(_scanner, "scanner")
        matches = await asyncio.get_running_loop().run_in_executor(
            None, sc.scan_process, pid
        )
        return {
            "status": "ok",
            "pid": pid,
            "matches": [
                {
                    "pattern_id": m.pattern_id,
                    "va": hex(m.va),
                    "region": m.region_label,
                    "category": m.category,
                    "description": m.description,
                    "context_hex": m.context_bytes.hex(),
                }
                for m in matches
            ],
            "total": len(matches),
        }

    @app.post("/scanner/analyze/{pid}")
    async def scanner_analyze(pid: int):
        """High-level behavioral analysis of a PE process."""
        sc = _require(_scanner, "scanner")
        analysis = await asyncio.get_running_loop().run_in_executor(
            None, sc.analyze_process, pid
        )
        return {"status": "ok", "analysis": analysis}

    @app.get("/scanner/stats")
    async def scanner_stats():
        """Get pattern scanner statistics.

        Read-only aggregate counts (patterns/scans/hits). Auth-exempt so
        external monitoring tools can poll liveness without a token — see
        auth.ENDPOINT_TRUST. Returns the ``unavailable`` envelope when the
        scanner is disabled in config.
        """
        if _scanner is None:
            return {
                "status": "unavailable",
                "patterns": 0,
                "scans": 0,
                "hits": 0,
                "stats": {},
            }
        try:
            stats = _scanner.get_stats() or {}
        except Exception as e:
            logger.warning("scanner/stats failed: %s", e)
            return {
                "status": "error",
                "patterns": 0,
                "scans": 0,
                "hits": 0,
                "error": str(e),
            }
        return {
            "status": "ok",
            "patterns": int(stats.get("total_patterns", 0)),
            "scans": int(stats.get("scans", 0)),
            "hits": int(stats.get("hits", 0)),
            "stats": stats,
        }

    @app.post("/scanner/patterns")
    async def scanner_add_pattern(req: AddPatternRequest):
        """Add a custom scan pattern to the database."""
        sc = _require(_scanner, "scanner")
        from pattern_scanner import Pattern
        pattern = Pattern(
            id=req.id,
            bytes_hex=req.bytes_hex,
            category=req.category,
            description=req.description,
            severity=req.severity,
            metadata=req.metadata,
        )
        sc.db.add_pattern(pattern)
        # Recompile patterns to include the new one
        sc._compile_patterns()
        # Persist custom patterns
        try:
            sc.db.save_custom()
        except Exception as e:
            logger.warning("Failed to persist custom pattern: %s", e)
        return {"status": "ok", "pattern_id": req.id,
                "total_patterns": len(sc.db.patterns)}

    # --- Stub Discovery Engine ---

    @app.get("/discovery/profiles")
    async def discovery_profiles():
        """List all analyzed PE process profiles."""
        sd = _require(_stub_discovery, "stub_discovery")
        return {"status": "ok", "profiles": sd.get_all_profiles()}

    @app.post("/discovery/analyze/{pid}")
    async def discovery_analyze(pid: int):
        """Analyze a running PE process's import dependencies and stub status."""
        sd = _require(_stub_discovery, "stub_discovery")
        try:
            profile = await sd.analyze_process(pid)
            return {"status": "ok", "profile": profile.to_full_dict()}
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Analysis failed: {e}")

    @app.get("/discovery/priority")
    async def discovery_priority():
        """Get cross-process priority list of APIs to implement next."""
        sd = _require(_stub_discovery, "stub_discovery")
        return {"status": "ok", "priority": sd.get_implementation_priority()}

    @app.get("/discovery/profile/{pid}")
    async def discovery_profile(pid: int):
        """Get the full analysis profile for a specific process."""
        sd = _require(_stub_discovery, "stub_discovery")
        profile = sd.get_profile(pid)
        if profile is None:
            raise HTTPException(
                status_code=404,
                detail=f"No profile found for PID {pid}. Run POST /discovery/analyze/{pid} first.",
            )
        return {"status": "ok", "profile": profile}

    @app.get("/discovery/coverage")
    async def discovery_coverage():
        """Get DLL stub coverage summary across all analyzed processes."""
        sd = _require(_stub_discovery, "stub_discovery")
        return {"status": "ok", "coverage": sd.get_dll_coverage()}

    @app.get("/discovery/categories")
    async def discovery_categories():
        """Get API implementation status grouped by functional category."""
        sd = _require(_stub_discovery, "stub_discovery")
        return {"status": "ok", **sd.get_category_summary()}

    @app.delete("/discovery/profile/{pid}")
    async def discovery_clear_profile(pid: int):
        """Remove a stored process profile."""
        sd = _require(_stub_discovery, "stub_discovery")
        if sd.clear_profile(pid):
            return {"status": "ok", "message": f"Profile for PID {pid} removed"}
        raise HTTPException(status_code=404, detail=f"No profile for PID {pid}")

    # --- Stub Generator (auto-generate C stubs for Windows APIs) ---

    class StubGenerateRequest(BaseModel):
        declaration: str = Field(..., description="C-style function declaration")
        dll: str = Field(default="kernel32.dll", description="Source DLL name")
        strategy: str = Field(default="auto", description="auto, template, or generic")

    class StubCompileRequest(BaseModel):
        function_name: str = Field(..., description="Previously generated function name")

    class StubDllRequest(BaseModel):
        dll: str = Field(..., description="DLL name, e.g. kernel32.dll")
        declarations: list[str] = Field(..., description="List of C declarations")

    @app.post("/generator/generate")
    async def generator_generate(req: StubGenerateRequest):
        """Generate a C stub implementation for a Windows API function."""
        sg = _require(_stub_generator, "stub_generator")
        try:
            from stub_generator import WinApiSignature
            sig = WinApiSignature.parse(req.declaration, dll=req.dll)
            result = sg.generate_stub(sig, strategy=req.strategy)
            return {"status": "ok", "function": sig.name, **{k: result[k] for k in ("code", "filename", "confidence", "notes", "signature")}}
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Generation failed: {e}")

    @app.post("/generator/compile")
    async def generator_compile(req: StubCompileRequest):
        """Compile a previously generated stub into a .so shared library."""
        sg = _require(_stub_generator, "stub_generator")
        filepath = sg.save_stub(req.function_name)
        if filepath is None:
            raise HTTPException(status_code=404, detail=f"No generated stub for '{req.function_name}'. POST /generator/generate first.")
        so_file = filepath.replace(".c", ".so")
        result = sg.compile_stub(filepath, so_file)
        return {"status": "ok" if result["success"] else "error", "c_file": filepath, "so_file": so_file if result["success"] else None, **result}

    @app.get("/generator/templates")
    async def generator_templates():
        """List all available stub generation templates by family."""
        sg = _require(_stub_generator, "stub_generator")
        return {"status": "ok", **sg.list_templates()}

    @app.post("/generator/dll")
    async def generator_dll(req: StubDllRequest):
        """Generate a complete .c file with stubs for all functions in a DLL."""
        sg = _require(_stub_generator, "stub_generator")
        try:
            from stub_generator import WinApiSignature
            sigs = [WinApiSignature.parse(d, dll=req.dll) for d in req.declarations]
            filepath = sg.save_dll(req.dll, sigs)
            return {"status": "ok", "dll": req.dll, "filepath": filepath, "function_count": len(sigs), "functions": [s.name for s in sigs]}
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"DLL generation failed: {e}")

    @app.get("/generator/generated")
    async def generator_generated():
        """List all stubs generated in this session."""
        sg = _require(_stub_generator, "stub_generator")
        return {"status": "ok", "stubs": sg.get_generated()}

    # --- Memory Observer (PE Memory Translator) ---

    class MemoryScanRequest(BaseModel):
        pattern_hex: str  # hex-encoded byte pattern, e.g. "4d5a9000"
        max_results: int = 100
        # Optional: pid can also be supplied in the request body. This is
        # a convenience override — callers may still pass ?pid=NNN as a
        # query parameter (backwards compatibility with older clients).
        pid: Optional[int] = None

    @app.get("/memory/processes")
    async def memory_processes():
        """List all tracked PE processes with a per-process memory summary.

        Read-only monitoring surface. Auth-exempt so external test
        harnesses (QEMU smoke test, monitoring daemons) can probe without
        a token. Returns ``{processes: [], count: 0, enabled: false}``
        when the memory observer is not loaded — an empty list is a
        valid steady state on a freshly-booted system with no PE
        processes.
        """
        if _memory_observer is None:
            return {
                "status": "unavailable",
                "enabled": False,
                "processes": [],
                "count": 0,
                "mode": "none",
                "stats": {},
            }
        try:
            tracked = await _memory_observer.get_all_tracked()
            if tracked is None:
                tracked = []
            stats = _memory_observer.get_stats() or {}
        except Exception as e:
            logger.warning("memory/processes failed: %s", e)
            return {
                "status": "error",
                "enabled": True,
                "processes": [],
                "count": 0,
                "mode": getattr(_memory_observer, "_mode", "unknown"),
                "stats": {},
                "error": str(e),
            }
        return {
            "status": "ok",
            "enabled": True,
            "mode": getattr(_memory_observer, "_mode", "unknown"),
            "processes": tracked,
            "count": len(tracked),
            "stats": stats,
        }

    @app.get("/memory/process/{pid}")
    async def memory_process_map(pid: int):
        """Get the full memory map for a specific process."""
        mo = _require(_memory_observer, "memory_observer")
        result = await mo.get_process_map(pid)
        if result is None:
            raise HTTPException(
                status_code=404,
                detail=f"Process {pid} not tracked or does not exist",
            )
        return {"status": "ok", **result}

    @app.get("/memory/process/{pid}/dlls")
    async def memory_process_dlls(pid: int):
        """Get loaded DLLs for a process."""
        mo = _require(_memory_observer, "memory_observer")
        dlls = await mo.get_loaded_dlls(pid)
        if dlls is None:
            raise HTTPException(
                status_code=404,
                detail=f"Process {pid} not tracked or does not exist",
            )
        return {"status": "ok", "pid": pid, "dlls": dlls, "count": len(dlls)}

    @app.get("/memory/process/{pid}/anomalies")
    async def memory_process_anomalies(pid: int):
        """Get detected memory anomalies for a process."""
        mo = _require(_memory_observer, "memory_observer")
        anomalies = await mo.get_memory_anomalies(pid)
        return {
            "status": "ok",
            "pid": pid,
            "anomalies": anomalies,
            "count": len(anomalies),
        }

    @app.get("/memory/process/{pid}/iat")
    async def memory_process_iat(pid: int):
        """Get IAT (Import Address Table) status for a process."""
        mo = _require(_memory_observer, "memory_observer")
        result = await mo.get_iat_status(pid)
        if result is None:
            raise HTTPException(
                status_code=404,
                detail=f"Process {pid} not tracked or does not exist",
            )
        return {"status": "ok", **result}

    @app.post("/memory/scan")
    async def memory_scan(req: MemoryScanRequest, pid: Optional[int] = None):
        """Scan a process's memory for a byte pattern.

        ``pid`` may be supplied either in the request body or as a query
        parameter (``?pid=1234``). The body field takes precedence when
        both are provided. Omitting both returns a 422.
        """
        mo = _require(_memory_observer, "memory_observer")
        # Prefer body.pid (explicit) over query-string pid (legacy).
        target_pid = req.pid if req.pid is not None else pid
        if target_pid is None:
            raise HTTPException(
                status_code=422,
                detail="pid is required (body field 'pid' or query param ?pid=...)",
            )
        try:
            pattern = bytes.fromhex(req.pattern_hex)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="Invalid hex pattern. Provide hex-encoded bytes, e.g. '4d5a9000'",
            )
        if len(pattern) < 2:
            raise HTTPException(
                status_code=400,
                detail="Pattern must be at least 2 bytes",
            )
        if req.max_results <= 0:
            raise HTTPException(
                status_code=400,
                detail="max_results must be positive",
            )
        matches = await mo.search_pattern(target_pid, pattern)
        # Respect max_results cap
        truncated = len(matches) > req.max_results
        matches = matches[:req.max_results]
        return {
            "status": "ok",
            "pid": target_pid,
            "pattern_hex": req.pattern_hex,
            "matches": matches,
            "count": len(matches),
            "truncated": truncated,
        }

    @app.get("/memory/anomalies")
    async def memory_all_anomalies():
        """Get all detected memory anomalies across all processes."""
        mo = _require(_memory_observer, "memory_observer")
        anomalies = await mo.get_memory_anomalies()
        return {
            "status": "ok",
            "anomalies": anomalies,
            "count": len(anomalies),
        }

    @app.get("/memory/stats")
    async def memory_stats():
        """Get memory observer statistics."""
        mo = _require(_memory_observer, "memory_observer")
        return {"status": "ok", "stats": mo.get_stats()}

    # --- Memory Diff Engine (snapshot capture & comparison) ---

    class SnapshotRequest(BaseModel):
        label: str = ""

    @app.post("/memory/snapshot/{pid}")
    async def memory_snapshot_capture(pid: int, req: SnapshotRequest = None):
        """Capture a memory snapshot for a process.

        Reads /proc/PID/maps and hashes readable regions so that later
        diffs can detect content changes, new DLLs, permission shifts,
        and potential code injection.
        """
        md = _require(_memory_diff, "memory_diff")
        label = req.label if req and req.label else ""
        try:
            snap = await md.capture_snapshot(pid, label=label)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc))
        return {
            "status": "ok",
            "pid": pid,
            "label": snap.label,
            "timestamp": snap.timestamp,
            "regions": snap.total_regions,
            "mapped": snap.total_mapped,
            "dlls": snap.dll_list,
            "hashed_regions": len(snap.region_hashes),
        }

    @app.get("/memory/snapshots/{pid}")
    async def memory_snapshot_list(pid: int):
        """List all captured snapshots for a process."""
        md = _require(_memory_diff, "memory_diff")
        snapshots = md.get_snapshots(pid)
        return {
            "status": "ok",
            "pid": pid,
            "snapshots": snapshots,
            "count": len(snapshots),
        }

    @app.get("/memory/diff/stats")
    async def memory_diff_stats():
        """Get memory diff engine statistics."""
        md = _require(_memory_diff, "memory_diff")
        return {"status": "ok", "stats": md.get_stats()}

    @app.get("/memory/diff/{pid}")
    async def memory_snapshot_diff(pid: int, a: str, b: str):
        """Diff two named snapshots for a process.

        Query parameters:
          a — label of the earlier snapshot
          b — label of the later snapshot
        """
        md = _require(_memory_diff, "memory_diff")
        diff = md.diff_snapshots(pid, a, b)
        if diff is None:
            raise HTTPException(
                status_code=404,
                detail=f"Snapshot '{a}' or '{b}' not found for PID {pid}",
            )

        def _region_summary(r: dict) -> dict:
            """Compact region representation for JSON response."""
            out = {
                "start": f"{r['start']:#x}",
                "end": f"{r['end']:#x}",
                "size": r["size"],
                "perms": r.get("perms", ""),
                "path": r.get("path", ""),
            }
            if "change" in r:
                out["change"] = r["change"]
            if "old_perms" in r:
                out["old_perms"] = r["old_perms"]
            return out

        return {
            "status": "ok",
            "pid": pid,
            "from": diff.snapshot_a,
            "to": diff.snapshot_b,
            "time_delta": round(diff.time_delta, 3),
            "memory_growth": diff.memory_growth,
            "region_count_delta": diff.region_count_delta,
            "new_regions": [_region_summary(r) for r in diff.new_regions],
            "removed_regions": [_region_summary(r) for r in diff.removed_regions],
            "modified_regions": [_region_summary(r) for r in diff.modified_regions],
            "new_dlls": diff.new_dlls,
            "removed_dlls": diff.removed_dlls,
            "anomalies": diff.anomalies,
            "summary": {
                "new": len(diff.new_regions),
                "removed": len(diff.removed_regions),
                "modified": len(diff.modified_regions),
                "anomalies": len(diff.anomalies),
            },
        }

    @app.get("/memory/timeline/{pid}")
    async def memory_snapshot_timeline(pid: int):
        """Get a chronological timeline of all changes across snapshots.

        Returns one entry per consecutive snapshot pair, summarising what
        changed between them — new regions, DLL loads, memory growth, and
        any anomalies detected.
        """
        md = _require(_memory_diff, "memory_diff")
        timeline = md.get_timeline(pid)
        return {
            "status": "ok",
            "pid": pid,
            "entries": timeline,
            "count": len(timeline),
        }

    @app.delete("/memory/snapshots/{pid}")
    async def memory_snapshot_clear(pid: int):
        """Delete all snapshots for a process."""
        md = _require(_memory_diff, "memory_diff")
        removed = md.clear_snapshots(pid)
        return {
            "status": "ok",
            "pid": pid,
            "removed": removed,
        }

    # --- Behavioral Model Engine ---

    @app.post("/behavioral/analyze/{pid}")
    async def behavioral_analyze(pid: int):
        """Full behavioral analysis of a PE process.

        Gathers data from memory observer, pattern scanner, stub discovery,
        and binary signature DB to produce a comprehensive fingerprint with
        compatibility score, failure predictions, and a detailed report.
        """
        bm = _require(_behavioral_model, "behavioral_model")
        try:
            fp = await bm.analyze(
                pid,
                memory_observer=_memory_observer,
                pattern_scanner=_scanner,
                stub_discovery=_stub_discovery,
                binary_db=_binary_signatures,
            )
            return {"status": "ok", "fingerprint": fp.to_full_dict()}
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Behavioral analysis failed: {e}")

    @app.get("/behavioral/fingerprint/{pid}")
    async def behavioral_fingerprint(pid: int):
        """Get the behavioral fingerprint for a previously analyzed process."""
        bm = _require(_behavioral_model, "behavioral_model")
        fp = bm.get_fingerprint(pid)
        if fp is None:
            raise HTTPException(
                status_code=404,
                detail=f"No fingerprint for PID {pid}. Run POST /behavioral/analyze/{pid} first.",
            )
        return {"status": "ok", "fingerprint": fp}

    @app.get("/behavioral/report/{pid}")
    async def behavioral_report(pid: int):
        """Get the detailed analysis report for a previously analyzed process."""
        bm = _require(_behavioral_model, "behavioral_model")
        report = bm.get_report(pid)
        if report is None:
            raise HTTPException(
                status_code=404,
                detail=f"No report for PID {pid}. Run POST /behavioral/analyze/{pid} first.",
            )
        return {"status": "ok", "report": report}

    @app.get("/behavioral/all")
    async def behavioral_all():
        """List all analyzed processes with summary fingerprints."""
        bm = _require(_behavioral_model, "behavioral_model")
        return {
            "status": "ok",
            "fingerprints": bm.get_all_fingerprints(),
            "stats": bm.get_stats(),
        }

    @app.get("/behavioral/predict/{pid}")
    async def behavioral_predict(pid: int):
        """Get failure predictions and recommended actions for a process."""
        bm = _require(_behavioral_model, "behavioral_model")
        predictions = bm.get_predictions(pid)
        if predictions is None:
            raise HTTPException(
                status_code=404,
                detail=f"No predictions for PID {pid}. Run POST /behavioral/analyze/{pid} first.",
            )
        return {"status": "ok", "predictions": predictions}

    @app.delete("/behavioral/fingerprint/{pid}")
    async def behavioral_clear(pid: int):
        """Remove a stored behavioral fingerprint."""
        bm = _require(_behavioral_model, "behavioral_model")
        if bm.clear_fingerprint(pid):
            return {"status": "ok", "message": f"Fingerprint for PID {pid} removed"}
        raise HTTPException(status_code=404, detail=f"No fingerprint for PID {pid}")

    # --- Binary Signature Database ---

    class ContributeProfileRequest(BaseModel):
        name: str
        exe_names: list[str] = []
        file_hashes: list[str] = []
        import_hash: str = ""
        required_dlls: list[str] = []
        required_drivers: list[str] = []
        graphics_api: str = "none"
        anti_cheat: str = "none"
        drm: str = "none"
        net_required: bool = False
        controller_support: str = "none"
        known_issues: list[str] = []
        workarounds: list[str] = []
        critical_apis: list[str] = []
        category: str = "unknown"
        engine: str = "custom"
        estimated_compatibility: float = 0.0
        version_notes: dict = {}

    @app.get("/signatures/identify/{path:path}")
    async def signatures_identify(path: str):
        """Identify a PE executable and return its pre-computed profile.

        If the binary is recognized (by name, hash, import table, or string
        signatures), the full dependency profile is returned instantly.
        """
        db = _require(_binary_signatures, "binary_signatures")
        exe_path = "/" + path if not path.startswith("/") else path
        profile = await asyncio.get_running_loop().run_in_executor(
            None, db.identify, exe_path
        )
        if profile is None:
            return {
                "status": "ok",
                "identified": False,
                "path": exe_path,
                "profile": None,
                "hint": "Unknown binary. Use POST /signatures/contribute to add it.",
            }
        return {
            "status": "ok",
            "identified": True,
            "path": exe_path,
            "profile": profile.to_dict(),
        }

    @app.get("/signatures/profiles")
    async def signatures_profiles(
        category: Optional[str] = None,
        engine: Optional[str] = None,
    ):
        """List all known binary profiles.

        Optional query params: ?category=game or ?engine=unreal
        """
        db = _require(_binary_signatures, "binary_signatures")
        if category:
            profiles = db.get_profiles_by_category(category)
        elif engine:
            profiles = db.get_profiles_by_engine(engine)
        else:
            profiles = db.get_all_profiles()
        return {
            "status": "ok",
            "profiles": profiles,
            "count": len(profiles),
        }

    @app.get("/signatures/stats")
    async def signatures_stats():
        """Get binary signature database statistics."""
        db = _require(_binary_signatures, "binary_signatures")
        return {"status": "ok", "stats": db.get_stats()}

    @app.post("/signatures/contribute")
    async def signatures_contribute(req: ContributeProfileRequest):
        """Submit a new binary profile to the signature database.

        The profile is registered in memory and persisted to disk so it
        survives daemon restarts.
        """
        db = _require(_binary_signatures, "binary_signatures")
        from binary_signatures import BinaryProfile
        import time as _time
        profile = BinaryProfile(
            name=req.name,
            exe_names=req.exe_names,
            file_hashes=req.file_hashes,
            import_hash=req.import_hash,
            required_dlls=req.required_dlls,
            required_drivers=req.required_drivers,
            graphics_api=req.graphics_api,
            anti_cheat=req.anti_cheat,
            drm=req.drm,
            net_required=req.net_required,
            controller_support=req.controller_support,
            known_issues=req.known_issues,
            workarounds=req.workarounds,
            critical_apis=req.critical_apis,
            category=req.category,
            engine=req.engine,
            estimated_compatibility=req.estimated_compatibility,
            added_date=_time.strftime("%Y-%m-%d"),
            source="community",
            version_notes=req.version_notes,
        )
        db._register(profile)
        saved_path = db.save_profile(profile)
        return {
            "status": "ok",
            "name": profile.name,
            "saved_to": saved_path,
            "total_profiles": len(db._profiles),
        }

    @app.get("/signatures/profile/{name}")
    async def signatures_profile_by_name(name: str):
        """Get a specific profile by name."""
        db = _require(_binary_signatures, "binary_signatures")
        profile = db.get_profile(name)
        if profile is None:
            raise HTTPException(
                status_code=404,
                detail=f"No profile named '{name}'. Use GET /signatures/profiles to list all.",
            )
        return {"status": "ok", "profile": profile}

    # --- Windows API Signature Database ---

    @app.get("/api-db/search")
    async def api_db_search(q: str = ""):
        """Search the Windows API signature database."""
        db = _require(_win_api_db, "win_api_db")
        if not q:
            raise HTTPException(status_code=400, detail="Query parameter 'q' is required")
        results = db.search(q)
        return {
            "status": "ok",
            "query": q,
            "results": [sig.to_dict() for sig in results],
            "count": len(results),
        }

    @app.get("/api-db/unimplemented")
    async def api_db_unimplemented(dll: Optional[str] = None):
        """List unimplemented Windows APIs, optionally filtered by DLL."""
        db = _require(_win_api_db, "win_api_db")
        results = db.get_unimplemented(dll)
        return {
            "status": "ok",
            "dll_filter": dll,
            "results": [sig.to_dict() for sig in results],
            "count": len(results),
        }

    @app.get("/api-db/stats")
    async def api_db_stats():
        """Get Windows API coverage statistics."""
        db = _require(_win_api_db, "win_api_db")
        return {"status": "ok", **db.get_stats()}

    @app.get("/api-db/dll/{dll_name}")
    async def api_db_by_dll(dll_name: str):
        """Get all function signatures for a specific DLL."""
        db = _require(_win_api_db, "win_api_db")
        if not dll_name.endswith(".dll"):
            dll_name = dll_name + ".dll"
        results = db.get_by_dll(dll_name)
        if not results:
            raise HTTPException(
                status_code=404,
                detail=f"No signatures found for DLL '{dll_name}'. "
                       f"Available: {', '.join(db.get_all_dlls())}",
            )
        impl = sum(1 for s in results if s.implemented)
        return {
            "status": "ok",
            "dll": dll_name,
            "functions": [sig.to_dict() for sig in results],
            "count": len(results),
            "implemented": impl,
            "unimplemented": len(results) - impl,
            "coverage_pct": round(impl / max(len(results), 1) * 100, 1),
        }

    @app.get("/api-db/category/{category}")
    async def api_db_by_category(category: str):
        """Get all function signatures in a functional category."""
        db = _require(_win_api_db, "win_api_db")
        results = db.get_by_category(category)
        if not results:
            raise HTTPException(
                status_code=404,
                detail=f"No signatures in category '{category}'. "
                       f"Available: {', '.join(db.get_all_categories())}",
            )
        impl = sum(1 for s in results if s.implemented)
        return {
            "status": "ok",
            "category": category,
            "functions": [sig.to_dict() for sig in results],
            "count": len(results),
            "implemented": impl,
            "unimplemented": len(results) - impl,
        }

    @app.get("/api-db/complexity/{complexity}")
    async def api_db_by_complexity(complexity: str):
        """Get all function signatures at a given complexity level."""
        db = _require(_win_api_db, "win_api_db")
        valid = ["trivial", "moderate", "complex", "needs_research"]
        if complexity not in valid:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid complexity '{complexity}'. Valid: {', '.join(valid)}",
            )
        results = db.get_by_complexity(complexity)
        return {
            "status": "ok",
            "complexity": complexity,
            "functions": [sig.to_dict() for sig in results],
            "count": len(results),
        }

    @app.get("/api-db/lookup/{dll_name}/{func_name}")
    async def api_db_lookup(dll_name: str, func_name: str):
        """Look up a specific function signature."""
        db = _require(_win_api_db, "win_api_db")
        if not dll_name.endswith(".dll"):
            dll_name = dll_name + ".dll"
        sig = db.lookup(dll_name, func_name)
        if sig is None:
            raise HTTPException(
                status_code=404,
                detail=f"Function '{func_name}' not found in '{dll_name}'",
            )
        return {"status": "ok", "signature": sig.to_dict()}

    @app.post("/api-db/mark-implemented/{dll_name}/{func_name}")
    async def api_db_mark_implemented(dll_name: str, func_name: str):
        """Mark a function as implemented."""
        db = _require(_win_api_db, "win_api_db")
        if not dll_name.endswith(".dll"):
            dll_name = dll_name + ".dll"
        sig = db.lookup(dll_name, func_name)
        if sig is None:
            raise HTTPException(
                status_code=404,
                detail=f"Function '{func_name}' not found in '{dll_name}'",
            )
        db.mark_implemented(dll_name, func_name)
        try:
            db.save()
        except Exception as e:
            logger.warning("Failed to persist API db: %s", e)
        return {"status": "ok", "dll": dll_name, "function": func_name, "implemented": True}

    @app.get("/api-db/dlls")
    async def api_db_list_dlls():
        """List all DLLs in the database."""
        db = _require(_win_api_db, "win_api_db")
        return {
            "status": "ok",
            "dlls": db.get_all_dlls(),
            "count": len(db.get_all_dlls()),
        }

    @app.get("/api-db/categories")
    async def api_db_list_categories():
        """List all functional categories."""
        db = _require(_win_api_db, "win_api_db")
        return {
            "status": "ok",
            "categories": db.get_all_categories(),
        }

    # ------------------------------------------------------------------ #
    #  Syscall-to-WinAPI Translator
    # ------------------------------------------------------------------ #

    class PathTranslateRequest(BaseModel):
        path: str

    class SyscallTranslateRequest(BaseModel):
        syscall_nr: int
        args: list = Field(default_factory=list)

    class NtSyscallTranslateRequest(BaseModel):
        nt_number: int
        args: list = Field(default_factory=list)

    class TranslatorSearchRequest(BaseModel):
        query: str

    @app.get("/translator/syscall/{nr}")
    async def translator_syscall(nr: int):
        """Translate a Linux x86-64 syscall number to its Windows API equivalent."""
        tr = _require(_syscall_translator, "syscall_translator")
        result = tr.translate(nr)
        return {"status": "ok", **result}

    @app.post("/translator/syscall")
    async def translator_syscall_with_args(req: SyscallTranslateRequest):
        """Translate a Linux syscall number with decoded arguments."""
        tr = _require(_syscall_translator, "syscall_translator")
        result = tr.translate(req.syscall_nr, req.args if req.args else None)
        return {"status": "ok", **result}

    @app.get("/translator/nt/{nr}")
    async def translator_nt_syscall(nr: int):
        """Translate a Windows NT syscall number to its NtXxx API name."""
        tr = _require(_syscall_translator, "syscall_translator")
        result = tr.translate_nt(nr)
        return {"status": "ok", **result}

    @app.post("/translator/nt")
    async def translator_nt_with_args(req: NtSyscallTranslateRequest):
        """Translate a Windows NT syscall number with decoded arguments."""
        tr = _require(_syscall_translator, "syscall_translator")
        result = tr.translate_nt(req.nt_number, req.args if req.args else None)
        return {"status": "ok", **result}

    @app.get("/translator/ioctl/{code}")
    async def translator_ioctl(code: str):
        """Decode a Windows IOCTL code into its components.

        Accepts hex (0x00070000) or decimal (458752) format.
        """
        tr = _require(_syscall_translator, "syscall_translator")
        try:
            if code.startswith("0x") or code.startswith("0X"):
                code_int = int(code, 16)
            else:
                code_int = int(code)
        except ValueError:
            raise HTTPException(status_code=400,
                                detail=f"Invalid IOCTL code: {code!r}. "
                                       "Use hex (0x00070000) or decimal.")
        result = tr.decode_ioctl(code_int)
        return {"status": "ok", **result}

    @app.post("/translator/path")
    async def translator_path(req: PathTranslateRequest):
        """Translate a Linux path to its Windows equivalent for PE processes."""
        tr = _require(_syscall_translator, "syscall_translator")
        result = tr.translate_file_path(req.path)
        return {"status": "ok", **result}

    @app.get("/translator/stats")
    async def translator_stats():
        """Get translation table statistics."""
        tr = _require(_syscall_translator, "syscall_translator")
        return {"status": "ok", "stats": tr.get_stats()}

    @app.post("/translator/search")
    async def translator_search(req: TranslatorSearchRequest):
        """Search across all translation tables by API name or keyword."""
        tr = _require(_syscall_translator, "syscall_translator")
        if not req.query or len(req.query) < 2:
            raise HTTPException(status_code=400,
                                detail="Search query must be at least 2 characters.")
        result = tr.search(req.query)
        return {"status": "ok", **result}

    # ------------------------------------------------------------------ #
    #  Syscall Monitor (live PE process syscall tracing)
    # ------------------------------------------------------------------ #

    @app.get("/syscall/processes")
    async def syscall_tracked_processes():
        """List all processes being tracked by the syscall monitor."""
        sm = _require(_syscall_monitor, "syscall_monitor")
        tracked = await sm.get_all_tracked()
        return {
            "status": "ok",
            "mode": sm._mode,
            "processes": tracked,
            "count": len(tracked),
            "stats": sm.get_global_stats(),
        }

    @app.get("/syscall/trace/{pid}")
    async def syscall_trace(pid: int, limit: int = 100):
        """Get the full syscall trace for a PE process.

        Each event shows the Linux syscall, the equivalent Windows API,
        arguments, return value, and timestamp.
        """
        sm = _require(_syscall_monitor, "syscall_monitor")
        trace = await sm.get_trace(pid, limit=min(limit, 4096))
        if trace is None:
            raise HTTPException(
                status_code=404,
                detail=f"Process {pid} not tracked by syscall monitor",
            )
        return {
            "status": "ok",
            "pid": pid,
            "events": trace,
            "count": len(trace),
        }

    @app.get("/syscall/stats/{pid}")
    async def syscall_stats(pid: int):
        """Get syscall frequency statistics for a PE process.

        Shows how many times each syscall was called, with Windows API
        translations and categorization.
        """
        sm = _require(_syscall_monitor, "syscall_monitor")
        stats = await sm.get_stats(pid)
        if stats is None:
            raise HTTPException(
                status_code=404,
                detail=f"Process {pid} not tracked by syscall monitor",
            )
        return {"status": "ok", **stats}

    @app.get("/syscall/ioctls/{pid}")
    async def syscall_ioctls(pid: int):
        """Get ioctl analysis for a PE process.

        Shows what drivers or devices the process is communicating with,
        translated into Windows DeviceIoControl equivalents.
        """
        sm = _require(_syscall_monitor, "syscall_monitor")
        ioctls = await sm.get_ioctl_analysis(pid)
        if ioctls is None:
            raise HTTPException(
                status_code=404,
                detail=f"Process {pid} not tracked by syscall monitor",
            )
        return {
            "status": "ok",
            "pid": pid,
            "ioctls": ioctls,
            "count": len(ioctls),
        }

    @app.get("/syscall/files/{pid}")
    async def syscall_files(pid: int):
        """Get file access log for a PE process.

        Shows which files were opened, read, written, with Windows API
        translation (CreateFile, ReadFile, WriteFile, etc.).
        """
        sm = _require(_syscall_monitor, "syscall_monitor")
        files = await sm.get_file_access(pid)
        if files is None:
            raise HTTPException(
                status_code=404,
                detail=f"Process {pid} not tracked by syscall monitor",
            )
        return {
            "status": "ok",
            "pid": pid,
            "file_operations": files,
            "count": len(files),
        }

    @app.get("/syscall/network/{pid}")
    async def syscall_network(pid: int):
        """Get network activity for a PE process.

        Shows socket creation, connections, binds, sends and receives,
        translated into Winsock API equivalents.
        """
        sm = _require(_syscall_monitor, "syscall_monitor")
        network = await sm.get_network_activity(pid)
        if network is None:
            raise HTTPException(
                status_code=404,
                detail=f"Process {pid} not tracked by syscall monitor",
            )
        return {
            "status": "ok",
            "pid": pid,
            "network_activity": network,
            "count": len(network),
        }

    @app.get("/syscall/behavior/{pid}")
    async def syscall_behavior(pid: int):
        """Get behavioral classification for a PE process.

        Analyzes syscall patterns to classify the process (driver_heavy,
        network_heavy, file_heavy, etc.) and compute a risk score.
        Used by the cortex decision engine for autonomous responses.
        """
        sm = _require(_syscall_monitor, "syscall_monitor")
        summary = await sm.get_behavioral_summary(pid)
        if summary is None:
            raise HTTPException(
                status_code=404,
                detail=f"Process {pid} not tracked by syscall monitor",
            )
        return {"status": "ok", "pid": pid, **summary}

    @app.post("/syscall/track/{pid}")
    async def syscall_start_tracking(pid: int, subject_id: int = 0):
        """Manually start tracking a PE process."""
        sm = _require(_syscall_monitor, "syscall_monitor")
        ok = await sm.start_tracking(pid, subject_id)
        if not ok:
            raise HTTPException(
                status_code=409,
                detail=f"Process {pid} is already being tracked",
            )
        return {"status": "ok", "pid": pid, "tracking": True}

    @app.delete("/syscall/track/{pid}")
    async def syscall_stop_tracking(pid: int):
        """Manually stop tracking a PE process."""
        sm = _require(_syscall_monitor, "syscall_monitor")
        ok = await sm.stop_tracking(pid)
        if not ok:
            raise HTTPException(
                status_code=404,
                detail=f"Process {pid} is not being tracked",
            )
        return {"status": "ok", "pid": pid, "tracking": False}

    # --- Comprehensive Analysis (runs ALL engines on a PE process) ---

    @app.post("/analyze/{pid}")
    async def full_analysis(pid: int):
        """Run complete analysis: memory + patterns + stubs + signatures + syscalls + behavior.

        Invokes every available analysis engine on a single PE process and
        returns the combined results in one response.  Each engine is
        fault-isolated -- a failure in one does not block the others.
        """
        results = {}

        # Memory observer: process memory map and anomalies
        if _memory_observer:
            try:
                proc_map = await _memory_observer.get_process_map(pid)
                anomalies = await _memory_observer.get_memory_anomalies(pid)
                results["memory"] = {
                    "map": proc_map,
                    "anomalies": anomalies,
                }
            except Exception as e:
                results["memory"] = {"error": str(e)}

        # Pattern scanner: byte-pattern matches
        if _scanner:
            try:
                matches = await asyncio.get_running_loop().run_in_executor(
                    None, _scanner.scan_process, pid
                )
                results["patterns"] = {
                    "matches": [
                        {
                            "pattern_id": m.pattern_id,
                            "va": hex(m.va),
                            "region": m.region_label,
                            "category": m.category,
                            "description": m.description,
                        }
                        for m in matches
                    ],
                    "total": len(matches),
                }
            except Exception as e:
                results["patterns"] = {"error": str(e)}

        # Stub discovery: import table analysis
        if _stub_discovery:
            try:
                profile = await _stub_discovery.analyze_process(pid)
                results["stubs"] = profile.to_full_dict()
            except Exception as e:
                results["stubs"] = {"error": str(e)}

        # Binary signature database: identify the executable
        if _binary_signatures:
            try:
                exe_path = f"/proc/{pid}/exe"
                profile = await asyncio.get_running_loop().run_in_executor(
                    None, _binary_signatures.identify, exe_path
                )
                results["signature"] = profile.to_dict() if profile else None
            except Exception as e:
                results["signature"] = {"error": str(e)}

        # Syscall monitor: recent syscall trace and behavioral summary
        if _syscall_monitor:
            try:
                trace = await _syscall_monitor.get_trace(pid, limit=50)
                behavior = await _syscall_monitor.get_behavioral_summary(pid)
                results["syscalls"] = {
                    "trace": trace,
                    "behavior": behavior,
                }
            except Exception as e:
                results["syscalls"] = {"error": str(e)}

        # Memory diff: snapshot timeline (if any snapshots exist)
        if _memory_diff:
            try:
                timeline = _memory_diff.get_timeline(pid)
                snapshots = _memory_diff.get_snapshots(pid)
                results["memory_diff"] = {
                    "snapshots": len(snapshots),
                    "timeline": timeline,
                }
            except Exception as e:
                results["memory_diff"] = {"error": str(e)}

        # Behavioral model: full AI-driven behavioral fingerprint (runs last
        # because it can consume data from the other engines)
        if _behavioral_model:
            try:
                fp = await _behavioral_model.analyze(
                    pid,
                    memory_observer=_memory_observer,
                    pattern_scanner=_scanner,
                    stub_discovery=_stub_discovery,
                    binary_db=_binary_signatures,
                )
                results["behavioral"] = fp.to_full_dict()
            except Exception as e:
                results["behavioral"] = {"error": str(e)}

        return {"status": "ok", "pid": pid, "analysis": results}

    # --- /system/summary (factory-based, unit-tested) ---
    # The app_state mapping is read on every summary request, so
    # late-initialised subsystems (e.g. those started from lifespan)
    # appear automatically once present.
    try:
        from system_summary import make_summary_router
        _summary_state: dict = {
            "scanner": _scanner,
            "memory_observer": _memory_observer,
            "memory_diff": _memory_diff,
            "stub_discovery": _stub_discovery,
            "binary_signatures": _binary_signatures,
            "win_api_db": _win_api_db,
            "stub_generator": _stub_generator,
            "syscall_monitor": _syscall_monitor,
            "syscall_translator": _syscall_translator,
            "behavioral_model": _behavioral_model,
            "thermal": _thermal,
            "power": _power,
            "contusion": _contusion,
            "firewall": _firewall,
            "audit": _audit,
            "session": os.environ.get("XDG_SESSION_TYPE", "headless"),
            "ready": True,  # create_app completed; lifespan start runs shortly
            # Omit start_monotonic: the factory falls back to its own
            # module-level _BOOT_MONOTONIC (set at import), which is a
            # valid time.monotonic() origin. _start_time is wall-clock
            # (time.time()) and MUST NOT be passed here.
        }
        app.include_router(make_summary_router(_summary_state))
        logger.info("Registered /system/summary factory router")
    except Exception as e:
        logger.error("Failed to register /system/summary router: %s", e)

    return app


async def start_server(app, host: str, port: int, ready_event=None):
    """Start the uvicorn server.

    access_log is intentionally disabled: every request already gets audit-
    logged (see audit.py) with full caller identity, path, and status. The
    uvicorn access log was a redundant second write + format pass per
    request — ~5-10% of CPU on tiny endpoints like /health under load.
    Pick httptools + uvloop where available for additional throughput.

    If `ready_event` is provided, it is set() once uvicorn has finished
    startup (lifespan.startup complete + socket bound). Callers use this
    to gate systemd `READY=1` notification so the service unit's
    `Type=notify` contract reflects real HTTP readiness, not just the
    Python process being alive.
    """
    import uvicorn

    kwargs = {
        "app": app,
        "host": host,
        "port": port,
        "log_level": "info",
        "access_log": False,
    }
    # Prefer uvloop/httptools when installed; Uvicorn silently falls back
    # on systems that don't have them (e.g. headless QEMU smoke tests).
    try:
        import uvloop  # noqa: F401
        kwargs["loop"] = "uvloop"
    except ImportError:
        pass
    try:
        import httptools  # noqa: F401
        kwargs["http"] = "httptools"
    except ImportError:
        pass
    config = uvicorn.Config(**kwargs)
    server = uvicorn.Server(config)

    if ready_event is not None:
        async def _signal_when_started():
            # uvicorn.Server.started flips to True after lifespan.startup
            # completes AND the socket is accepting. Poll at 50 ms; typical
            # wait is <1 s on warm disk.
            while not server.started:
                await asyncio.sleep(0.05)
            ready_event.set()
        # Keep a strong reference to the task; bare asyncio.create_task()
        # returns a weakly-held Task that the GC can collect mid-flight
        # (CPython RuntimeWarning: "Task was destroyed but it is pending!"),
        # leaving ready_event permanently unset and systemd hanging on
        # Type=notify. Cancel it on shutdown so a stuck poll doesn't linger.
        _ready_signal_task = asyncio.create_task(_signal_when_started())
        try:
            await server.serve()
        finally:
            if not _ready_signal_task.done():
                _ready_signal_task.cancel()
                try:
                    await _ready_signal_task
                except (asyncio.CancelledError, Exception):
                    pass
    else:
        await server.serve()
