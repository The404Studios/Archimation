"""
Cortex REST API -- human interface for the AI cortex.

Exposes cortex state, autonomy controls, pending decisions, and event history
via FastAPI on port 8421 (the AI daemon uses 8420).
"""

import logging
import time
from typing import Optional

from .autonomy import (
    AutonomyController, AutonomyLevel, ALL_DOMAINS, Decision,
    MAX_AUTONOMY_LEVEL,
)
from .decision_engine import DecisionEngine
from .orchestrator import Orchestrator
from .event_bus import EventBus
from .trust_history import TrustHistoryStore

logger = logging.getLogger("cortex.api")

# Import start time for uptime calculation
_start_time = time.time()


def create_cortex_api(
    autonomy: AutonomyController,
    orchestrator: Orchestrator,
    handlers: object,
    bus: EventBus,
    trust_history: Optional[TrustHistoryStore] = None,
    decision_engine: Optional[DecisionEngine] = None,
) -> object:
    """
    Create and return a FastAPI app wired to the live cortex components.

    Args:
        autonomy: The AutonomyController instance.
        orchestrator: The Orchestrator instance.
        handlers: The CortexHandlers instance (has recent_events, events_processed).
        bus: The EventBus instance.
        trust_history: The TrustHistoryStore instance (optional).
        decision_engine: The DecisionEngine instance (optional).

    Returns:
        A FastAPI application.
    """
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel

    # Lazy-initialized pattern scanner (shared across requests).
    # Instantiating PatternDatabase + MemoryScanner on every request parses
    # the pattern DB each time, which is expensive and needlessly allocates.
    _scanner_cache: dict = {"db": None, "scanner": None, "available": None}

    def _get_scanner():
        if _scanner_cache["available"] is False:
            return None, None
        if _scanner_cache["scanner"] is not None:
            return _scanner_cache["db"], _scanner_cache["scanner"]
        try:
            from ..daemon.pattern_scanner import MemoryScanner, PatternDatabase
            db = PatternDatabase()
            scanner = MemoryScanner(db)
            _scanner_cache["db"] = db
            _scanner_cache["scanner"] = scanner
            _scanner_cache["available"] = True
            return db, scanner
        except Exception:
            _scanner_cache["available"] = False
            return None, None

    app = FastAPI(
        title="AI Cortex",
        description="Central nervous system of AI Arch Linux",
        version="0.1.0",
    )

    # -- Request/response models ---------------------------------------------

    class AutonomySetRequest(BaseModel):
        level: int

    class DecisionActionRequest(BaseModel):
        reason: Optional[str] = None

    # -- GET /health ----------------------------------------------------------

    @app.get("/health")
    async def health():
        """Cortex health check."""
        return {
            "status": "ok",
            "uptime_seconds": round(time.time() - _start_time, 1),
            "trust_device": orchestrator.trust_available,
            "event_bus_running": bus.stats["running"],
        }

    # Rate-limit cache for /status -- dashboards poll this every 1-2s and
    # regenerating full autonomy/orchestrator state is ~200us on old hw.
    # Cache the heavy sub-dicts for 500ms so tight polls don't walk the
    # whole state graph on every request.
    _status_cache: dict = {"ts": 0.0, "result": None}
    _STATUS_CACHE_TTL = 0.5

    # -- GET /status ----------------------------------------------------------

    @app.get("/status")
    async def status():
        """Full cortex state: autonomy, events, decisions, orchestrator stats."""
        now = time.time()
        cached = _status_cache["result"]
        if cached is not None and now - _status_cache["ts"] < _STATUS_CACHE_TTL:
            # Return a shallow copy so callers can't mutate the cache.
            result = dict(cached)
            result["uptime_seconds"] = round(now - _start_time, 1)
            return result

        result = {
            "version": "0.1.0",
            "uptime_seconds": round(now - _start_time, 1),
            "autonomy": autonomy.state,
            "orchestrator": orchestrator.stats,
            "event_bus": bus.stats,
            "events_processed": handlers.events_processed,
        }
        if trust_history is not None:
            result["trust_history"] = trust_history.stats
        if decision_engine is not None:
            result["decision_engine"] = decision_engine.stats

        # Memory scanner stats -- use O(1) running counters maintained on
        # the handler when each event is recorded, instead of walking the
        # whole recent_events ring buffer 5 times per /status poll.  The
        # old path was O(N*K) per request (K=5 substring scans) and showed
        # up in p99 latency under dashboard polling.
        counts = getattr(handlers, "action_counts", None)
        if counts is None:
            counts = {
                "memory_anomaly": 0, "memory_pattern": 0,
                "memory_stub": 0, "memory_map": 0,
            }
        total_memory = (
            counts.get("memory_anomaly", 0)
            + counts.get("memory_pattern", 0)
            + counts.get("memory_stub", 0)
            + counts.get("memory_map", 0)
        )
        result["memory_scanner"] = {
            "recent_memory_events": total_memory,
            "anomalies": counts.get("memory_anomaly", 0),
            "patterns": counts.get("memory_pattern", 0),
            "stub_calls": counts.get("memory_stub", 0),
            "memory_maps": counts.get("memory_map", 0),
        }

        # Try to include scanner module stats (pattern DB info)
        db, _ = _get_scanner()
        if db is not None:
            try:
                cats = set(p.category for p in db.patterns.values())
                result["memory_scanner"]["pattern_database"] = {
                    "total_patterns": len(db.patterns),
                    "categories": sorted(cats),
                }
            except Exception:
                result["memory_scanner"]["pattern_database"] = {"status": "unavailable"}
        else:
            result["memory_scanner"]["pattern_database"] = {"status": "unavailable"}

        # Cache the assembled result for rapid re-poll.
        _status_cache["ts"] = now
        _status_cache["result"] = result
        return result

    # -- GET /decision-engine -------------------------------------------------

    @app.get("/decision-engine")
    async def get_decision_engine():
        """Decision engine statistics, policy rules, and verdict counts."""
        if decision_engine is None:
            return {"status": "not configured"}
        return {
            "stats": decision_engine.stats,
            "rules": decision_engine.rules,
        }

    # -- GET /autonomy --------------------------------------------------------

    @app.get("/autonomy")
    async def get_autonomy():
        """Current autonomy levels per domain."""
        return autonomy.state

    # -- POST /autonomy/{domain} ----------------------------------------------

    @app.post("/autonomy/{domain}")
    async def set_autonomy(domain: str, body: AutonomySetRequest):
        """
        Set autonomy level for a specific domain (human override).

        Level must be 0-4. The effective level will still be clamped
        to the score-based ceiling.
        """
        if domain not in ALL_DOMAINS:
            raise HTTPException(
                status_code=404,
                detail=f"Unknown domain: {domain}. Valid: {ALL_DOMAINS}",
            )

        level = max(0, min(int(MAX_AUTONOMY_LEVEL), body.level))

        # Save old level BEFORE overwriting so we can detect a downward change
        old_level = autonomy._configured_levels.get(domain, 2)

        # Access the internal configured levels dict
        autonomy._configured_levels[domain] = level

        # This is a human interaction -- reset the dead-man timer
        autonomy.record_human_interaction()

        effective = autonomy.effective_level(domain)
        level_name = AutonomyLevel(effective).name

        logger.info(
            "Human override: %s configured=%d effective=%d (%s)",
            domain, level, effective, level_name,
        )

        # If the human lowered autonomy, record the score penalty
        if level < old_level:
            autonomy.record_manual_lower()

        return {
            "domain": domain,
            "configured_level": level,
            "effective_level": effective,
            "effective_name": level_name,
            "score": autonomy.score,
            "ceiling": autonomy.ceiling,
        }

    # -- GET /decisions/pending -----------------------------------------------

    @app.get("/decisions/pending")
    async def get_pending():
        """List decisions awaiting human approval."""
        pending = autonomy.get_pending()

        def _level_name(lvl: int) -> str:
            # Mirror AutonomyController._level_name; Session 23 pattern.
            try:
                return AutonomyLevel(lvl).name
            except ValueError:
                return f"LEVEL_{lvl}"

        return {
            "count": len(pending),
            "decisions": [
                {
                    "index": i,
                    "domain": d.domain,
                    "action": d.action,
                    "description": d.description,
                    "autonomy_level": d.autonomy_level,
                    "level_name": _level_name(d.autonomy_level),
                    "timestamp": d.timestamp,
                    # Follow-through metadata (Session 25): surfaces
                    # the gated pid and expiry deadline so the UI can
                    # show how much time is left before auto-deny.
                    "pid": d.pid,
                    "expires_at": d.expires_at,
                    "expires_in_s": (
                        round(d.expires_at - time.time(), 1)
                        if d.expires_at is not None else None
                    ),
                    "has_resume_action": d.resume_action is not None,
                    "has_reject_action": d.reject_action is not None,
                }
                for i, d in enumerate(pending)
            ],
        }

    # -- POST /decisions/{index}/approve --------------------------------------

    @app.post("/decisions/{index}/approve")
    async def approve_decision(index: int, body: DecisionActionRequest):
        """Approve a pending decision by index.

        If the decision was gating a frozen PID, the resume callback
        (registered by the handler that froze it) fires inside
        approve_pending -- so a SIGSTOP'd PE process gets SIGCONT here.
        """
        pending = autonomy.get_pending()
        if index < 0 or index >= len(pending):
            raise HTTPException(
                status_code=404,
                detail=f"No pending decision at index {index} (have {len(pending)})",
            )
        # Capture pid BEFORE approve (which pops from the pending list)
        gated_pid = pending[index].pid
        had_resume = pending[index].resume_action is not None
        if autonomy.approve_pending(index):
            autonomy.record_correct()
            logger.info(
                "Decision %d approved by human (pid=%s, resume_fired=%s)",
                index, gated_pid, had_resume,
            )
            return {
                "success": True,
                "message": f"Decision {index} approved",
                "gated_pid": gated_pid,
                "resume_callback_fired": had_resume,
            }
        raise HTTPException(status_code=404, detail=f"No pending decision at index {index}")

    # -- POST /decisions/{index}/deny -----------------------------------------

    @app.post("/decisions/{index}/deny")
    async def deny_decision(index: int, body: DecisionActionRequest):
        """Deny a pending decision by index. Records a false-positive score penalty.

        If the decision was gating a frozen PID, the reject callback
        (registered by the handler that froze it) fires inside
        deny_pending -- so a SIGSTOP'd PE process gets SIGKILL'd here
        instead of leaking as a ghost.
        """
        pending = autonomy.get_pending()
        if index < 0 or index >= len(pending):
            raise HTTPException(
                status_code=404,
                detail=f"No pending decision at index {index} (have {len(pending)})",
            )
        gated_pid = pending[index].pid
        had_reject = pending[index].reject_action is not None
        if autonomy.deny_pending(index):
            logger.info(
                "Decision %d denied by human (pid=%s, reject_fired=%s)",
                index, gated_pid, had_reject,
            )
            return {
                "success": True,
                "message": f"Decision {index} denied (score penalty applied)",
                "new_score": autonomy.score,
                "gated_pid": gated_pid,
                "reject_callback_fired": had_reject,
            }
        raise HTTPException(status_code=404, detail=f"No pending decision at index {index}")

    # -- POST /emergency-stop -------------------------------------------------

    @app.post("/emergency-stop")
    async def emergency_stop():
        """PANIC BUTTON: immediately drop ALL domains to OBSERVE (level 0).

        Score is zeroed.  Only a human setting autonomy levels back up
        via POST /autonomy/{domain} can restore operation.
        """
        autonomy.emergency_stop("API emergency-stop endpoint invoked")
        autonomy.record_human_interaction()
        logger.critical("EMERGENCY STOP triggered via API")
        return {
            "success": True,
            "message": "Emergency stop activated. All domains set to OBSERVE.",
            "score": autonomy.score,
            "ceiling": autonomy.ceiling,
        }

    # -- GET /events/recent ---------------------------------------------------

    @app.get("/events/recent")
    async def recent_events():
        """Recent events (last 100)."""
        events = handlers.recent_events
        return {
            "count": len(events),
            "total_processed": handlers.events_processed,
            "events": events,
        }

    # -- GET /scores ----------------------------------------------------------

    @app.get("/scores")
    async def scores():
        """Trust score history for the cortex itself."""
        state = autonomy.state
        return {
            "current_score": state["score"],
            "ceiling": state["ceiling"],
            "ceiling_name": state["ceiling_name"],
            "history_length": state["score_history_len"],
            "recent": state["recent_score_history"],
        }

    # -- GET /trust-history ---------------------------------------------------

    @app.get("/trust-history")
    async def get_trust_history():
        """List all per-executable trust records with reliability scores."""
        if trust_history is None:
            raise HTTPException(status_code=503, detail="Trust history store not available")

        records = trust_history.get_all()
        return {
            "stats": trust_history.stats,
            "records": [r.to_api_dict() for r in records],
        }

    # -- GET /trust-history/{exe_path:path} -----------------------------------

    @app.get("/trust-history/{exe_path:path}")
    async def get_trust_history_entry(exe_path: str):
        """Get trust record for a specific executable path."""
        if trust_history is None:
            raise HTTPException(status_code=503, detail="Trust history store not available")

        record = trust_history.get(exe_path)
        if record is None:
            raise HTTPException(status_code=404, detail=f"No trust history for: {exe_path}")

        return record.to_api_dict()

    # -- GET /scanner -----------------------------------------------------------

    @app.get("/scanner")
    async def get_scanner_status():
        """Memory scanner status and recent pattern matches.

        Returns scanner stats (pattern count, categories) and the last
        memory-related events captured by the cortex handlers.
        """
        _, scanner = _get_scanner()
        if scanner is not None:
            try:
                scanner_stats = scanner.get_stats()
            except Exception:
                scanner_stats = {"status": "unavailable"}
        else:
            scanner_stats = {"status": "unavailable"}

        # Collect recent memory events from the handler buffer
        recent_memory = [
            e for e in handlers.recent_events
            if any(tag in e.get("action", "") for tag in (
                "memory anomaly", "pattern:", "stub:",
            ))
        ]

        return {
            "scanner": scanner_stats,
            "recent_memory_events": recent_memory[-50:],
            "total_memory_events": len(recent_memory),
        }

    # -- POST /scanner/scan/{pid} ----------------------------------------------

    @app.post("/scanner/scan/{pid}")
    async def scan_process(pid: int):
        """Trigger a memory scan of a running process by PID.

        Returns all pattern matches found in the process memory.

        Input validation: PID must be > 0 and within PID_MAX range.
        Scan runs in the default executor so its blocking /proc/<pid>/mem
        reads don't stall the asyncio event loop (and all the other API
        handlers that share it).
        """
        # Input validation -- reject nonsense PIDs early instead of letting
        # the scanner choke on them.
        if pid <= 0 or pid > 4_194_304:  # Linux PID_MAX = 4M by default
            raise HTTPException(status_code=400, detail=f"Invalid PID: {pid}")

        _, scanner = _get_scanner()
        if scanner is None:
            raise HTTPException(
                status_code=503,
                detail="Pattern scanner module not available",
            )

        import asyncio as _asyncio
        loop = _asyncio.get_running_loop()
        try:
            analysis = await loop.run_in_executor(
                None, scanner.analyze_process, pid,
            )
        except Exception as exc:
            raise HTTPException(
                status_code=500,
                detail=f"Scan failed for PID {pid}: {exc}",
            )

        return analysis

    return app
