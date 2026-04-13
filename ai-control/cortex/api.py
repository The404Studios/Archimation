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

    # TODO: Add rate limiting on API endpoints (e.g. slowapi or custom middleware).
    # Acceptable for development; required before production deployment.
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

    # -- GET /status ----------------------------------------------------------

    @app.get("/status")
    async def status():
        """Full cortex state: autonomy, events, decisions, orchestrator stats."""
        result = {
            "version": "0.1.0",
            "uptime_seconds": round(time.time() - _start_time, 1),
            "autonomy": autonomy.state,
            "orchestrator": orchestrator.stats,
            "event_bus": bus.stats,
            "events_processed": handlers.events_processed,
        }
        if trust_history is not None:
            result["trust_history"] = trust_history.stats
        if decision_engine is not None:
            result["decision_engine"] = decision_engine.stats

        # Memory scanner stats -- summarize recent memory events from handlers
        memory_events = [
            e for e in handlers.recent_events
            if any(tag in e.get("action", "") for tag in (
                "memory anomaly", "pattern:", "stub:", "map:",
            ))
        ]
        result["memory_scanner"] = {
            "recent_memory_events": len(memory_events),
            "anomalies": sum(
                1 for e in memory_events
                if "memory anomaly" in e.get("action", "")
            ),
            "patterns": sum(
                1 for e in memory_events
                if "pattern:" in e.get("action", "")
            ),
            "stub_calls": sum(
                1 for e in memory_events
                if "stub:" in e.get("action", "")
            ),
            "memory_maps": sum(
                1 for e in memory_events
                if "map:" in e.get("action", "")
            ),
        }

        # Try to include scanner module stats (pattern DB info)
        try:
            from ..daemon.pattern_scanner import PatternDatabase
            db = PatternDatabase()
            cats = set(p.category for p in db.patterns.values())
            result["memory_scanner"]["pattern_database"] = {
                "total_patterns": len(db.patterns),
                "categories": sorted(cats),
            }
        except Exception:
            result["memory_scanner"]["pattern_database"] = {"status": "unavailable"}

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
        return {
            "count": len(pending),
            "decisions": [
                {
                    "index": i,
                    "domain": d.domain,
                    "action": d.action,
                    "description": d.description,
                    "autonomy_level": d.autonomy_level,
                    "level_name": AutonomyLevel(d.autonomy_level).name,
                    "timestamp": d.timestamp,
                }
                for i, d in enumerate(pending)
            ],
        }

    # -- POST /decisions/{index}/approve --------------------------------------

    @app.post("/decisions/{index}/approve")
    async def approve_decision(index: int, body: DecisionActionRequest):
        """Approve a pending decision by index."""
        pending = autonomy.get_pending()
        if index < 0 or index >= len(pending):
            raise HTTPException(
                status_code=404,
                detail=f"No pending decision at index {index} (have {len(pending)})",
            )
        if autonomy.approve_pending(index):
            autonomy.record_correct()
            logger.info("Decision %d approved by human", index)
            return {"success": True, "message": f"Decision {index} approved"}
        raise HTTPException(status_code=404, detail=f"No pending decision at index {index}")

    # -- POST /decisions/{index}/deny -----------------------------------------

    @app.post("/decisions/{index}/deny")
    async def deny_decision(index: int, body: DecisionActionRequest):
        """Deny a pending decision by index. Records a false-positive score penalty."""
        pending = autonomy.get_pending()
        if index < 0 or index >= len(pending):
            raise HTTPException(
                status_code=404,
                detail=f"No pending decision at index {index} (have {len(pending)})",
            )
        if autonomy.deny_pending(index):
            logger.info("Decision %d denied by human", index)
            return {
                "success": True,
                "message": f"Decision {index} denied (score penalty applied)",
                "new_score": autonomy.score,
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
        try:
            from ..daemon.pattern_scanner import MemoryScanner, PatternDatabase
            db = PatternDatabase()
            scanner = MemoryScanner(db)
            scanner_stats = scanner.get_stats()
        except Exception:
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
        """
        try:
            from ..daemon.pattern_scanner import MemoryScanner, PatternDatabase
        except ImportError:
            raise HTTPException(
                status_code=503,
                detail="Pattern scanner module not available",
            )

        db = PatternDatabase()
        scanner = MemoryScanner(db)

        try:
            analysis = scanner.analyze_process(pid)
        except Exception as exc:
            raise HTTPException(
                status_code=500,
                detail=f"Scan failed for PID {pid}: {exc}",
            )

        return analysis

    return app
