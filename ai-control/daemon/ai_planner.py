"""
AI Planner — multi-step Contusion instruction decomposition.

Single-step LLM routing (Contusion._route_via_llm) handles atomic
instructions like "open firefox" or "increase volume". This module is
the COMPLEMENT: when the user issues a compound instruction such as

    "ai install claude and set up a proper default space to use claude"

the planner decomposes it into an ordered list of atomic Contusion
handler invocations (each itself dispatchable through the existing
typed-handler registry). The planner DOES NOT execute on its own — it
returns a plan with a stable plan_id that is then explicitly executed
via /ai/plan/execute. This two-step flow lets the operator skip risky
steps via `step_indices`, dry-run the whole plan, or refuse it outright.

Design contract:
  * The planner has no side effects beyond LLM inference and an in-
    memory plan cache. plan() never mutates system state.
  * execute() goes through Contusion handlers that ARE side-effecting
    and EACH one re-checks the cortex emergency latch via the daemon's
    /ai/plan/execute endpoint guard plus per-step contusion gating.
  * LLM unavailability (LLM_DISABLED env, no model loaded) returns a
    structured error rather than raising — callers degrade gracefully.
  * Plans expire after 15 min. The active-plan cache is bounded at 32
    entries with LRU eviction; an attacker cannot grow it unbounded.
  * Hard wall-clock cap on planner LLM call: 15s. Hard cap on per-step
    execution: 30s. A run-away step cannot pin the daemon.

Schemas (returned dicts):

  plan() →
    {
      "plan_id":           "<uuid4 hex>" | None (None ⇒ check "error"),
      "instruction":       "<original user text>",
      "summary":           "<one-sentence model summary>",
      "steps": [
        {
          "index":         <int>,
          "handler_type":  "<dotted handler name from HANDLERS>",
          "args":          {<dict of handler kwargs>},
          "rationale":     "<why this step>",
          "depends_on":    [<int>, ...]   # earlier step indices, may be []
        },
        ...
      ],
      "estimated_duration_s": <int>,
      "created_at":        "<ISO8601 UTC>",
      "expires_at":        "<ISO8601 UTC, +15 min>",
      "error":             "<diagnostic string>"   # only when plan_id is None
    }

  execute() →
    {
      "plan_id":   "<uuid4 hex>",
      "results": [
        {
          "index":        <int>,
          "handler_type": "...",
          "args":         {...},
          "status":       "ok" | "failed" | "skipped_dep_failed" | "dry_run",
          "result":       {<contusion handler envelope, or None for dry_run>},
          "duration_s":   <float>
        },
        ...
      ],
      "completed":  <int>,         # status == ok
      "failed":     <int>,         # status == failed
      "skipped":    <int>,         # status == skipped_dep_failed
      "duration_s": <float>        # total wall time
    }
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
import uuid
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

logger = logging.getLogger("ai-control.ai_planner")

# -- Tunables ---------------------------------------------------------------

# Wall clock for the LLM call inside plan(). The planner is called from a
# user-facing endpoint; sub-15s means the operator's "ai do X" command
# either lands or returns a clean error inside their attention span.
PLAN_LLM_TIMEOUT_S = 15.0

# Wall clock for ONE step inside execute(). Most contusion handlers
# (volume up, screenshot, brightness) finish in < 1s; pacman install
# can run for minutes — we want the planner to surface a per-step hang
# rather than block the orchestrator forever.
STEP_EXEC_TIMEOUT_S = 180.0

# Plan TTL. After this the plan is auto-pruned and its id no longer
# resolves; the operator must re-plan. 15 min leaves time to read the
# plan, ack any confirmations, and execute, but expires stale plans
# whose context (running processes, focused window) drifted away.
PLAN_TTL_S = 15 * 60

# Hard cap on simultaneously cached plans. LRU eviction keeps memory
# bounded even if a misbehaving caller hammers /ai/plan repeatedly.
ACTIVE_PLAN_CAP = 32

# Hard cap on steps per plan. Anything beyond this is almost certainly
# either model hallucination or a malicious "decompose into 10000 steps"
# attack. Mirrored client-side via the max_steps parameter.
HARD_MAX_STEPS = 16

# Per-step duration heuristic (seconds) used to estimate wall time.
# Very rough — apt installs dominate; everything else is < 1s.
_STEP_DURATION_HEURISTIC: dict[str, int] = {
    "app.install_steam":   90,
    "app.install_lutris":  60,
    "app.install_heroic":  60,
    "app.install_proton":  120,
    "app.launch":          3,
    "driver.load":         5,
    "driver.unload":       5,
    "driver.list":         1,
    "driver.info":         1,
    "service.start":       3,
    "service.stop":        3,
    "service.restart":     5,
    "service.enable":      2,
    "service.disable":     2,
    "service.status":      1,
    "service.is_active":   1,
    "service.list":        1,
    "service.reload":      2,
    "game.list":           1,
    "game.running":        1,
    "game.kill":           2,
    "perf.lowlatency_on":  3,
    "perf.lowlatency_off": 3,
    "perf.gamescope_on":   2,
    "perf.gamescope_off":  2,
    "perf.dxvk_clear":     2,
    "system.screenshot_full":   1,
    "system.screenshot_window": 1,
    "system.screenshot_region": 1,
    "system.notify":            1,
    "legacy.shell_exec":        10,
}

_DEFAULT_STEP_DURATION_S = 2


# -- Prompt template --------------------------------------------------------

# A deliberately tight prompt. The model is instructed to emit ONLY a
# JSON object — no commentary, no markdown fences (we still strip them
# tolerantly via _extract_json). The handler-family hints are short on
# purpose; verbose API docs would push real instructions out of context
# on a small model. Each registered handler_type still gets validated
# against HANDLERS at parse time, so a hallucinated name is rejected
# rather than executed.
_PROMPT = """You are a planner. Decompose this user instruction into atomic steps.
Each step is one Contusion handler invocation. Available handler families:
  - app.install_steam, app.install_lutris, app.install_heroic, app.install_proton, app.launch
  - driver.load, driver.unload, driver.list, driver.info
  - service.start, service.stop, service.restart, service.reload, service.enable, service.disable, service.status, service.is_active, service.list
  - game.list, game.running, game.kill
  - perf.lowlatency_on, perf.lowlatency_off, perf.gamescope_on, perf.gamescope_off, perf.dxvk_clear
  - system.screenshot_full, system.screenshot_window, system.screenshot_region, system.notify
  - legacy.shell_exec   (fallback; args = {{"cmd": "<command>", "timeout": 60}})

Return STRICT JSON only. No commentary, no markdown fences. Schema:
{{
  "summary": "<one short sentence summarising the plan>",
  "steps": [
    {{
      "handler_type": "<one of the families above>",
      "args": {{<keyword args for the handler>}},
      "depends_on": [<earlier step index, or empty list>],
      "rationale": "<one short sentence>"
    }}
  ]
}}

Rules:
- Maximum {max_steps} steps.
- Each step independently confirmable.
- "depends_on" entries MUST be smaller than the step's own index.
- Prefer the most specific handler. Use legacy.shell_exec only when no typed handler fits.

Instruction: "{instruction}"
"""


# -- JSON tolerance (mirrors cortex/decision_engine.DecisionEngine) ---------

def _extract_json(text: str) -> Optional[dict]:
    """Return the first parseable {...} object in `text`, or None.

    Accepts (a) bare JSON, (b) JSON wrapped in a ```json ... ``` fence,
    (c) JSON embedded in chatty model output. Same tolerance level as the
    decision engine so a single model can serve both planner and gate.
    """
    if not text:
        return None
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```[a-zA-Z]*\n?", "", stripped)
        if stripped.endswith("```"):
            stripped = stripped[:-3]
        stripped = stripped.strip()
    # Fast path: whole string is JSON.
    try:
        obj = json.loads(stripped)
        if isinstance(obj, dict):
            return obj
    except (json.JSONDecodeError, ValueError):
        pass
    # Fallback: scan for the first balanced {...} run.
    start = stripped.find("{")
    while start != -1:
        depth = 0
        for i in range(start, len(stripped)):
            ch = stripped[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    chunk = stripped[start:i + 1]
                    try:
                        obj = json.loads(chunk)
                        if isinstance(obj, dict):
                            return obj
                    except (json.JSONDecodeError, ValueError):
                        break
                    break
        start = stripped.find("{", start + 1)
    return None


def _llm_disabled() -> bool:
    val = os.environ.get("LLM_DISABLED", "").strip().lower()
    return val in ("1", "true", "yes", "on")


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _expires_iso(ttl_s: int = PLAN_TTL_S) -> str:
    return (datetime.now(timezone.utc).replace(microsecond=0)
            + timedelta(seconds=ttl_s)).isoformat()


# -- AIPlanner --------------------------------------------------------------

class AIPlanner:
    """Multi-step instruction decomposer + executor.

    The constructor takes a reference to the LLM module (typically
    `ai-control/daemon/llm.py` — anything that exposes
    `async generate(prompt, max_tokens, temperature, timeout, stop)`)
    and a Contusion engine instance. Both are kept as references so a
    later module reload (test harness) can swap them out.
    """

    def __init__(self, llm_module: Any, contusion_module: Any):
        self._llm = llm_module
        self._contusion = contusion_module
        # OrderedDict gives O(1) LRU semantics via move_to_end / popitem.
        self._active_plans: "OrderedDict[str, dict]" = OrderedDict()
        # Single lock guards the active-plan cache. plan() and execute()
        # both need to mutate it (insert vs prune+lookup); a single lock
        # is fine because both paths are O(plan-count) under the cap.
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------ #
    # Internal helpers                                                   #
    # ------------------------------------------------------------------ #

    def _known_handlers(self) -> set[str]:
        """Return the set of handler_type strings the planner may emit.

        Pulled fresh from `contusion_handlers.HANDLERS` each call so a
        runtime extension to the registry (Session-N+1 handlers) is
        immediately plannable without restarting the daemon.
        """
        try:
            from contusion_handlers import HANDLERS  # noqa: WPS433
            return set(HANDLERS.keys())
        except Exception as exc:
            logger.warning("could not import HANDLERS, returning empty set: %s",
                           exc)
            return set()

    def _estimate_duration(self, steps: list[dict]) -> int:
        total = 0
        for s in steps:
            ht = s.get("handler_type", "")
            total += _STEP_DURATION_HEURISTIC.get(ht, _DEFAULT_STEP_DURATION_S)
        return int(total)

    async def _prune_expired(self) -> None:
        """Drop any plans whose expires_at has passed.

        Caller must hold self._lock. We compute "now" once and walk the
        ordered dict from the front; OrderedDict iteration is FIFO by
        insertion order (LRU after move_to_end), but since we don't
        bump on plan() insertions only on execute() lookups, oldest by
        creation tend to live at the front. We still do a full scan to
        catch out-of-order TTLs (unusual, but possible if execute()
        bumped a younger plan).
        """
        now = datetime.now(timezone.utc)
        expired: list[str] = []
        for plan_id, plan in self._active_plans.items():
            try:
                exp = datetime.fromisoformat(plan["expires_at"])
            except (KeyError, ValueError, TypeError):
                expired.append(plan_id)
                continue
            if exp <= now:
                expired.append(plan_id)
        for pid in expired:
            self._active_plans.pop(pid, None)
        if expired:
            logger.info("ai_planner: pruned %d expired plan(s)", len(expired))

    async def _evict_lru_if_needed(self) -> None:
        """Hold cache to ACTIVE_PLAN_CAP via popitem(last=False) (LRU).

        Caller must hold self._lock.
        """
        while len(self._active_plans) > ACTIVE_PLAN_CAP:
            evicted_id, _ = self._active_plans.popitem(last=False)
            logger.info("ai_planner: LRU-evicted plan %s (cap=%d)",
                        evicted_id, ACTIVE_PLAN_CAP)

    def _validate_steps(self, raw_steps: Any, max_steps: int,
                        known_handlers: set[str]) -> tuple[list[dict], Optional[str]]:
        """Return (validated_steps, error_or_None).

        Each returned step is shape-normalised: index, handler_type, args,
        rationale, depends_on (list of ints, all < own index, all in
        range). Anything malformed returns ([], "<diagnostic>").
        """
        if not isinstance(raw_steps, list):
            return [], "steps field is not a list"
        if len(raw_steps) == 0:
            return [], "model returned 0 steps"
        if len(raw_steps) > max_steps:
            return [], (f"model returned {len(raw_steps)} steps, exceeds "
                        f"max_steps={max_steps}")
        out: list[dict] = []
        for idx, raw in enumerate(raw_steps):
            if not isinstance(raw, dict):
                return [], f"step[{idx}] is not an object"
            handler_type = raw.get("handler_type")
            if not isinstance(handler_type, str) or not handler_type:
                return [], f"step[{idx}] missing handler_type"
            if handler_type not in known_handlers:
                return [], (f"step[{idx}] handler_type {handler_type!r} not in "
                            f"registry ({len(known_handlers)} known handlers)")
            args = raw.get("args", {})
            if args is None:
                args = {}
            if not isinstance(args, dict):
                return [], f"step[{idx}] args is not a dict"
            # Force-coerce to a plain dict of str→primitive so a model
            # can't sneak a list of args that crashes the handler.
            safe_args: dict[str, Any] = {}
            for k, v in args.items():
                if not isinstance(k, str):
                    return [], f"step[{idx}] args has non-string key {k!r}"
                # Allow primitives + nested lists/dicts of primitives.
                if isinstance(v, (str, int, float, bool, list, dict)) or v is None:
                    safe_args[k] = v
                else:
                    return [], (f"step[{idx}] args[{k!r}] has unsupported "
                                f"type {type(v).__name__}")
            depends_on_raw = raw.get("depends_on", [])
            # Tolerate a single int instead of a list.
            if isinstance(depends_on_raw, int):
                depends_on_raw = [depends_on_raw]
            if depends_on_raw is None:
                depends_on_raw = []
            if not isinstance(depends_on_raw, list):
                return [], f"step[{idx}] depends_on is not a list"
            depends_on: list[int] = []
            for d in depends_on_raw:
                if not isinstance(d, int):
                    return [], (f"step[{idx}] depends_on entry {d!r} is not "
                                f"an int")
                if d < 0 or d >= idx:
                    return [], (f"step[{idx}] depends_on={d} must be a "
                                f"prior step index in [0, {idx})")
                depends_on.append(d)
            rationale = raw.get("rationale", "")
            if not isinstance(rationale, str):
                rationale = str(rationale)
            # Keep rationale bounded — a verbose model could otherwise
            # blow up the plan envelope.
            if len(rationale) > 256:
                rationale = rationale[:256]
            out.append({
                "index": idx,
                "handler_type": handler_type,
                "args": safe_args,
                "rationale": rationale,
                "depends_on": depends_on,
            })
        return out, None

    # ------------------------------------------------------------------ #
    # Public API                                                         #
    # ------------------------------------------------------------------ #

    async def plan(self, instruction: str, max_steps: int = 8) -> dict:
        """Decompose `instruction` into an ordered plan of atomic steps.

        Returns a plan dict (see module docstring for full schema). On
        any failure the returned dict has plan_id=None and an "error"
        diagnostic; the caller should NOT pass it to execute().
        """
        # Input sanity. The auth layer already gates trust band; this
        # layer guards against malformed payloads slipping through.
        if not isinstance(instruction, str) or not instruction.strip():
            return {"plan_id": None,
                    "error": "instruction must be a non-empty string"}
        if not isinstance(max_steps, int):
            return {"plan_id": None,
                    "error": "max_steps must be an int"}
        max_steps = max(1, min(max_steps, HARD_MAX_STEPS))
        if len(instruction) > 4096:
            return {"plan_id": None,
                    "error": "instruction too long (>4096 chars)"}

        # LLM gating. Mirror llm.generate's behaviour so the operator
        # gets a clear "no model" error rather than a 15s timeout.
        if _llm_disabled():
            return {"plan_id": None,
                    "error": "LLM_DISABLED env set; planner unavailable"}
        if self._llm is None:
            return {"plan_id": None,
                    "error": "LLM module not available"}
        if not hasattr(self._llm, "generate"):
            return {"plan_id": None,
                    "error": ("LLM module missing generate(); cannot plan "
                              "(loaded module: %r)" % type(self._llm))}

        prompt = _PROMPT.format(max_steps=max_steps,
                                instruction=instruction.replace('"', "'"))

        try:
            text = await asyncio.wait_for(
                self._llm.generate(
                    prompt,
                    max_tokens=800,
                    temperature=0.2,
                    timeout=PLAN_LLM_TIMEOUT_S,
                    stop=["\n\nInstruction:", "```\n\n"],
                ),
                timeout=PLAN_LLM_TIMEOUT_S,
            )
        except asyncio.TimeoutError:
            return {"plan_id": None,
                    "error": f"LLM did not respond within "
                             f"{PLAN_LLM_TIMEOUT_S:.0f}s"}
        except Exception as exc:  # noqa: BLE001
            logger.exception("planner LLM call failed: %s", exc)
            return {"plan_id": None,
                    "error": f"LLM call raised {type(exc).__name__}: {exc}"}

        if not text:
            return {"plan_id": None,
                    "error": "LLM returned empty/None response"}

        obj = _extract_json(text)
        if obj is None:
            # Truncate the offending text to a debuggable snippet.
            preview = text[:200].replace("\n", " ")
            return {"plan_id": None,
                    "error": f"LLM response was not valid JSON; got: {preview!r}"}

        summary = obj.get("summary", "")
        if not isinstance(summary, str):
            summary = str(summary)
        if len(summary) > 512:
            summary = summary[:512]

        known = self._known_handlers()
        if not known:
            return {"plan_id": None,
                    "error": "no contusion handlers registered; planner cannot validate"}

        steps, err = self._validate_steps(obj.get("steps"), max_steps, known)
        if err:
            return {"plan_id": None,
                    "error": err,
                    "raw_summary": summary}

        plan_id = uuid.uuid4().hex
        plan = {
            "plan_id": plan_id,
            "instruction": instruction,
            "summary": summary,
            "steps": steps,
            "estimated_duration_s": self._estimate_duration(steps),
            "created_at": _now_iso(),
            "expires_at": _expires_iso(),
        }

        async with self._lock:
            await self._prune_expired()
            self._active_plans[plan_id] = plan
            await self._evict_lru_if_needed()

        return plan

    async def execute(self, plan_id: str, *,
                      step_indices: Optional[list[int]] = None,
                      dry_run: bool = False) -> dict:
        """Execute a previously-planned multi-step pipeline.

        - `step_indices`: if provided, only these steps are run (still in
          ascending order). Useful when the operator wants to skip a
          risky step (e.g. omit an `app.install_*` they already have).
          Indices not in the plan are silently dropped (with a log
          line).
        - `dry_run`: do not actually invoke handlers; just return what
          WOULD be called. Result envelopes are None for dry-run steps.

        Dependency handling: a step whose `depends_on` includes any
        previously-FAILED step is marked `skipped_dep_failed` and not
        executed. (A skipped step also propagates this state — its
        dependents will skip too.)

        Per-step execution timeout: STEP_EXEC_TIMEOUT_S. Beyond that
        the step is reported as failed("timeout").
        """
        if not isinstance(plan_id, str) or not plan_id:
            return {"plan_id": "", "error": "plan_id required",
                    "results": [], "completed": 0, "failed": 0,
                    "skipped": 0, "duration_s": 0.0}

        async with self._lock:
            await self._prune_expired()
            plan = self._active_plans.get(plan_id)
            if plan is None:
                return {"plan_id": plan_id,
                        "error": "plan_id not found or expired",
                        "results": [], "completed": 0, "failed": 0,
                        "skipped": 0, "duration_s": 0.0}
            # Bump LRU position so an in-progress plan isn't evicted
            # by a flood of new plan() calls mid-execute.
            self._active_plans.move_to_end(plan_id)

        # `plan` is now a stable reference; we don't need the lock for
        # execution since plan dicts are immutable after creation and
        # we don't share the `results` list with anyone.
        all_steps = plan["steps"]

        # Resolve step subset.
        selected: list[dict]
        if step_indices is not None:
            if not isinstance(step_indices, list):
                return {"plan_id": plan_id,
                        "error": "step_indices must be a list of ints",
                        "results": [], "completed": 0, "failed": 0,
                        "skipped": 0, "duration_s": 0.0}
            wanted = set()
            for s in step_indices:
                if isinstance(s, int) and 0 <= s < len(all_steps):
                    wanted.add(s)
                else:
                    logger.info("ai_planner: dropping invalid step_index %r", s)
            selected = [s for s in all_steps if s["index"] in wanted]
        else:
            selected = list(all_steps)

        if not selected:
            return {"plan_id": plan_id,
                    "error": "no executable steps after filtering",
                    "results": [], "completed": 0, "failed": 0,
                    "skipped": 0, "duration_s": 0.0}

        # Build the contusion handler registry once for fast dispatch.
        try:
            from contusion_handlers import HANDLERS  # noqa: WPS433
        except Exception as exc:
            return {"plan_id": plan_id,
                    "error": f"contusion_handlers import failed: {exc}",
                    "results": [], "completed": 0, "failed": 0,
                    "skipped": 0, "duration_s": 0.0}

        results: list[dict] = []
        # failed_or_skipped indices, used for dep-failure propagation.
        bad: set[int] = set()

        wall_start = time.monotonic()
        for step in selected:
            idx = step["index"]
            handler_type = step["handler_type"]
            args = dict(step["args"])  # defensive copy
            depends_on = step.get("depends_on", [])

            # Dependency check FIRST — a step that depends on a
            # not-yet-run-because-skipped step doesn't run either.
            dep_failed = any(d in bad for d in depends_on)
            if dep_failed:
                results.append({
                    "index": idx,
                    "handler_type": handler_type,
                    "args": args,
                    "status": "skipped_dep_failed",
                    "result": None,
                    "duration_s": 0.0,
                })
                bad.add(idx)
                continue

            if dry_run:
                results.append({
                    "index": idx,
                    "handler_type": handler_type,
                    "args": args,
                    "status": "dry_run",
                    "result": None,
                    "duration_s": 0.0,
                })
                continue

            handler = HANDLERS.get(handler_type)
            if handler is None:
                # Should be unreachable — _validate_steps already
                # checked. Belt-and-braces in case of registry hot-reload.
                results.append({
                    "index": idx,
                    "handler_type": handler_type,
                    "args": args,
                    "status": "failed",
                    "result": {"success": False,
                               "error": f"handler {handler_type!r} no longer registered"},
                    "duration_s": 0.0,
                })
                bad.add(idx)
                continue

            t0 = time.monotonic()
            try:
                step_result = await asyncio.wait_for(
                    handler(args),
                    timeout=STEP_EXEC_TIMEOUT_S,
                )
            except asyncio.TimeoutError:
                step_result = {"success": False,
                               "error": f"step timed out after "
                                        f"{STEP_EXEC_TIMEOUT_S:.0f}s",
                               "handler": handler_type}
                bad.add(idx)
            except Exception as exc:  # noqa: BLE001
                logger.exception("planner step %d (%s) crashed: %s",
                                 idx, handler_type, exc)
                step_result = {"success": False,
                               "error": f"{type(exc).__name__}: {exc}",
                               "handler": handler_type}
                bad.add(idx)
            duration = round(time.monotonic() - t0, 3)

            ok = isinstance(step_result, dict) and step_result.get("success", False)
            if not ok:
                bad.add(idx)
            results.append({
                "index": idx,
                "handler_type": handler_type,
                "args": args,
                "status": "ok" if ok else "failed",
                "result": step_result,
                "duration_s": duration,
            })

        wall = round(time.monotonic() - wall_start, 3)
        completed = sum(1 for r in results if r["status"] == "ok")
        failed = sum(1 for r in results if r["status"] == "failed")
        skipped = sum(1 for r in results if r["status"] == "skipped_dep_failed")
        return {
            "plan_id": plan_id,
            "results": results,
            "completed": completed,
            "failed": failed,
            "skipped": skipped,
            "duration_s": wall,
            "dry_run": dry_run,
        }
