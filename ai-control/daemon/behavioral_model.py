"""
AI Behavioral Model -- Analyzes PE process behavior and predicts failures.

Combines data from:
- Pattern scanner (signatures found in memory)
- Memory observer (loaded DLLs, anomalies)
- Stub discovery (unimplemented APIs called)
- Syscall monitor (actual system calls made)
- Binary signatures (known exe identification)

Produces:
- Process classification (game, installer, tool, service)
- Behavioral fingerprint
- Compatibility prediction
- Failure prediction with specific API recommendations
- Natural language analysis report
"""

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("ai-control.behavioral_model")


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class BehavioralFingerprint:
    """Unique behavioral signature of a PE process."""
    pid: int
    exe_name: str
    timestamp: float

    # Classification
    category: str           # "game", "installer", "tool", "service", "runtime"
    engine: str             # "unreal", "unity", "electron", "custom", etc.
    graphics_api: str       # "d3d12", "d3d11", "d3d9", "vulkan", "opengl", "gdi", "none"

    # Behavioral metrics
    dll_count: int
    import_count: int
    stub_hit_count: int
    unique_syscalls: int
    file_access_count: int
    network_connections: int
    thread_count: int
    memory_allocated_mb: float

    # Compatibility assessment
    compatibility_score: float      # 0.0 - 1.0
    blocking_issues: list           # Must-fix issues
    warnings: list                  # Nice-to-fix issues
    working_features: list          # What already works

    # Predictions
    predicted_failures: list        # What will break and why
    recommended_actions: list       # What to implement/fix

    # Report
    summary: str                    # One-paragraph human-readable summary
    detailed_report: str            # Full analysis

    def to_dict(self) -> dict:
        """Serializable summary for API responses."""
        return {
            "pid": self.pid,
            "exe_name": self.exe_name,
            "timestamp": self.timestamp,
            "category": self.category,
            "engine": self.engine,
            "graphics_api": self.graphics_api,
            "dll_count": self.dll_count,
            "import_count": self.import_count,
            "stub_hit_count": self.stub_hit_count,
            "unique_syscalls": self.unique_syscalls,
            "file_access_count": self.file_access_count,
            "network_connections": self.network_connections,
            "thread_count": self.thread_count,
            "memory_allocated_mb": round(self.memory_allocated_mb, 2),
            "compatibility_score": round(self.compatibility_score, 3),
            "blocking_issues": self.blocking_issues,
            "warnings": self.warnings,
            "working_features": self.working_features,
            "predicted_failures": self.predicted_failures,
            "recommended_actions": self.recommended_actions,
            "summary": self.summary,
        }

    def to_full_dict(self) -> dict:
        """Full serializable output including detailed report."""
        d = self.to_dict()
        d["detailed_report"] = self.detailed_report
        return d


# ---------------------------------------------------------------------------
# Known engine signatures (used to classify by loaded DLLs / patterns)
# ---------------------------------------------------------------------------

_ENGINE_DLL_HINTS: dict[str, list[str]] = {
    "unreal": [
        "ue4-", "ue5-", "unrealengine", "xaudio2_9.dll", "bink2w64.dll",
    ],
    "unity": [
        "unityplayer.dll", "mono-2.0-bdwgc.dll", "il2cpp.dll",
        "unityclasslibrary", "gameassembly.dll",
    ],
    "electron": [
        "electron.exe", "libcef.dll", "chrome_elf.dll",
    ],
    "cryengine": [
        "cryengine", "crysystem.dll", "cryrender",
    ],
    "godot": [
        "godot", "libgodot",
    ],
    "gamemaker": [
        "gamemaker", "data.win",
    ],
    "source": [
        "engine.dll", "vphysics.dll", "materialsystem.dll",
        "shaderapidx9.dll", "tier0.dll",
    ],
    "idtech": [
        "idtech", "doomx64vk.exe", "doomx64.exe",
    ],
    "rpgmaker": [
        "rpgmaker", "rgss", "system/rgss",
    ],
}

_ENGINE_PATTERN_KEYWORDS: dict[str, list[str]] = {
    "unreal": ["Unreal", "UE4", "UE5", "UnrealEngine"],
    "unity": ["Unity", "UnityEngine", "MonoAssembly"],
    "cryengine": ["CryEngine", "CrySystem"],
    "godot": ["Godot"],
    "source": ["Source Engine", "Valve"],
}

# Category DLL heuristics: if these DLLs are loaded, this is likely a game
_GAME_DLL_INDICATORS = {
    "d3d9.dll", "d3d11.dll", "d3d12.dll", "dxgi.dll", "ddraw.dll",
    "xinput1_3.dll", "xinput1_4.dll", "xinput9_1_0.dll",
    "dsound.dll", "dinput8.dll", "xaudio2_9.dll",
    "vulkan-1.dll", "opengl32.dll",
    "steam_api64.dll", "steam_api.dll",
}

_INSTALLER_DLL_INDICATORS = {
    "msi.dll", "cabinet.dll", "setupapi.dll", "wintrust.dll",
    "advpack.dll", "sfc.dll", "sfc_os.dll",
}

_SERVICE_DLL_INDICATORS = {
    "sechost.dll", "wtsapi32.dll", "shlwapi.dll",
}

_RUNTIME_DLL_INDICATORS = {
    "mscoree.dll", "clrjit.dll", "clr.dll",
    "mono-2.0-bdwgc.dll", "il2cpp.dll",
}


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class BehavioralModelEngine:
    """Analyzes PE processes and produces behavioral models."""

    # Maximum cached fingerprints to prevent unbounded memory growth
    # when many PE processes are analyzed over the daemon's lifetime.
    MAX_CACHED_FINGERPRINTS = 512

    def __init__(self):
        self._fingerprints: dict[int, BehavioralFingerprint] = {}
        self._analysis_count: int = 0

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def analyze(
        self,
        pid: int,
        memory_observer=None,
        pattern_scanner=None,
        stub_discovery=None,
        binary_db=None,
    ) -> BehavioralFingerprint:
        """Full behavioral analysis of a PE process.

        Gathers data from all available sub-systems and synthesizes
        a fingerprint with compatibility score, failure predictions,
        and a human-readable report.
        """
        t0 = time.monotonic()
        exe_name = self._get_exe_name(pid)
        logger.info("Starting behavioral analysis for PID %d (%s)", pid, exe_name)

        # Gather all available data (each returns a dict, never None)
        memory_data = await self._gather_memory_data(pid, memory_observer)
        pattern_data = self._gather_pattern_data(pid, pattern_scanner)
        stub_data = await self._gather_stub_data(pid, stub_discovery)
        sig_data = self._gather_signature_data(exe_name, binary_db)

        # Classify the process
        category = self._classify(memory_data, pattern_data, stub_data, sig_data)
        engine = self._detect_engine(pattern_data, memory_data)
        graphics = self._detect_graphics_api(pattern_data, memory_data)

        # Compute compatibility score
        score, blocking, warnings, working = self._assess_compatibility(
            memory_data, stub_data, pattern_data
        )

        # Predict failures
        predictions = self._predict_failures(stub_data, pattern_data, memory_data)
        recommendations = self._generate_recommendations(predictions, stub_data)

        # Generate reports
        summary = self._generate_summary(
            exe_name, category, engine, graphics, score, blocking, predictions
        )
        detailed = self._generate_detailed_report(
            exe_name, category, engine, graphics, score,
            blocking, warnings, working, predictions, recommendations,
            memory_data, pattern_data, stub_data
        )

        elapsed = time.monotonic() - t0

        fp = BehavioralFingerprint(
            pid=pid,
            exe_name=exe_name,
            timestamp=time.time(),
            category=category,
            engine=engine,
            graphics_api=graphics,
            dll_count=len(memory_data.get("dlls", [])),
            import_count=stub_data.get("total_imports", 0),
            stub_hit_count=stub_data.get("stub_count", 0),
            unique_syscalls=0,  # From syscall monitor when available
            file_access_count=0,
            network_connections=self._count_network_hints(pattern_data),
            thread_count=self._count_threads(pid),
            memory_allocated_mb=memory_data.get("total_mapped", 0) / (1024 * 1024),
            compatibility_score=score,
            blocking_issues=blocking,
            warnings=warnings,
            working_features=working,
            predicted_failures=predictions,
            recommended_actions=recommendations,
            summary=summary,
            detailed_report=detailed,
        )

        self._fingerprints[pid] = fp
        self._analysis_count += 1

        # Evict stale fingerprints to prevent unbounded memory growth
        self._evict_stale_fingerprints()

        logger.info(
            "Behavioral analysis complete for PID %d (%s): "
            "score=%.1f%% category=%s engine=%s gfx=%s elapsed=%.3fs",
            pid, exe_name, score * 100, category, engine, graphics, elapsed,
        )
        return fp

    # ------------------------------------------------------------------
    # Eviction
    # ------------------------------------------------------------------

    def _evict_stale_fingerprints(self) -> None:
        """Remove fingerprints for dead processes; evict oldest if over cap."""
        # Remove entries for PIDs that no longer exist
        dead_pids = [
            pid for pid in self._fingerprints
            if not os.path.exists(f"/proc/{pid}")
        ]
        for pid in dead_pids:
            del self._fingerprints[pid]

        # If still over cap, evict oldest by timestamp
        if len(self._fingerprints) > self.MAX_CACHED_FINGERPRINTS:
            by_age = sorted(
                self._fingerprints.items(),
                key=lambda kv: kv[1].timestamp,
            )
            to_remove = len(self._fingerprints) - self.MAX_CACHED_FINGERPRINTS
            for pid, _ in by_age[:to_remove]:
                del self._fingerprints[pid]

    # ------------------------------------------------------------------
    # Data gathering (one method per sub-system)
    # ------------------------------------------------------------------

    async def _gather_memory_data(self, pid: int, memory_observer) -> dict:
        """Collect data from the memory observer."""
        result = {
            "dlls": [],
            "dll_names": [],
            "total_mapped": 0,
            "region_count": 0,
            "anomalies": [],
            "iat_entries": {},
        }
        if memory_observer is None:
            return result

        try:
            process_map = await memory_observer.get_process_map(pid)
            if process_map:
                result["region_count"] = len(process_map.get("regions", []))
                result["total_mapped"] = sum(
                    r.get("size", 0) for r in process_map.get("regions", [])
                )
        except Exception as e:
            logger.debug("Memory observer process_map failed for %d: %s", pid, e)

        try:
            dlls = await memory_observer.get_loaded_dlls(pid)
            if dlls:
                result["dlls"] = dlls
                result["dll_names"] = [
                    d.get("name", d.get("dll_name", "")).lower()
                    for d in dlls
                ]
        except Exception as e:
            logger.debug("Memory observer get_loaded_dlls failed for %d: %s", pid, e)

        try:
            anomalies = await memory_observer.get_memory_anomalies(pid)
            if anomalies:
                result["anomalies"] = anomalies
        except Exception as e:
            logger.debug("Memory observer anomalies failed for %d: %s", pid, e)

        try:
            iat = await memory_observer.get_iat_status(pid)
            if iat:
                result["iat_entries"] = iat
        except Exception as e:
            logger.debug("Memory observer IAT failed for %d: %s", pid, e)

        return result

    def _gather_pattern_data(self, pid: int, pattern_scanner) -> dict:
        """Collect data from the pattern scanner."""
        result = {
            "matches": [],
            "analysis": {},
        }
        if pattern_scanner is None:
            return result

        try:
            analysis = pattern_scanner.analyze_process(pid)
            result["analysis"] = analysis

            # Convert analysis into match-like records for classification
            matches = []
            for desc in analysis.get("anti_cheat_detected", []):
                matches.append({
                    "category": "anti_cheat",
                    "description": desc,
                    "metadata": {},
                })
            for desc in analysis.get("anti_debug_detected", []):
                matches.append({
                    "category": "anti_debug",
                    "description": desc,
                    "metadata": {},
                })
            for desc in analysis.get("drm_detected", []):
                matches.append({
                    "category": "drm",
                    "description": desc,
                    "metadata": {},
                })
            for req in analysis.get("dx_requirements", []):
                matches.append({
                    "category": "dx_init",
                    "description": f"DirectX requirement: {req}",
                    "metadata": {"requires": req},
                })
            result["matches"] = matches

        except Exception as e:
            logger.debug("Pattern scanner failed for %d: %s", pid, e)

        return result

    async def _gather_stub_data(self, pid: int, stub_discovery) -> dict:
        """Collect data from the stub discovery engine."""
        result = {
            "total_imports": 0,
            "resolved_imports": 0,
            "stub_count": 0,
            "missing_count": 0,
            "recommendations": [],
            "dll_coverage": [],
            "categories": {},
        }
        if stub_discovery is None:
            return result

        try:
            # Check if already analyzed; if not, run analysis
            profile_dict = stub_discovery.get_profile(pid)
            if profile_dict is None:
                profile = await stub_discovery.analyze_process(pid)
                profile_dict = profile.to_full_dict()

            result["total_imports"] = profile_dict.get("total_imports", 0)
            result["resolved_imports"] = profile_dict.get("resolved_imports", 0)
            result["stub_count"] = profile_dict.get("stubbed_imports", 0)
            result["missing_count"] = profile_dict.get("missing_imports", 0)
            result["recommendations"] = profile_dict.get("recommendations", [])

        except Exception as e:
            logger.debug("Stub discovery failed for %d: %s", pid, e)

        return result

    def _gather_signature_data(self, exe_name: str, binary_db) -> dict:
        """Look up the executable in the binary signature database."""
        # binary_db is a placeholder for a future known-exe database
        # (e.g., mapping Steam AppIDs, known engines, etc.)
        if binary_db is None:
            return {}
        try:
            sig = binary_db.lookup(exe_name)
            if sig:
                return sig
        except Exception as e:
            logger.debug("Binary DB lookup failed for %s: %s", exe_name, e)
        return {}

    # ------------------------------------------------------------------
    # Classification
    # ------------------------------------------------------------------

    def _classify(self, memory: dict, patterns: dict, stubs: dict, sigs: dict) -> str:
        """Classify the process type based on all gathered data."""
        # Signature database overrides everything if present
        if sigs and sigs.get("category"):
            return sigs["category"]

        dll_names = set(memory.get("dll_names", []))

        # .NET/Mono runtime
        if dll_names & _RUNTIME_DLL_INDICATORS:
            # Could be a game running on .NET/Mono -- check further
            if dll_names & _GAME_DLL_INDICATORS:
                return "game"
            return "runtime"

        # Game detection: DirectX, audio, input, or Steam DLLs
        if dll_names & _GAME_DLL_INDICATORS:
            return "game"

        # Installer detection
        if dll_names & _INSTALLER_DLL_INDICATORS:
            # Only classify as installer if it does NOT also have game DLLs
            return "installer"

        # Pattern-based: anti-cheat or DRM strongly suggests game
        analysis = patterns.get("analysis", {})
        if analysis.get("anti_cheat_detected") or analysis.get("drm_detected"):
            return "game"

        # DirectX requirements in pattern scanner
        if analysis.get("dx_requirements"):
            return "game"

        # Service detection: imports RegisterServiceCtrlHandler
        for rec in stubs.get("recommendations", []):
            func = rec.get("function", "")
            if "RegisterServiceCtrlHandler" in func or "StartServiceCtrlDispatcher" in func:
                return "service"

        # Service DLL indicators
        if dll_names & _SERVICE_DLL_INDICATORS and not (dll_names & _GAME_DLL_INDICATORS):
            return "service"

        return "tool"

    def _detect_engine(self, patterns: dict, memory: dict) -> str:
        """Detect the game/application engine from patterns and loaded DLLs."""
        dll_names = memory.get("dll_names", [])

        # Check loaded DLLs against known engine hints
        for engine_name, hints in _ENGINE_DLL_HINTS.items():
            for hint in hints:
                hint_lower = hint.lower()
                for dll in dll_names:
                    if hint_lower in dll:
                        return engine_name

        # Check pattern scanner matches for engine strings
        for match in patterns.get("matches", []):
            desc = match.get("description", "")
            for engine_name, keywords in _ENGINE_PATTERN_KEYWORDS.items():
                for kw in keywords:
                    if kw in desc:
                        return engine_name

        # Check the analysis data for engine-related DLLs
        analysis = patterns.get("analysis", {})
        for dll in analysis.get("required_dlls", []):
            dll_lower = dll.lower()
            for engine_name, hints in _ENGINE_DLL_HINTS.items():
                for hint in hints:
                    if hint.lower() in dll_lower:
                        return engine_name

        return "custom"

    def _detect_graphics_api(self, patterns: dict, memory: dict) -> str:
        """Detect which graphics API is being used."""
        dll_names = set(memory.get("dll_names", []))

        # Check pattern scanner analysis first (most reliable)
        analysis = patterns.get("analysis", {})
        dx_reqs = analysis.get("dx_requirements", [])
        if dx_reqs:
            # Prefer the newest detected API
            for api in ("d3d12", "vulkan", "d3d11", "d3d9"):
                if api in dx_reqs:
                    return api

        # Check pattern matches metadata
        for match in patterns.get("matches", []):
            meta = match.get("metadata", {})
            req = meta.get("requires", "")
            if req in ("d3d12", "d3d11", "d3d9", "vulkan", "dxgi"):
                if req == "dxgi":
                    # DXGI implies D3D11 or D3D12 -- check further
                    if "d3d12.dll" in dll_names:
                        return "d3d12"
                    return "d3d11"
                return req

        # Fallback: check loaded DLLs
        if "vulkan-1.dll" in dll_names:
            return "vulkan"
        if "dxgi.dll" in dll_names:
            if "d3d12.dll" in dll_names:
                return "d3d12"
            if "d3d11.dll" in dll_names:
                return "d3d11"
        if "d3d9.dll" in dll_names:
            return "d3d9"
        if "ddraw.dll" in dll_names:
            return "d3d9"  # DirectDraw era, closest match
        if "opengl32.dll" in dll_names:
            return "opengl"

        # Check for GDI usage (simple 2D apps)
        if "gdi32.dll" in dll_names:
            return "gdi"

        return "none"

    # ------------------------------------------------------------------
    # Compatibility assessment
    # ------------------------------------------------------------------

    def _assess_compatibility(
        self, memory: dict, stubs: dict, patterns: dict
    ) -> tuple[float, list, list, list]:
        """Score compatibility and identify blocking issues.

        Returns (score, blocking_issues, warnings, working_features).
        Score ranges from 0.0 (completely broken) to 1.0 (fully compatible).
        """
        score = 1.0
        blocking = []
        warnings = []
        working = []

        # --- Stub coverage ---
        total = stubs.get("total_imports", 0)
        resolved = stubs.get("resolved_imports", 0)
        stub_count = stubs.get("stub_count", 0)
        missing_count = stubs.get("missing_count", 0)

        if total > 0:
            coverage = resolved / total
            # Coverage below 80% is a significant risk
            if coverage < 0.5:
                score *= 0.3
            elif coverage < 0.8:
                score *= coverage
            else:
                score *= min(1.0, coverage * 1.05)  # small bonus for high coverage

            if missing_count > 0:
                blocking.append({
                    "type": "missing_dll",
                    "detail": f"{missing_count} imports could not be resolved at all",
                    "impact": "Process will crash when calling these functions",
                    "count": missing_count,
                })
                score -= min(0.3, missing_count * 0.02)

            # Check critical stub hits from recommendations
            for rec in stubs.get("recommendations", [])[:15]:
                priority = rec.get("priority", "low")
                func = rec.get("function", "unknown")
                dll = rec.get("dll", "unknown")
                call_count = rec.get("call_count", 0)

                if priority == "critical" or call_count > 50:
                    blocking.append({
                        "type": "missing_api",
                        "detail": f"{dll}!{func}",
                        "impact": f"Called {call_count}x, returns dummy value",
                        "call_count": call_count,
                    })
                    score -= min(0.15, 0.01 * call_count)
                elif priority == "high" or call_count > 10:
                    warnings.append({
                        "type": "stub_api",
                        "detail": f"{dll}!{func}",
                        "impact": f"Stubbed, called {call_count}x",
                        "call_count": call_count,
                    })
                    score -= min(0.05, 0.005 * call_count)
        else:
            # No import data -- cannot assess; assume moderate risk
            warnings.append({
                "type": "no_import_data",
                "detail": "No import table data available",
                "impact": "Cannot assess API coverage without import analysis",
            })
            score *= 0.7

        # --- Anti-cheat detection ---
        analysis = patterns.get("analysis", {})
        for desc in analysis.get("anti_cheat_detected", []):
            warnings.append({
                "type": "anti_cheat",
                "detail": desc,
                "impact": "Anti-cheat may detect PE-compat environment and refuse to run",
            })
            score -= 0.08

        # --- Anti-debug detection ---
        for desc in analysis.get("anti_debug_detected", []):
            warnings.append({
                "type": "anti_debug",
                "detail": desc,
                "impact": "Anti-debug checks may trigger false positives",
            })
            score -= 0.03

        # --- DRM detection ---
        for desc in analysis.get("drm_detected", []):
            blocking.append({
                "type": "drm",
                "detail": desc,
                "impact": "DRM protection may prevent execution entirely",
            })
            score -= 0.15

        # --- Memory anomalies ---
        anomalies = memory.get("anomalies", [])
        critical_anomalies = [a for a in anomalies if a.get("severity") == "critical"]
        if critical_anomalies:
            warnings.append({
                "type": "memory_anomaly",
                "detail": f"{len(critical_anomalies)} critical memory anomalies detected",
                "impact": "Memory layout issues may cause crashes",
                "count": len(critical_anomalies),
            })
            score -= min(0.1, len(critical_anomalies) * 0.03)

        # Clamp score
        score = max(0.0, min(1.0, score))

        # --- Working features ---
        working.append("PE loading and memory mapping")
        if total > 0:
            working.append(f"{resolved}/{total} imports resolved ({int(resolved/total*100)}% coverage)")
        dll_count = len(memory.get("dlls", []))
        if dll_count > 0:
            working.append(f"{dll_count} DLL stubs loaded")

        dll_names = set(memory.get("dll_names", []))
        if dll_names & {"d3d9.dll", "d3d11.dll", "d3d12.dll", "dxgi.dll"}:
            working.append("DirectX DLL stubs loaded (DXVK/VKD3D-Proton translation)")
        if dll_names & {"ws2_32.dll", "wsock32.dll"}:
            working.append("Winsock networking stubs available")
        if dll_names & {"kernel32.dll", "ntdll.dll"}:
            working.append("Core Win32 subsystem stubs loaded")

        return score, blocking, warnings, working

    # ------------------------------------------------------------------
    # Failure prediction
    # ------------------------------------------------------------------

    def _predict_failures(
        self, stubs: dict, patterns: dict, memory: dict
    ) -> list:
        """Predict where and how the process will fail."""
        predictions = []

        # Predict failures from unimplemented stubs
        for rec in stubs.get("recommendations", [])[:10]:
            call_count = rec.get("call_count", 0)
            func = rec.get("function", "unknown")
            dll = rec.get("dll", "unknown")
            category = rec.get("category", "misc")

            if call_count > 50:
                likelihood = "high"
            elif call_count > 10:
                likelihood = "medium"
            else:
                likelihood = "low"

            predictions.append({
                "stage": "runtime",
                "api": f"{dll}!{func}",
                "category": category,
                "likelihood": likelihood,
                "call_count": call_count,
                "description": (
                    f"{func} in {dll} is stubbed and returning a dummy value. "
                    f"Called {call_count}x at runtime."
                ),
                "fix": f"Implement {func} in the {dll} stub library",
            })

        # Predict failures from anti-cheat
        analysis = patterns.get("analysis", {})
        for desc in analysis.get("anti_cheat_detected", []):
            predictions.append({
                "stage": "startup",
                "api": "anti-cheat",
                "category": "anti_cheat",
                "likelihood": "medium",
                "call_count": 0,
                "description": (
                    f"Anti-cheat system detected: {desc}. "
                    f"May check for Linux/Wine/PE-compat environment markers."
                ),
                "fix": "Ensure anti-cheat shim is loaded and returning convincing data",
            })

        # Predict failures from DRM
        for desc in analysis.get("drm_detected", []):
            predictions.append({
                "stage": "startup",
                "api": "drm",
                "category": "drm",
                "likelihood": "high",
                "call_count": 0,
                "description": (
                    f"DRM detected: {desc}. "
                    f"May perform hardware fingerprinting or online activation."
                ),
                "fix": "DRM bypass or compatibility shim required",
            })

        # Predict failures from missing DLLs
        missing = stubs.get("missing_count", 0)
        if missing > 0:
            predictions.append({
                "stage": "load",
                "api": "dll_resolution",
                "category": "loader",
                "likelihood": "high",
                "call_count": 0,
                "description": (
                    f"{missing} DLL imports could not be resolved. "
                    f"The process may crash during initialization."
                ),
                "fix": "Create .so stub libraries for the missing DLLs",
            })

        # Predict failures from memory anomalies
        anomalies = memory.get("anomalies", [])
        critical = [a for a in anomalies if a.get("severity") == "critical"]
        if critical:
            predictions.append({
                "stage": "runtime",
                "api": "memory_layout",
                "category": "memory",
                "likelihood": "medium",
                "call_count": 0,
                "description": (
                    f"{len(critical)} critical memory anomalies detected "
                    f"(e.g., executable heap, RWX text, IAT hooks). "
                    f"These suggest the process may be self-modifying or packed."
                ),
                "fix": "Investigate memory anomalies; may need unpacker support",
            })

        # Sort by likelihood severity
        likelihood_order = {"high": 0, "medium": 1, "low": 2}
        predictions.sort(key=lambda p: likelihood_order.get(p["likelihood"], 3))

        return predictions

    # ------------------------------------------------------------------
    # Recommendations
    # ------------------------------------------------------------------

    def _generate_recommendations(self, predictions: list, stubs: dict) -> list:
        """Generate prioritized action items based on predictions."""
        recs = []
        seen_actions = set()

        for pred in predictions:
            action = pred.get("fix", "")
            if action and action not in seen_actions:
                seen_actions.add(action)
                recs.append({
                    "priority": 1 if pred["likelihood"] == "high" else (
                        2 if pred["likelihood"] == "medium" else 3
                    ),
                    "action": action,
                    "category": pred.get("category", "misc"),
                    "impact": f"Fixes: {pred['api']} ({pred['description'][:80]}...)"
                              if len(pred["description"]) > 80
                              else f"Fixes: {pred['api']} ({pred['description']})",
                })

        return sorted(recs, key=lambda r: r["priority"])

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------

    def _generate_summary(
        self,
        exe_name: str,
        category: str,
        engine: str,
        graphics: str,
        score: float,
        blocking: list,
        predictions: list,
    ) -> str:
        """One-paragraph human-readable summary."""
        pct = int(score * 100)
        n_blocking = len(blocking)
        n_predictions = len(predictions)

        engine_str = f" ({engine} engine)" if engine != "custom" else ""
        graphics_str = f", {graphics} graphics" if graphics != "none" else ""

        risk = "high" if pct < 40 else ("moderate" if pct < 70 else "low")

        parts = [
            f"{exe_name} is classified as a {category}{engine_str}{graphics_str}.",
            f"Estimated compatibility: {pct}% ({risk} risk).",
        ]
        if n_blocking > 0:
            parts.append(f"{n_blocking} blocking issue{'s' if n_blocking != 1 else ''} found.")
        if n_predictions > 0:
            high = sum(1 for p in predictions if p["likelihood"] == "high")
            if high > 0:
                parts.append(f"{high} high-likelihood failure point{'s' if high != 1 else ''} predicted.")
            else:
                parts.append(f"{n_predictions} potential failure point{'s' if n_predictions != 1 else ''} predicted.")

        return " ".join(parts)

    def _generate_detailed_report(
        self,
        exe_name: str,
        category: str,
        engine: str,
        graphics: str,
        score: float,
        blocking: list,
        warnings: list,
        working: list,
        predictions: list,
        recommendations: list,
        memory_data: dict,
        pattern_data: dict,
        stub_data: dict,
    ) -> str:
        """Full multi-section analysis report."""
        lines = []
        pct = int(score * 100)

        # Header
        lines.append(f"=== Behavioral Analysis Report: {exe_name} ===")
        lines.append("")

        # Classification
        lines.append("--- Classification ---")
        lines.append(f"  Category:     {category}")
        lines.append(f"  Engine:       {engine}")
        lines.append(f"  Graphics API: {graphics}")
        lines.append(f"  Compatibility: {pct}%")
        lines.append("")

        # Memory profile
        lines.append("--- Memory Profile ---")
        dll_count = len(memory_data.get("dlls", []))
        total_mb = memory_data.get("total_mapped", 0) / (1024 * 1024)
        region_count = memory_data.get("region_count", 0)
        lines.append(f"  DLLs loaded:    {dll_count}")
        lines.append(f"  Memory regions: {region_count}")
        lines.append(f"  Total mapped:   {total_mb:.1f} MB")
        anomaly_count = len(memory_data.get("anomalies", []))
        if anomaly_count:
            lines.append(f"  Anomalies:      {anomaly_count}")
        lines.append("")

        # Import coverage
        lines.append("--- Import Coverage ---")
        total_imports = stub_data.get("total_imports", 0)
        resolved = stub_data.get("resolved_imports", 0)
        stubbed = stub_data.get("stub_count", 0)
        missing = stub_data.get("missing_count", 0)
        if total_imports > 0:
            lines.append(f"  Total imports:  {total_imports}")
            lines.append(f"  Resolved:       {resolved} ({int(resolved/total_imports*100)}%)")
            lines.append(f"  Stubbed:        {stubbed}")
            lines.append(f"  Missing:        {missing}")
        else:
            lines.append("  No import data available.")
        lines.append("")

        # Pattern scanner findings
        analysis = pattern_data.get("analysis", {})
        lines.append("--- Pattern Scanner Findings ---")
        total_matches = analysis.get("total_matches", 0)
        lines.append(f"  Total pattern matches: {total_matches}")
        if analysis.get("anti_cheat_detected"):
            lines.append(f"  Anti-cheat: {', '.join(analysis['anti_cheat_detected'])}")
        if analysis.get("anti_debug_detected"):
            lines.append(f"  Anti-debug: {', '.join(analysis['anti_debug_detected'])}")
        if analysis.get("drm_detected"):
            lines.append(f"  DRM: {', '.join(analysis['drm_detected'])}")
        if analysis.get("dx_requirements"):
            lines.append(f"  DirectX: {', '.join(analysis['dx_requirements'])}")
        if analysis.get("network_activity"):
            lines.append(f"  Network: {', '.join(analysis['network_activity'])}")
        if analysis.get("required_drivers"):
            lines.append(f"  Drivers: {', '.join(analysis['required_drivers'])}")
        lines.append("")

        # What works
        lines.append("--- Working Features ---")
        for w in working:
            lines.append(f"  [OK] {w}")
        lines.append("")

        # Blocking issues
        if blocking:
            lines.append("--- Blocking Issues (must fix) ---")
            for i, b in enumerate(blocking, 1):
                lines.append(f"  {i}. [{b['type']}] {b['detail']}")
                lines.append(f"     Impact: {b['impact']}")
            lines.append("")

        # Warnings
        if warnings:
            lines.append("--- Warnings ---")
            for i, w in enumerate(warnings, 1):
                lines.append(f"  {i}. [{w['type']}] {w['detail']}")
                lines.append(f"     Impact: {w['impact']}")
            lines.append("")

        # Failure predictions
        if predictions:
            lines.append("--- Failure Predictions ---")
            for i, p in enumerate(predictions, 1):
                lines.append(
                    f"  {i}. [{p['likelihood'].upper()}] {p['api']} "
                    f"(stage: {p['stage']})"
                )
                lines.append(f"     {p['description']}")
            lines.append("")

        # Recommendations
        if recommendations:
            lines.append("--- Recommended Actions (prioritized) ---")
            for i, r in enumerate(recommendations, 1):
                pri_label = {1: "HIGH", 2: "MEDIUM", 3: "LOW"}.get(r["priority"], "?")
                lines.append(f"  {i}. [{pri_label}] {r['action']}")
            lines.append("")

        lines.append(f"=== End of Report ({exe_name}) ===")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_exe_name(self, pid: int) -> str:
        try:
            return os.path.basename(os.readlink(f"/proc/{pid}/exe"))
        except (OSError, PermissionError):
            return f"pid_{pid}"

    def _count_threads(self, pid: int) -> int:
        try:
            return len(os.listdir(f"/proc/{pid}/task"))
        except (OSError, PermissionError):
            return 1

    def _count_network_hints(self, patterns: dict) -> int:
        """Count network-related pattern matches."""
        analysis = patterns.get("analysis", {})
        return len(analysis.get("network_activity", []))

    # ------------------------------------------------------------------
    # Query API (for the REST layer)
    # ------------------------------------------------------------------

    def get_fingerprint(self, pid: int) -> Optional[dict]:
        """Get the fingerprint for a previously analyzed process."""
        fp = self._fingerprints.get(pid)
        if fp:
            return fp.to_dict()
        return None

    def get_report(self, pid: int) -> Optional[dict]:
        """Get the detailed report for a previously analyzed process."""
        fp = self._fingerprints.get(pid)
        if fp:
            return {
                "pid": fp.pid,
                "exe_name": fp.exe_name,
                "summary": fp.summary,
                "detailed_report": fp.detailed_report,
            }
        return None

    def get_predictions(self, pid: int) -> Optional[dict]:
        """Get failure predictions for a previously analyzed process."""
        fp = self._fingerprints.get(pid)
        if fp:
            return {
                "pid": fp.pid,
                "exe_name": fp.exe_name,
                "compatibility_score": round(fp.compatibility_score, 3),
                "predicted_failures": fp.predicted_failures,
                "recommended_actions": fp.recommended_actions,
            }
        return None

    def get_all_fingerprints(self) -> list[dict]:
        """Summary list of all analyzed processes."""
        return [
            {
                "pid": fp.pid,
                "exe_name": fp.exe_name,
                "timestamp": fp.timestamp,
                "category": fp.category,
                "engine": fp.engine,
                "graphics_api": fp.graphics_api,
                "compatibility_score": round(fp.compatibility_score, 3),
                "blocking_issues": len(fp.blocking_issues),
                "predicted_failures": len(fp.predicted_failures),
            }
            for fp in self._fingerprints.values()
        ]

    def get_stats(self) -> dict:
        """Return engine statistics."""
        return {
            "analysis_count": self._analysis_count,
            "tracked_processes": len(self._fingerprints),
            "categories": self._category_breakdown(),
        }

    def _category_breakdown(self) -> dict:
        """Count processes per category."""
        cats: dict[str, int] = {}
        for fp in self._fingerprints.values():
            cats[fp.category] = cats.get(fp.category, 0) + 1
        return cats

    def clear_fingerprint(self, pid: int) -> bool:
        """Remove a stored fingerprint."""
        if pid in self._fingerprints:
            del self._fingerprints[pid]
            return True
        return False
