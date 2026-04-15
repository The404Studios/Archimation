"""
Firewall control module - manages nftables rules via the PE-Compat firewall backend.

Bridges the AI daemon's REST API with the full firewall backend (NftManager,
RuleStore, ConnectionMonitor). Rules added via the API are persisted in the
RuleStore and visible in the GUI, and vice versa.
"""

import asyncio
import logging
import re
import sys
from pathlib import Path
from typing import Optional

logger = logging.getLogger("ai-control.firewall")

# Add firewall package to path so we can import from firewall.backend
# Try production path first, then development tree path
_fw_backend_prod = Path("/usr/lib/pe-compat/firewall")
_fw_backend_dev = Path(__file__).resolve().parent.parent.parent / "firewall"
_fw_backend_root = _fw_backend_prod if _fw_backend_prod.is_dir() else _fw_backend_dev
if str(_fw_backend_root) not in sys.path:
    sys.path.insert(0, str(_fw_backend_root))

NFT_BIN = "/usr/sbin/nft"

# Try to import the full firewall backend; fall back to raw nft if unavailable
_backend_available = False
try:
    from backend.nft_manager import NftManager, FirewallRule, Direction, Action, Protocol
    from backend.rule_store import RuleStore
    from backend.connection_monitor import ConnectionMonitor
    from backend import app_tracker as _app_tracker_mod
    _backend_available = True
except ImportError:
    logger.warning("Firewall backend not available — using raw nft fallback")
    _app_tracker_mod = None  # type: ignore

# cgroup_manager is optional -- the daemon keeps working on systems without
# cgroup v2 (the nft socket-cgroupv2 predicate just never matches).  We import
# it defensively so an ImportError from a non-Linux build host doesn't take
# the whole firewall offline.
_cgroup_manager_mod = None
if _backend_available:
    try:
        from backend import cgroup_manager as _cgroup_manager_mod  # type: ignore
    except ImportError:
        logger.debug("cgroup_manager module unavailable — app-scope enforcement disabled")
        _cgroup_manager_mod = None


class FirewallController:
    """AI-facing controller bridging the REST API with the full firewall backend."""

    def __init__(self, nft_bin: str = NFT_BIN) -> None:
        self._nft_bin = nft_bin
        self._nft: Optional["NftManager"] = None
        self._store: Optional["RuleStore"] = None
        self._monitor: Optional["ConnectionMonitor"] = None
        self._tracker = None  # AppTracker instance owning the app-rule listener

        if _backend_available:
            try:
                self._nft = NftManager()
                self._store = RuleStore()
                self._monitor = ConnectionMonitor()
                self._monitor.start()
                # ------------------------------------------------------------------
                # Wire AppTracker -> NftManager so rule.application entries actually
                # enforce.  Without this, nft emits "socket cgroupv2 level 2
                # \"pe-compat.slice/<app>.scope\"" predicates but no PID ever
                # lives in that cgroup path, so the rule never matches.  The
                # tracker's on_rule_changed() callback plus its /proc polling
                # place running PIDs into the right scope.
                #
                # Graceful fallback: if cgroup v2 isn't available or we lack
                # permission (e.g. running non-root in a container), the
                # cgroup_manager methods become no-ops and return False --
                # the firewall still works, application predicates just don't
                # match.  We log once so operators can diagnose.
                # ------------------------------------------------------------------
                cgroup_ok = False
                if _cgroup_manager_mod is not None:
                    try:
                        cgroup_ok = bool(_cgroup_manager_mod.detect_cgroupv2())
                    except Exception:
                        cgroup_ok = False

                if cgroup_ok:
                    try:
                        # Pre-create pe-compat.slice so the first rule add
                        # doesn't race with cgroup directory creation.
                        _cgroup_manager_mod.ensure_slice()
                    except Exception:
                        logger.exception("cgroup_manager.ensure_slice() failed")

                    if _app_tracker_mod is not None:
                        try:
                            self._tracker = _app_tracker_mod.AppTracker()
                            self._tracker.attach_to_nft_manager(self._nft)
                            logger.info(
                                "AppTracker attached to NftManager "
                                "(cgroup v2 enforcement active)"
                            )
                        except Exception:
                            logger.exception(
                                "Failed to attach AppTracker; application-scoped "
                                "firewall rules will not enforce"
                            )
                            self._tracker = None
                else:
                    logger.warning(
                        "cgroup v2 not available or insufficient permissions — "
                        "application-scoped firewall rules will be compiled "
                        "but not enforced"
                    )

                logger.info("Firewall backend initialized (NftManager + RuleStore + ConnectionMonitor)")
            except Exception:
                logger.exception("Failed to initialize firewall backend, falling back to raw nft")
                self._nft = None
                self._store = None
                self._monitor = None
                self._tracker = None

    def prune_pid_cache(self) -> int:
        """Prune stale (exited) PIDs from the AppTracker's memoisation set.

        The tracker memoises successful cgroup placements as
        ``(pid, app_name)`` tuples to avoid hammering ``cgroup.procs`` on
        every 2-second poll.  Linux recycles PID numbers, so without
        pruning, a stale entry for a long-dead process can cause a newly
        spawned process with the same PID to skip scoping.  Call this
        from the daemon's housekeeping timer (once per minute is plenty).

        Returns the number of entries pruned, 0 when there's no tracker.
        """
        tracker = self._tracker
        if tracker is None:
            return 0
        try:
            from firewall import prune_exited_pids  # type: ignore
        except ImportError:
            return 0
        try:
            return prune_exited_pids(tracker)
        except Exception:
            logger.debug("prune_exited_pids failed", exc_info=True)
            return 0

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    async def get_status(self) -> dict:
        """Return firewall status: enabled, rule counts, connections."""
        if self._nft:
            enabled = self._nft.is_enabled()
            rule_count = self._store.count_rules() if self._store else 0
            conn_count = self._nft.active_connection_count()
            return {
                "enabled": enabled,
                "rule_count": rule_count,
                "active_connections": conn_count,
                "backend": "full",
            }
        # Fallback
        active = await self._table_exists()
        return {
            "enabled": active,
            "rule_count": 0,
            "active_connections": 0,
            "backend": "raw_nft",
        }

    async def list_rules(self, direction: Optional[str] = None) -> list:
        """Return current firewall rules from the RuleStore."""
        if self._store and _backend_available:
            dir_enum = None
            if direction and _backend_available:
                dir_enum = Direction.INBOUND if direction == "inbound" else Direction.OUTBOUND
            rules = self._store.list_rules(direction=dir_enum)
            return [
                {
                    "id": r.id,
                    "name": r.name,
                    "direction": r.direction.value if r.direction else None,
                    "action": r.action.value if r.action else None,
                    "protocol": r.protocol.value if r.protocol else None,
                    "port": r.port,
                    "remote_address": r.remote_address,
                    "enabled": r.enabled,
                    "priority": r.priority,
                }
                for r in rules
            ]
        # Fallback: raw nft output
        if await self._table_exists():
            return await self._run_nft("list table inet pe_compat_firewall")
        return []

    def get_connections(self) -> list:
        """Return active network connections from the ConnectionMonitor."""
        if self._monitor:
            return self._monitor.get_connections()
        return []

    # ------------------------------------------------------------------
    # Control
    # ------------------------------------------------------------------

    async def enable(self) -> dict:
        """Enable the firewall."""
        if self._nft:
            try:
                self._nft.enable()
                return {"success": True}
            except Exception as exc:
                return {"success": False, "error": str(exc)}
        return await self._systemctl("start", "pe-compat-firewall.service")

    async def disable(self) -> dict:
        """Disable the firewall."""
        if self._nft:
            try:
                self._nft.disable()
                return {"success": True}
            except Exception as exc:
                return {"success": False, "error": str(exc)}
        return await self._systemctl("stop", "pe-compat-firewall.service")

    async def reload(self) -> dict:
        """Reload firewall rules from the RuleStore and apply."""
        if self._nft:
            try:
                self._nft.reload()
                return {"success": True}
            except Exception as exc:
                return {"success": False, "error": str(exc)}
        return await self._systemctl("restart", "pe-compat-firewall.service")

    # ------------------------------------------------------------------
    # Rule management (via RuleStore for persistence + GUI visibility)
    # ------------------------------------------------------------------

    async def add_rule(self, chain: str, rule: str,
                       name: Optional[str] = None,
                       direction: str = "inbound",
                       protocol: str = "any",
                       port: Optional[int] = None,
                       remote_address: Optional[str] = None) -> dict:
        """Add a firewall rule. Persisted in RuleStore and applied via NftManager."""
        if self._store and self._nft:
            try:
                fw_rule = FirewallRule(
                    name=name or f"api-rule-{chain}",
                    direction=Direction.INBOUND if direction == "inbound" else Direction.OUTBOUND,
                    action=Action.ALLOW,
                    protocol=_parse_protocol(protocol),
                    port=port,
                    remote_address=remote_address,
                    enabled=True,
                )
                stored_rule = self._store.add_rule(fw_rule)
                self._nft.reload()
                return {"success": True, "rule_id": stored_rule.id}
            except Exception as exc:
                return {"success": False, "error": str(exc)}
        # Fallback: raw nft (validate inputs to prevent syntax injection)
        if not _validate_chain(chain):
            return {"success": False, "error": "invalid chain name"}
        if not _validate_rule(rule):
            return {"success": False, "error": "invalid rule syntax"}
        cmd = f'add rule inet pe_compat_firewall {chain} {rule}'
        output = await self._run_nft(cmd)
        return {"success": True, "output": output}

    async def delete_rule(self, chain: str, handle) -> dict:
        """Delete a rule by its ID (RuleStore UUID str) or handle (raw nft int)."""
        if self._store and self._nft:
            try:
                self._store.delete_rule(str(handle))
                self._nft.reload()
                return {"success": True}
            except Exception as exc:
                return {"success": False, "error": str(exc)}
        if not _validate_chain(chain):
            return {"success": False, "error": "invalid chain name"}
        # handle must be numeric
        try:
            handle_int = int(handle)
        except (ValueError, TypeError):
            return {"success": False, "error": "invalid handle (must be integer)"}
        cmd = f'delete rule inet pe_compat_firewall {chain} handle {handle_int}'
        output = await self._run_nft(cmd)
        return {"success": True, "output": output}

    async def flush_chain(self, chain: str) -> dict:
        """Flush all rules from a chain."""
        if self._store and self._nft:
            try:
                self._nft.flush_rules()
                self._nft.reload()
                return {"success": True}
            except Exception as exc:
                return {"success": False, "error": str(exc)}
        # Fallback: raw nft (no reload — would re-add RuleStore rules)
        if not _validate_chain(chain):
            return {"success": False, "error": "invalid chain name"}
        cmd = f'flush chain inet pe_compat_firewall {chain}'
        output = await self._run_nft(cmd)
        return {"success": True, "output": output}

    # ------------------------------------------------------------------
    # Internals (raw nft fallback)
    # ------------------------------------------------------------------

    async def _table_exists(self) -> bool:
        try:
            output = await self._run_nft("list table inet pe_compat_firewall")
            return "pe_compat_firewall" in output
        except Exception:
            return False

    async def _run_nft(self, args: str) -> str:
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                self._nft_bin, *args.split(),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
            if proc.returncode != 0:
                logger.warning("nft failed: %s %s — %s", self._nft_bin, args,
                               stderr.decode(errors="replace").strip())
            return stdout.decode(errors="replace")
        except asyncio.TimeoutError:
            logger.error("nft command timed out: %s %s", self._nft_bin, args)
            if proc is not None:
                try:
                    proc.kill()
                    await proc.wait()
                except Exception:
                    pass
            return ""
        except FileNotFoundError:
            logger.error("nft binary not found at %s", self._nft_bin)
            return ""

    @staticmethod
    async def _systemctl(action: str, unit: str) -> dict:
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                "systemctl", action, unit,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
            return {
                "success": proc.returncode == 0,
                "stdout": stdout.decode(errors="replace").strip(),
                "stderr": stderr.decode(errors="replace").strip(),
            }
        except asyncio.TimeoutError:
            if proc is not None:
                try:
                    proc.kill()
                    await proc.wait()
                except Exception:
                    pass
            return {"success": False, "error": "timeout"}
        except Exception as exc:
            return {"success": False, "error": str(exc)}


_CHAIN_RE = re.compile(r'^[a-zA-Z0-9_-]{1,64}$')
_RULE_UNSAFE_RE = re.compile(r'[;&|`$(){}<>\\]')


def _validate_chain(chain: str) -> bool:
    """Validate that a chain name contains only safe characters."""
    return bool(_CHAIN_RE.match(chain))


def _validate_rule(rule: str) -> bool:
    """Reject rule strings containing shell metacharacters or nft control syntax."""
    if _RULE_UNSAFE_RE.search(rule):
        return False
    # Block attempts to use nft include/define directives
    lower = rule.lower().strip()
    if lower.startswith(('include ', 'define ', 'redefine ')):
        return False
    return True


def _parse_protocol(proto: str) -> "Protocol":
    """Convert a protocol string to the Protocol enum."""
    if not _backend_available:
        return proto
    mapping = {
        "tcp": Protocol.TCP,
        "udp": Protocol.UDP,
        "icmp": Protocol.ICMP,
    }
    return mapping.get(proto.lower(), Protocol.ANY)
