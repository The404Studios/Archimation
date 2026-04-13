"""
nftables rule management - generates and applies nftables rules.

Translates Windows-style firewall rules into nftables rulesets and
applies them via the nft command-line tool. Supports inbound/outbound
directions, allow/block actions, and filtering by protocol, port,
address, and application path (via cgroup matching).
"""

import ipaddress
import json
import logging
import re
import subprocess
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional

logger = logging.getLogger("firewall.nft_manager")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TABLE_NAME = "pe_compat_firewall"
INBOUND_CHAIN = "input_filter"
OUTBOUND_CHAIN = "output_filter"
FORWARD_CHAIN = "forward_filter"

NFT_BIN = "/usr/sbin/nft"

# Characters that must never appear in cgroup paths used in nft rules
_CGROUP_FORBIDDEN = re.compile(r'[;"\'`$\\]')


def _validate_address(addr: str) -> bool:
    """Validate IP address or CIDR notation."""
    try:
        if '/' in addr:
            ipaddress.ip_network(addr, strict=False)
        else:
            ipaddress.ip_address(addr)
        return True
    except ValueError:
        return False


def _validate_port_range(port_str: str) -> bool:
    """Validate port or port range."""
    if '-' in port_str:
        parts = port_str.split('-', 1)
        try:
            start, end = int(parts[0]), int(parts[1])
            return 0 <= start <= 65535 and 0 <= end <= 65535 and start <= end
        except ValueError:
            return False
    try:
        port = int(port_str)
        return 0 <= port <= 65535
    except ValueError:
        return False


class RuleValidationError(ValueError):
    """Raised when a firewall rule field contains invalid or dangerous input."""


def validate_rule_fields(rule: "FirewallRule") -> None:
    """Validate user-controlled fields of a FirewallRule before compilation.

    Raises :class:`RuleValidationError` if any field contains input that
    could lead to nftables rule injection.
    """
    if rule.remote_address is not None:
        if not _validate_address(rule.remote_address):
            raise RuleValidationError(
                f"Invalid remote_address: {rule.remote_address!r}"
            )

    if rule.local_address is not None:
        if not _validate_address(rule.local_address):
            raise RuleValidationError(
                f"Invalid local_address: {rule.local_address!r}"
            )

    if rule.port_range is not None:
        if not _validate_port_range(rule.port_range):
            raise RuleValidationError(
                f"Invalid port_range: {rule.port_range!r}"
            )

    if rule.port is not None:
        if not isinstance(rule.port, int) or not (0 <= rule.port <= 65535):
            raise RuleValidationError(
                f"Invalid port: {rule.port!r}"
            )

    if rule.application is not None:
        import os
        basename = os.path.basename(rule.application)
        if _CGROUP_FORBIDDEN.search(basename):
            raise RuleValidationError(
                f"Invalid application path (forbidden characters): "
                f"{rule.application!r}"
            )
        if "\x00" in rule.application:
            raise RuleValidationError(
                f"Invalid application path (null byte): {rule.application!r}"
            )


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Direction(str, Enum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"


class Action(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"


class Protocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ANY = "any"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class FirewallRule:
    """Represents a single firewall rule in Windows Firewall style."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    direction: str = Direction.INBOUND.value
    action: str = Action.BLOCK.value
    protocol: str = Protocol.ANY.value
    port: Optional[int] = None
    port_range: Optional[str] = None          # e.g. "1024-65535"
    remote_address: Optional[str] = None      # CIDR or single IP
    local_address: Optional[str] = None
    application: Optional[str] = None         # binary path
    enabled: bool = True
    profile: str = "public"                   # public | private | domain
    priority: int = 100                       # lower = higher priority

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "FirewallRule":
        known = {f.name for f in cls.__dataclass_fields__.values()}
        return cls(**{k: v for k, v in data.items() if k in known})


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------

class NftManager:
    """Generates and applies nftables rules from Windows-style rule objects.

    The manager maintains a single nftables table (``pe_compat_firewall``)
    with ``input_filter`` and ``output_filter`` base chains.  Rules are
    compiled into nft statements and applied atomically.
    """

    def __init__(self, nft_bin: str = NFT_BIN) -> None:
        self._nft_bin = nft_bin
        self._rules: dict[str, FirewallRule] = {}
        self._default_inbound_action: Action = Action.BLOCK
        self._default_outbound_action: Action = Action.ALLOW

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_rule(self, rule: FirewallRule) -> FirewallRule:
        """Add a firewall rule and return it (with generated id if needed).

        Raises :class:`RuleValidationError` if any field contains input
        that could lead to nftables rule injection.
        """
        validate_rule_fields(rule)
        if not rule.id:
            rule.id = str(uuid.uuid4())
        self._rules[rule.id] = rule
        logger.info("Added rule %s (%s)", rule.id, rule.name)
        return rule

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a rule by id.  Returns True if the rule existed."""
        removed = self._rules.pop(rule_id, None)
        if removed:
            logger.info("Removed rule %s (%s)", rule_id, removed.name)
            return True
        logger.warning("Rule %s not found for removal", rule_id)
        return False

    def enable_rule(self, rule_id: str) -> bool:
        """Enable a previously disabled rule."""
        rule = self._rules.get(rule_id)
        if rule is None:
            return False
        rule.enabled = True
        logger.info("Enabled rule %s (%s)", rule_id, rule.name)
        return True

    def disable_rule(self, rule_id: str) -> bool:
        """Disable a rule without removing it."""
        rule = self._rules.get(rule_id)
        if rule is None:
            return False
        rule.enabled = False
        logger.info("Disabled rule %s (%s)", rule_id, rule.name)
        return True

    def get_rule(self, rule_id: str) -> Optional[FirewallRule]:
        """Retrieve a single rule by id."""
        return self._rules.get(rule_id)

    def list_rules(
        self,
        direction: Optional[str] = None,
        profile: Optional[str] = None,
        enabled_only: bool = False,
    ) -> list[FirewallRule]:
        """List rules with optional filters."""
        result: list[FirewallRule] = []
        for rule in self._rules.values():
            if direction and rule.direction != direction:
                continue
            if profile and rule.profile != profile:
                continue
            if enabled_only and not rule.enabled:
                continue
            result.append(rule)
        result.sort(key=lambda r: r.priority)
        return result

    def flush_rules(self) -> None:
        """Remove all rules from memory and flush the nftables table."""
        self._rules.clear()
        # Only flush if the table actually exists to avoid nft errors
        if self.is_enabled():
            self._exec_nft(["flush", "table", "inet", TABLE_NAME])
        logger.info("Flushed all rules")

    def set_default_actions(
        self,
        inbound: Action = Action.BLOCK,
        outbound: Action = Action.ALLOW,
    ) -> None:
        """Set the default policy for inbound/outbound chains."""
        self._default_inbound_action = inbound
        self._default_outbound_action = outbound

    # ------------------------------------------------------------------
    # Ruleset generation
    # ------------------------------------------------------------------

    def generate_ruleset(self, profile: Optional[str] = None) -> str:
        """Generate a complete nftables ruleset string.

        If *profile* is given only rules matching that profile (plus rules
        with profile ``*``) are included.
        """
        lines: list[str] = []
        lines.append(f"flush table inet {TABLE_NAME}")
        lines.append(f"table inet {TABLE_NAME} {{")

        # --- input chain ---
        inbound_policy = "drop" if self._default_inbound_action == Action.BLOCK else "accept"
        lines.append(f"  chain {INBOUND_CHAIN} {{")
        lines.append(f"    type filter hook input priority 0; policy {inbound_policy};")
        lines.append("    # Allow established/related")
        lines.append("    ct state established,related accept")
        lines.append("    # Allow loopback")
        lines.append("    iif lo accept")
        for rule in self._sorted_rules(Direction.INBOUND, profile):
            stmt = self._compile_rule(rule)
            if stmt:
                lines.append(f"    # {rule.name} [{rule.id[:8]}]")
                lines.append(f"    {stmt}")
        lines.append("  }")

        # --- output chain ---
        outbound_policy = "drop" if self._default_outbound_action == Action.BLOCK else "accept"
        lines.append(f"  chain {OUTBOUND_CHAIN} {{")
        lines.append(f"    type filter hook output priority 0; policy {outbound_policy};")
        lines.append("    # Allow established/related")
        lines.append("    ct state established,related accept")
        lines.append("    # Allow loopback")
        lines.append("    oif lo accept")
        for rule in self._sorted_rules(Direction.OUTBOUND, profile):
            stmt = self._compile_rule(rule)
            if stmt:
                lines.append(f"    # {rule.name} [{rule.id[:8]}]")
                lines.append(f"    {stmt}")
        lines.append("  }")

        # --- forward chain (default drop) ---
        lines.append(f"  chain {FORWARD_CHAIN} {{")
        lines.append("    type filter hook forward priority 0; policy drop;")
        lines.append("  }")

        lines.append("}")
        return "\n".join(lines)

    def apply_rules(self, profile: Optional[str] = None) -> bool:
        """Generate the ruleset and apply it atomically via ``nft -f``.

        Returns True on success, False on error.
        """
        ruleset = self.generate_ruleset(profile)
        logger.debug("Applying ruleset:\n%s", ruleset)
        return self._apply_ruleset(ruleset)

    # ------------------------------------------------------------------
    # Live nftables queries
    # ------------------------------------------------------------------

    def list_active_nft_rules(self) -> str:
        """Return the current nftables ruleset as reported by ``nft list ruleset``."""
        return self._exec_nft(["list", "ruleset"], capture=True)

    def list_active_table(self) -> str:
        """Return only the pe_compat_firewall table."""
        return self._exec_nft(["list", "table", "inet", TABLE_NAME], capture=True)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _sorted_rules(
        self, direction: Direction, profile: Optional[str]
    ) -> list[FirewallRule]:
        """Return enabled rules for *direction*, sorted by priority."""
        rules: list[FirewallRule] = []
        for r in self._rules.values():
            if not r.enabled:
                continue
            if r.direction != direction.value:
                continue
            if profile and r.profile not in (profile, "*"):
                continue
            rules.append(r)
        rules.sort(key=lambda r: r.priority)
        return rules

    def _compile_rule(self, rule: FirewallRule) -> str:
        """Compile a single FirewallRule into an nft rule statement."""
        # Defense-in-depth: validate again at compile time even though
        # add_rule() already validates.  This catches rules loaded from
        # JSON or constructed programmatically.
        validate_rule_fields(rule)

        parts: list[str] = []

        # Protocol match
        proto = rule.protocol
        if proto and proto != Protocol.ANY.value:
            if proto == Protocol.ICMP.value:
                parts.append("meta l4proto icmp")
            else:
                parts.append(f"meta l4proto {proto}")

        # Address matches
        if rule.direction == Direction.INBOUND.value:
            if rule.remote_address:
                parts.append(f"ip saddr {rule.remote_address}")
            if rule.local_address:
                parts.append(f"ip daddr {rule.local_address}")
        else:
            if rule.local_address:
                parts.append(f"ip saddr {rule.local_address}")
            if rule.remote_address:
                parts.append(f"ip daddr {rule.remote_address}")

        # Port matches (only for tcp/udp)
        if rule.port and proto in (Protocol.TCP.value, Protocol.UDP.value):
            if rule.direction == Direction.INBOUND.value:
                parts.append(f"{proto} dport {rule.port}")
            else:
                parts.append(f"{proto} dport {rule.port}")
        elif rule.port_range and proto in (Protocol.TCP.value, Protocol.UDP.value):
            if rule.direction == Direction.INBOUND.value:
                parts.append(f"{proto} dport {rule.port_range}")
            else:
                parts.append(f"{proto} dport {rule.port_range}")

        # Application match via cgroup (Linux equivalent of app filtering)
        if rule.application:
            # nftables can match socket cgroup; we use a meta match.
            # The actual cgroup mapping is handled by the app_tracker module.
            cgroup_path = self._app_to_cgroup(rule.application)
            if cgroup_path:
                # Before inserting into nft rule, escape special chars
                cgroup_safe = cgroup_path.replace('"', '\\"').replace('\n', '').replace('\r', '')
                parts.append(f'socket cgroupv2 level 2 "{cgroup_safe}"')

        # Counter for logging/stats
        parts.append("counter")

        # Action
        action = "accept" if rule.action == Action.ALLOW.value else "drop"
        parts.append(action)

        return " ".join(parts)

    @staticmethod
    def _app_to_cgroup(app_path: str) -> Optional[str]:
        """Map an application binary path to a cgroup v2 path.

        In production this would look up the systemd slice for the
        application.  For now we derive a deterministic cgroup name.
        """
        if not app_path:
            return None
        # Use the binary name as the cgroup leaf
        import os
        basename = os.path.basename(app_path).replace(".", "_")
        return f"pe-compat.slice/{basename}.scope"

    def _apply_ruleset(self, ruleset: str) -> bool:
        """Write *ruleset* to a temp file and load via ``nft -f``."""
        import tempfile
        import os

        fd, path = tempfile.mkstemp(prefix="pe_fw_", suffix=".nft")
        try:
            with os.fdopen(fd, "w") as fh:
                fh.write(ruleset + "\n")
            result = subprocess.run(
                [self._nft_bin, "-f", path],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.returncode != 0:
                logger.error(
                    "nft apply failed (rc=%d): %s",
                    result.returncode,
                    result.stderr.strip(),
                )
                return False
            logger.info("Ruleset applied successfully")
            return True
        except subprocess.TimeoutExpired:
            logger.error("nft apply timed out")
            return False
        except FileNotFoundError:
            logger.error("nft binary not found at %s", self._nft_bin)
            return False
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass

    def _exec_nft(self, args: list[str], capture: bool = False) -> str:
        """Run an arbitrary ``nft`` command.  Returns stdout when *capture* is True.

        *args* must be a list of strings.  String arguments are not
        accepted to prevent shell-injection via ``shlex.split`` on
        attacker-controlled input.
        """
        if isinstance(args, str):
            raise TypeError(
                "_exec_nft() requires a list of arguments, not a string. "
                "This prevents shell-injection via shlex.split()."
            )
        cmd = [self._nft_bin] + list(args)
        try:
            result = subprocess.run(
                cmd,
                shell=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                logger.warning("nft command failed: %s — %s", cmd, result.stderr.strip())
            if capture:
                return result.stdout
            return ""
        except Exception as exc:
            logger.error("nft exec error: %s", exc)
            return ""

    # ------------------------------------------------------------------
    # Bulk load helpers
    # ------------------------------------------------------------------

    def load_rules(self, rules: list[FirewallRule]) -> None:
        """Replace all in-memory rules with *rules*."""
        self._rules.clear()
        for rule in rules:
            self._rules[rule.id] = rule
        logger.info("Loaded %d rules", len(rules))

    def export_rules_json(self) -> str:
        """Export all rules as a JSON string."""
        return json.dumps(
            [r.to_dict() for r in self._rules.values()],
            indent=2,
        )

    def import_rules_json(self, data: str) -> int:
        """Import rules from a JSON string.  Returns count imported."""
        items = json.loads(data)
        count = 0
        for item in items:
            rule = FirewallRule.from_dict(item)
            self._rules[rule.id] = rule
            count += 1
        logger.info("Imported %d rules from JSON", count)
        return count

    # ------------------------------------------------------------------
    # Methods expected by the GUI and CLI
    # ------------------------------------------------------------------

    def is_enabled(self) -> bool:
        """Check if the firewall is active (our nftables table exists)."""
        try:
            output = self._exec_nft(["list", "table", "inet", TABLE_NAME], capture=True)
            return TABLE_NAME in output
        except Exception:
            return False

    def enable(self) -> None:
        """Apply rules to activate the firewall."""
        self.apply_rules()
        logger.info("Firewall enabled")

    def disable(self) -> None:
        """Flush the nftables table to deactivate the firewall."""
        self._exec_nft(["flush", "table", "inet", TABLE_NAME])
        self._exec_nft(["delete", "table", "inet", TABLE_NAME])
        logger.info("Firewall disabled")

    def active_connection_count(self) -> int:
        """Return the count of tracked connections via conntrack or /proc."""
        # Try conntrack tool first
        try:
            result = subprocess.run(
                ["conntrack", "-C"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                count_str = result.stdout.strip()
                if count_str.isdigit():
                    return int(count_str)
        except (FileNotFoundError, ValueError, subprocess.TimeoutExpired):
            pass
        # Fallback: count entries in /proc/net/nf_conntrack
        try:
            with open("/proc/net/nf_conntrack", "r") as fh:
                return sum(1 for _ in fh)
        except (FileNotFoundError, PermissionError):
            pass
        return 0

    def reload(self) -> None:
        """Re-apply rules from the in-memory rule set."""
        self.apply_rules()
        logger.info("Firewall rules reloaded")


if __name__ == "__main__":
    import argparse as _argparse
    import time as _time

    _parser = _argparse.ArgumentParser(description="NftManager daemon/flush helper")
    _parser.add_argument("--daemon", action="store_true", help="Load rules and run as daemon")
    _parser.add_argument("--flush", action="store_true", help="Flush rules and exit")
    _cli_args = _parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    _mgr = NftManager()

    if _cli_args.flush:
        _mgr.disable()
        logger.info("Rules flushed, exiting.")
    elif _cli_args.daemon:
        # Load rules from the persistent store
        import sys as _sys, os as _os
        _sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
        from rule_store import RuleStore as _RuleStore
        _store = _RuleStore()
        try:
            _all_rules = _store.list_rules()
            _mgr.load_rules(_all_rules)
            _mgr.apply_rules()
            logger.info("Daemon mode: rules loaded and applied. Sleeping...")
            while True:
                _time.sleep(60)
        except KeyboardInterrupt:
            logger.info("Daemon interrupted, exiting.")
        finally:
            _store.close()
    else:
        _parser.print_help()
