#!/usr/bin/env python3
"""
PE-Compat Firewall CLI - ``winfw`` command-line management tool.

Provides a Windows-style CLI for managing the nftables-backed firewall:

    winfw status              Show firewall status and active profile
    winfw enable              Enable the firewall
    winfw disable             Disable the firewall
    winfw add ...             Add a new firewall rule
    winfw remove ...          Remove a firewall rule
    winfw list ...            List firewall rules
    winfw monitor             Live terminal connection monitor
    winfw profile --set NAME  Change the active network profile
    winfw import FILE         Import rules from JSON
    winfw export FILE         Export rules to JSON
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import Any, NoReturn

# Ensure we can import the backend package for deferred imports below.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Backend modules (NftManager, RuleStore, ConnectionMonitor, ProfileManager,
# FirewallRule) are imported lazily inside each sub-command.  Keeping the
# top-level import path light keeps ``winfw --help`` and ``winfw status``
# startup snappy on old hardware -- the full backend pulls in asyncio,
# ipaddress, subprocess, sqlite3, and ~2000 lines of module code that
# status-like invocations don't need to compile up-front.

logger = logging.getLogger("pe-compat.firewall.cli")

# Terminal colours (ANSI)
_RESET = "\033[0m"
_BOLD = "\033[1m"
_RED = "\033[91m"
_GREEN = "\033[92m"
_YELLOW = "\033[93m"
_CYAN = "\033[96m"
_DIM = "\033[2m"


def _colour(text: str, code: str) -> str:
    """Wrap *text* in an ANSI colour code if stdout is a TTY."""
    if sys.stdout.isatty():
        return f"{code}{text}{_RESET}"
    return text


# ---------------------------------------------------------------------------
# Sub-commands
# ---------------------------------------------------------------------------

def cmd_status(_args: argparse.Namespace) -> None:
    """Show firewall status and active profile."""
    from backend import NftManager, ProfileManager, RuleStore  # noqa: E402
    nft = NftManager()
    profiles = ProfileManager()

    enabled = nft.is_enabled()
    profile_name = profiles.get_active_profile_name()
    store = RuleStore()  # noqa: F811  (imported lazily above)

    status_str = _colour("ON", _GREEN) if enabled else _colour("OFF", _RED)
    print(f"{_colour('Firewall Status:', _BOLD)} {status_str}")
    print(f"{_colour('Active Profile:', _BOLD)}  {profile_name.capitalize()}")
    print()

    inbound = store.count_rules(direction="inbound")
    outbound = store.count_rules(direction="outbound")
    print(f"  Inbound rules:  {inbound}")
    print(f"  Outbound rules: {outbound}")

    try:
        active = nft.active_connection_count()
        print(f"  Active connections: {active}")
    except Exception:
        pass

    try:
        blocked = store.blocked_count_today()
        print(f"  Blocked today: {blocked}")
    except Exception:
        pass


def cmd_enable(_args: argparse.Namespace) -> None:
    """Enable the firewall.

    We ensure the pe-compat.slice cgroup exists at enable time so that any
    ``socket cgroupv2`` predicates emitted by subsequent rule loads can
    match.  The slice is created lazily anyway, but doing it here produces
    a single diagnostic on failure instead of N rule-evaluation failures.
    """
    from backend import NftManager  # noqa: E402
    try:
        from backend import cgroup_manager as _cgm  # noqa: E402
        if _cgm.detect_cgroupv2():
            _cgm.ensure_slice()
    except ImportError:
        pass  # cgroup_manager is optional
    NftManager().enable()
    print(_colour("Firewall enabled.", _GREEN))


def cmd_disable(_args: argparse.Namespace) -> None:
    """Disable the firewall."""
    from backend import NftManager  # noqa: E402
    NftManager().disable()
    print(_colour("Firewall disabled.", _YELLOW))


def cmd_add(args: argparse.Namespace) -> None:
    """Add a new firewall rule."""
    from backend import FirewallRule, NftManager, RuleStore  # noqa: E402
    rule = FirewallRule(
        name=args.name,
        direction=args.direction,
        action=args.action,
        protocol=args.protocol,
        port=args.port,
        remote_address=args.address,
        application=args.app,
        enabled=True,
    )

    store = RuleStore()
    stored = store.add_rule(rule)
    # A fresh NftManager has an empty in-memory rule set, so reload()
    # alone would apply an empty ruleset and wipe out whatever rules
    # were already active.  Load from the persistent store first.
    nft = NftManager()
    nft.load_rules(store.list_rules())
    nft.apply_rules()
    print(
        f"Rule added (id={stored.id}): "
        f"{_colour(args.action.upper(), _GREEN if args.action == 'allow' else _RED)} "
        f"{args.direction} {args.protocol.upper()} port {args.port or 'any'}"
    )


def cmd_remove(args: argparse.Namespace) -> None:
    """Remove a firewall rule by name or id."""
    from backend import NftManager, RuleStore  # noqa: E402
    store = RuleStore()

    def _reload_from_store() -> None:
        nft = NftManager()
        nft.load_rules(store.list_rules())
        nft.apply_rules()

    if args.id is not None:
        store.delete_rule(args.id)
        _reload_from_store()
        print(f"Rule id={args.id} removed.")
    elif args.name:
        rules = store.get_rules()
        matched = [r for r in rules if r.get("name") == args.name]
        if not matched:
            print(_colour(f"No rule named '{args.name}' found.", _RED))
            sys.exit(1)
        for r in matched:
            store.delete_rule(r["id"])
        _reload_from_store()
        print(f"Removed {len(matched)} rule(s) named '{args.name}'.")
    else:
        print(_colour("Specify --name or --id.", _RED))
        sys.exit(1)


def cmd_list(args: argparse.Namespace) -> None:
    """List firewall rules."""
    from backend import ProfileManager, RuleStore  # noqa: E402
    store = RuleStore()
    profiles_mgr = ProfileManager()

    direction = getattr(args, "direction", None)
    profile = getattr(args, "profile", None) or profiles_mgr.get_active_profile_name()

    rules = store.get_rules(direction=direction)

    # Filter by profile if requested
    if profile:
        rules = [
            r for r in rules
            if r.get("profile", "all") in (profile, "all", "*")
        ]

    if not rules:
        print(_colour("No rules found.", _DIM))
        return

    # Header
    hdr = f"{'ID':>36}  {'Enabled':>7}  {'Dir':>8}  {'Action':>6}  {'Proto':>5}  {'Port':>6}  Name"
    print(_colour(hdr, _BOLD))
    print("-" * len(hdr))

    for r in rules:
        rid = r.get("id", "-")
        ena = _colour("Yes", _GREEN) if r.get("enabled", True) else _colour("No", _RED)
        direction_str = r.get("direction", "?")[:3]
        action = r.get("action", "?")
        action_c = _colour(action.upper(), _GREEN if action == "allow" else _RED)
        proto = r.get("protocol", "any").upper()
        port = r.get("port") or "any"
        name = r.get("name", "")

        print(f"{rid:>36}  {ena:>7}  {direction_str:>8}  {action_c:>6}  {proto:>5}  {str(port):>6}  {name}")


def cmd_monitor(_args: argparse.Namespace) -> None:
    """Live terminal connection monitor (refreshes every 2s)."""
    # Use AppTracker directly: ConnectionMonitor.get_connections() only
    # reports entries that have been picked up by its background poll
    # loop, which we never start here.  AppTracker.get_connections()
    # reads /proc synchronously each call, which is what we want for
    # a one-shot CLI refresh loop.
    import signal
    import time
    from backend import AppTracker, NftManager
    monitor = AppTracker()
    # Wire tracker → NftManager so rules with application= fields actually
    # cause PIDs to be scoped.  The monitor CLI is the most common path
    # users take to watch rules work interactively, so hooking the tracker
    # here lets "winfw monitor" double as a live enforcement surface.
    try:
        from backend import cgroup_manager as _cgm
        if _cgm.detect_cgroupv2():
            _cgm.ensure_slice()
            monitor.attach_to_nft_manager(NftManager())
    except ImportError:
        pass
    except Exception:
        logger.debug("attach_to_nft_manager failed", exc_info=True)
    running = True

    def _handle_signal(_sig: int, _frame: object) -> None:
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    state_colours: dict[str, str] = {
        "ESTABLISHED": _GREEN,
        "LISTEN": _YELLOW,
        "LISTENING": _YELLOW,
        "TIME_WAIT": _DIM,
        "CLOSE_WAIT": _DIM,
        "BLOCKED": _RED,
    }

    print(_colour("Live Connection Monitor  (Ctrl+C to exit)", _BOLD))
    print()

    from dataclasses import asdict
    # ANSI escape: move cursor home + clear below.  os.system("clear")
    # forks /bin/sh on every tick which on old hardware is ~20 ms of
    # pure overhead; the escape is zero-cost on any ANSI terminal.
    _CLEAR_SCREEN = "\033[H\033[2J"
    while running:
        try:
            raw = monitor.get_connections()
            connections = [asdict(c) for c in raw]
        except Exception as exc:
            print(_colour(f"Error: {exc}", _RED))
            time.sleep(2)
            continue

        # Clear screen via ANSI (fast) with fallback for non-TTY or
        # Windows terminals without VT processing enabled.
        if sys.stdout.isatty() and os.name != "nt":
            sys.stdout.write(_CLEAR_SCREEN)
            sys.stdout.flush()
        else:
            os.system("clear" if os.name != "nt" else "cls")
        print(_colour("Live Connection Monitor  (Ctrl+C to exit)", _BOLD))
        print(f"Connections: {len(connections)}")
        print()

        hdr = f"{'Proto':<6} {'Local Address':<22} {'Remote Address':<22} {'State':<14} {'PID':>6} {'Process'}"
        print(_colour(hdr, _BOLD))
        print("-" * 90)

        for conn in connections:
            proto = conn.get("protocol", "").upper()
            local = f"{conn.get('local_addr', conn.get('local_address', ''))}:{conn.get('local_port', '')}"
            remote = f"{conn.get('remote_addr', conn.get('remote_address', '*'))}:{conn.get('remote_port', '*')}"
            state = conn.get("state", "UNKNOWN")
            pid = conn.get("pid", 0)
            pname = conn.get("process_name", "")

            colour = state_colours.get(state.upper(), _RESET)
            print(
                f"{proto:<6} {local:<22} {remote:<22} "
                f"{_colour(state, colour):<14} {pid:>6} {pname}"
            )

        try:
            time.sleep(2)
        except KeyboardInterrupt:
            break

    print("\nMonitor stopped.")


def cmd_profile(args: argparse.Namespace) -> None:
    """View or change the active network profile."""
    from backend import NftManager, ProfileManager  # noqa: E402
    profiles = ProfileManager()

    if args.set:
        valid = ("public", "private", "domain")
        name = args.set.lower()
        if name not in valid:
            print(_colour(f"Invalid profile '{name}'. Choose: {', '.join(valid)}", _RED))
            sys.exit(1)
        profiles.set_active_profile(name)
        # Load rules from the store and apply with the new profile
        # filter so the profile change actually takes effect.
        from backend import RuleStore as _RS  # noqa: E402
        nft = NftManager()
        with _RS() as _store:
            nft.load_rules(_store.list_rules())
        nft.apply_rules(profile=name)
        print(f"Active profile set to {_colour(name.capitalize(), _CYAN)}.")
    else:
        current = profiles.get_active_profile_name()
        print(f"Active profile: {_colour(current.capitalize(), _CYAN)}")


def cmd_import(args: argparse.Namespace) -> None:
    """Import rules from a JSON file."""
    from backend import NftManager, RuleStore  # noqa: E402
    path = Path(args.file)
    if not path.exists():
        print(_colour(f"File not found: {path}", _RED))
        sys.exit(1)

    store = RuleStore()
    store.import_rules(str(path))
    # Ensure the freshly-imported rules actually reach nftables.
    nft = NftManager()
    nft.load_rules(store.list_rules())
    nft.apply_rules()
    print(f"Rules imported from {_colour(str(path), _CYAN)}.")


def cmd_export(args: argparse.Namespace) -> None:
    """Export rules to a JSON file."""
    from backend import RuleStore  # noqa: E402
    path = Path(args.file)
    store = RuleStore()
    store.export_rules(str(path))
    print(f"Rules exported to {_colour(str(path), _CYAN)}.")


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Construct the argparse parser with all sub-commands."""
    parser = argparse.ArgumentParser(
        prog="winfw",
        description="PE-Compat Windows-Style Firewall Management Tool",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose (debug) logging",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # --- status ---
    sub.add_parser("status", help="Show firewall status and active profile")

    # --- enable / disable ---
    sub.add_parser("enable", help="Enable the firewall")
    sub.add_parser("disable", help="Disable the firewall")

    # --- add ---
    add_p = sub.add_parser("add", help="Add a new firewall rule")
    add_p.add_argument("--name", required=True, help="Rule name")
    add_p.add_argument(
        "--direction", required=True, choices=["in", "out"],
        help="Rule direction (in=inbound, out=outbound)",
    )
    add_p.add_argument(
        "--action", required=True, choices=["allow", "block"],
        help="Rule action",
    )
    add_p.add_argument(
        "--protocol", required=True, choices=["tcp", "udp", "icmp", "any"],
        help="Network protocol",
    )
    add_p.add_argument("--port", type=int, default=None, help="Port number")
    add_p.add_argument("--address", default=None, help="Remote address/CIDR")
    add_p.add_argument("--app", default=None, help="Application path")

    # --- remove ---
    rm_p = sub.add_parser("remove", help="Remove a firewall rule")
    rm_p.add_argument("--name", default=None, help="Rule name")
    rm_p.add_argument("--id", type=str, default=None, help="Rule ID")

    # --- list ---
    ls_p = sub.add_parser("list", help="List firewall rules")
    ls_p.add_argument(
        "--direction", choices=["in", "out"], default=None,
        help="Filter by direction",
    )
    ls_p.add_argument("--profile", default=None, help="Filter by profile name")

    # --- monitor ---
    sub.add_parser("monitor", help="Live connection monitor (terminal UI)")

    # --- profile ---
    prof_p = sub.add_parser("profile", help="View or set the active network profile")
    prof_p.add_argument(
        "--set", metavar="NAME",
        help="Set profile to public, private, or domain",
    )

    # --- import ---
    imp_p = sub.add_parser("import", help="Import rules from a JSON file")
    imp_p.add_argument("file", help="Path to JSON file")

    # --- export ---
    exp_p = sub.add_parser("export", help="Export rules to a JSON file")
    exp_p.add_argument("file", help="Path to output JSON file")

    return parser


# ---------------------------------------------------------------------------
# Direction normalization helper
# ---------------------------------------------------------------------------

_DIRECTION_MAP = {"in": "inbound", "out": "outbound"}


def _normalize_direction(args: argparse.Namespace) -> None:
    """Translate 'in'/'out' shorthand to full direction names."""
    if hasattr(args, "direction") and args.direction in _DIRECTION_MAP:
        args.direction = _DIRECTION_MAP[args.direction]


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

_COMMAND_MAP: dict[str, Any] = {
    "status": cmd_status,
    "enable": cmd_enable,
    "disable": cmd_disable,
    "add": cmd_add,
    "remove": cmd_remove,
    "list": cmd_list,
    "monitor": cmd_monitor,
    "profile": cmd_profile,
    "import": cmd_import,
    "export": cmd_export,
}


def main() -> None:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    _normalize_direction(args)

    handler = _COMMAND_MAP.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)

    try:
        handler(args)
    except PermissionError:
        print(_colour("Error: This command requires root privileges. Try: sudo winfw ...", _RED))
        sys.exit(1)
    except Exception as exc:
        logger.debug("Unhandled exception", exc_info=True)
        print(_colour(f"Error: {exc}", _RED))
        sys.exit(1)


if __name__ == "__main__":
    main()
