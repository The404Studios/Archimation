#!/usr/bin/env python3
"""
PE-Compat Firewall GUI - Block Notification Manager

Desktop notifications for blocked connections, with rate limiting
and the option to create an allow rule directly from a notification.
"""

from __future__ import annotations

import itertools
import logging
import subprocess
import time
from collections import deque
from typing import Any, Dict, List, Optional, Tuple, Union

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Gio", "2.0")
gi.require_version("GLib", "2.0")

from gi.repository import Gtk, Gio, GLib  # noqa: E402

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

logger = logging.getLogger("pe-compat.firewall.gui.notifications")

# Defaults (can be overridden from config)
DEFAULT_RATE_LIMIT_SECONDS = 5
DEFAULT_MAX_PER_MINUTE = 12


class NotificationManager:
    """Manages desktop notifications for blocked firewall events.

    Supports two notification backends:
    1. Gio.Notification via the GTK Application (preferred)
    2. Fallback to ``notify-send`` subprocess if no Application is available

    Implements rate limiting to avoid spamming the user's desktop.
    """

    def __init__(
        self,
        *,
        app: Optional[Gtk.Application] = None,
        rate_limit_seconds: float = DEFAULT_RATE_LIMIT_SECONDS,
        max_per_minute: int = DEFAULT_MAX_PER_MINUTE,
    ) -> None:
        self._app = app
        self._rate_limit_seconds = rate_limit_seconds
        self._max_per_minute = max_per_minute

        # Sliding window of recent notification timestamps
        self._history: deque[float] = deque()
        self._last_sent: float = 0.0

        # Pending "allow from notification" callback registry.
        # Each entry is (rule_data, created_at) so stale pending allows can
        # be expired even if the user dismisses the notification without
        # clicking -- otherwise this dict grows without bound.
        self._pending_allows: Dict[str, Tuple[Dict[str, Any], float]] = {}
        self._pending_allow_ttl: float = 600.0  # 10 minutes
        self._pending_allow_counter = itertools.count()

        # Register the "allow" action on the application if available
        if self._app is not None:
            allow_action = Gio.SimpleAction.new(
                "firewall-allow", GLib.VariantType.new("s")
            )
            allow_action.connect("activate", self._on_allow_action)
            self._app.add_action(allow_action)

    # -- Rate limiting -----------------------------------------------------

    def _should_suppress(self) -> bool:
        """Return True if we should suppress this notification."""
        now = time.monotonic()

        # Per-event minimum interval
        if now - self._last_sent < self._rate_limit_seconds:
            return True

        # Sliding window per-minute cap
        if self._max_per_minute > 0:
            cutoff = now - 60.0
            while self._history and self._history[0] < cutoff:
                self._history.popleft()
            if len(self._history) >= self._max_per_minute:
                return True

        return False

    def _record_sent(self) -> None:
        now = time.monotonic()
        self._last_sent = now
        # Opportunistically evict entries older than 60 s so the deque
        # doesn't grow unboundedly when the rate limiter is disabled
        # (max_per_minute <= 0) or when notifications come faster than
        # the suppressor checks.  Bounded at max_per_minute + 1 entries.
        cutoff = now - 60.0
        hist = self._history
        while hist and hist[0] < cutoff:
            hist.popleft()
        hist.append(now)

    # -- Public API --------------------------------------------------------

    def notify_blocked(
        self,
        *,
        direction: str,
        protocol: str,
        remote_address: str,
        remote_port: Union[int, str],
        local_port: Optional[Union[int, str]] = None,
        process_name: Optional[str] = None,
        rule_data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Send a desktop notification about a blocked connection.

        Parameters
        ----------
        direction:
            "inbound" or "outbound".
        protocol:
            Protocol string, e.g. "TCP".
        remote_address:
            Remote IP address.
        remote_port:
            Remote port number.
        local_port:
            Local port (optional).
        process_name:
            Name of the process that triggered the block (optional).
        rule_data:
            If provided, the notification will include an "Allow" action
            that, when activated, adds this dict as a new allow rule.
        """
        if self._should_suppress():
            logger.debug("Notification suppressed by rate limit")
            return

        title = f"Firewall: {direction.capitalize()} Connection Blocked"

        body_parts: List[str] = [
            f"Protocol: {protocol.upper()}",
            f"Remote: {remote_address}:{remote_port}",
        ]
        if local_port is not None:
            body_parts.append(f"Local Port: {local_port}")
        if process_name:
            body_parts.append(f"Process: {process_name}")

        body = "\n".join(body_parts)

        # Unique key for the allow action.  Use a monotonically incrementing
        # counter rather than time.monotonic() to guarantee uniqueness even
        # when notifications fire faster than the clock resolution.
        allow_key: Optional[str] = None
        if rule_data is not None:
            self._purge_expired_allows()
            seq = next(self._pending_allow_counter)
            allow_key = f"{protocol}-{remote_address}-{remote_port}-{seq}"
            self._pending_allows[allow_key] = (rule_data, time.monotonic())

        # Try Gio.Notification first, fall back to notify-send
        if self._app is not None:
            self._send_gio_notification(title, body, allow_key)
        else:
            self._send_notify_send(title, body)

        self._record_sent()
        logger.info(
            "Notification sent: %s %s %s:%s",
            direction, protocol, remote_address, remote_port,
        )

    # -- Notification backends ---------------------------------------------

    def _send_gio_notification(
        self, title: str, body: str, allow_key: Optional[str]
    ) -> None:
        """Send via GLib.Notification through the GTK Application."""
        notification = Gio.Notification.new(title)
        notification.set_body(body)
        notification.set_priority(Gio.NotificationPriority.HIGH)
        notification.set_icon(
            Gio.ThemedIcon.new("security-medium-symbolic")
        )

        if allow_key is not None:
            notification.add_button_with_target(
                "Allow",
                "app.firewall-allow",
                GLib.Variant.new_string(allow_key),
            )

        # Use a unique id so each notification is independent
        notif_id = f"firewall-block-{time.monotonic()}"
        self._app.send_notification(notif_id, notification)

    @staticmethod
    def _send_notify_send(title: str, body: str) -> None:
        """Fallback: send via notify-send subprocess."""
        try:
            # subprocess.run() waits for completion so the child is reaped
            # inline; the previous fire-and-forget Popen leaked a zombie
            # per notification (the GUI has no SIGCHLD=SIG_IGN handler, so
            # <defunct> entries accumulate).  notify-send exits in <50ms,
            # so blocking the caller briefly is acceptable -- and in any
            # case it was already being invoked from a handler that can
            # tolerate it.  Capped at 2s in case the notification daemon
            # is wedged.
            subprocess.run(
                [
                    "notify-send",
                    "--urgency=normal",
                    "--icon=security-medium",
                    "--app-name=PE-Compat Firewall",
                    title,
                    body,
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2.0,
                check=False,
            )
        except FileNotFoundError:
            logger.warning("notify-send not found; desktop notification skipped")
        except subprocess.TimeoutExpired:
            logger.warning("notify-send timed out; notification may not have appeared")
        except Exception as exc:
            logger.error("notify-send failed: %s", exc)

    # -- Allow action handler ----------------------------------------------

    _MAX_PENDING_ALLOWS: int = 128

    def _purge_expired_allows(self) -> None:
        """Drop pending allow entries older than the configured TTL.

        Without this, entries registered by notifications the user never
        interacts with leak forever.  Also enforces a hard cap
        (``_MAX_PENDING_ALLOWS``) so a pathological burst of blocks
        can't pin arbitrary amounts of memory even within the TTL
        window.
        """
        if not self._pending_allows:
            return
        cutoff = time.monotonic() - self._pending_allow_ttl
        expired = [
            k for k, (_, created) in self._pending_allows.items()
            if created < cutoff
        ]
        for k in expired:
            self._pending_allows.pop(k, None)
        # Hard cap: if we still have too many, drop the oldest.  dict
        # preserves insertion order in Python 3.7+, so iterating keys
        # gives us age order.
        overflow = len(self._pending_allows) - self._MAX_PENDING_ALLOWS
        if overflow > 0:
            for key in list(self._pending_allows.keys())[:overflow]:
                self._pending_allows.pop(key, None)

    def _on_allow_action(
        self, _action: Gio.SimpleAction, param: GLib.Variant
    ) -> None:
        """Handle the 'Allow' button pressed in a notification."""
        allow_key = param.get_string()
        entry = self._pending_allows.pop(allow_key, None)
        if entry is None:
            logger.warning("Allow action key not found: %s", allow_key)
            return
        rule_data, _created = entry

        # Convert the blocked-connection info into an allow rule and persist it
        try:
            from backend import RuleStore, NftManager  # noqa: E402  (lazy import)

            rule_data["action"] = "allow"
            if "name" not in rule_data or not rule_data["name"]:
                proto = rule_data.get("protocol", "any")
                port = rule_data.get("remote_port") or rule_data.get("local_port", "?")
                rule_data["name"] = f"Allow {proto.upper()} port {port} (from notification)"
            rule_data["enabled"] = True

            from backend.nft_manager import FirewallRule  # noqa: E402
            # Use context manager so the SQLite connection is always closed.
            with RuleStore() as store:
                fw_rule = FirewallRule.from_dict(rule_data)
                store.add_rule(fw_rule)
                # Re-sync NftManager from the store.  A fresh NftManager
                # has an empty in-memory rule set, so calling .reload()
                # here would flush all rules -- we must load_rules() first
                # or we'd destroy the user's ruleset with a click of
                # "Allow" on a notification.
                nft = NftManager()
                nft.load_rules(store.list_rules())
                nft.apply_rules()
            logger.info("Allow rule created from notification: %s", rule_data["name"])
        except Exception as exc:
            logger.error("Failed to create allow rule from notification: %s", exc)

    # -- Configuration update ----------------------------------------------

    def update_config(
        self,
        *,
        rate_limit_seconds: Optional[float] = None,
        max_per_minute: Optional[int] = None,
    ) -> None:
        """Hot-update rate limiting parameters."""
        if rate_limit_seconds is not None:
            self._rate_limit_seconds = rate_limit_seconds
        if max_per_minute is not None:
            self._max_per_minute = max_per_minute
        logger.info(
            "Notification config updated: rate_limit=%.1fs, max/min=%d",
            self._rate_limit_seconds,
            self._max_per_minute,
        )
