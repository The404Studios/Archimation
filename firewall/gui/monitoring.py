#!/usr/bin/env python3
"""
PE-Compat Firewall GUI - Live Connection Monitor Panel

Real-time view of active network connections with automatic refresh,
protocol/state/process filtering, and color-coded connection states.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Gio", "2.0")
gi.require_version("GLib", "2.0")

from gi.repository import Gtk, Gio, GLib, GObject  # noqa: E402

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from backend import ConnectionMonitor  # noqa: E402

logger = logging.getLogger("pe-compat.firewall.gui.monitor")

# Refresh interval in milliseconds
DEFAULT_REFRESH_MS = 2000

# State colour CSS class mapping
STATE_CSS: dict[str, str] = {
    "ESTABLISHED": "success",   # green
    "LISTEN": "warning",        # yellow
    "LISTENING": "warning",
    "TIME_WAIT": "dim-label",
    "CLOSE_WAIT": "dim-label",
    "SYN_SENT": "accent",
    "SYN_RECV": "accent",
    "BLOCKED": "error",         # red
}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

class ConnectionObject(GObject.Object):
    """GObject wrapper for a single active connection entry."""

    __gtype_name__ = "ConnectionObject"

    def __init__(self, data: dict[str, Any]) -> None:
        super().__init__()
        self.data = data

    @GObject.Property(type=str)
    def protocol(self) -> str:
        return self.data.get("protocol", "").upper()

    @GObject.Property(type=str)
    def local(self) -> str:
        addr = self.data.get("local_addr", self.data.get("local_address", ""))
        port = self.data.get("local_port", "")
        return f"{addr}:{port}" if addr else str(port)

    @GObject.Property(type=str)
    def remote(self) -> str:
        addr = self.data.get("remote_addr", self.data.get("remote_address", ""))
        port = self.data.get("remote_port", "")
        if not addr and not port:
            return "*"
        return f"{addr}:{port}" if addr else str(port)

    @GObject.Property(type=str)
    def state(self) -> str:
        return self.data.get("state", "UNKNOWN")

    @GObject.Property(type=int)
    def pid(self) -> int:
        return self.data.get("pid", 0)

    @GObject.Property(type=str)
    def process_name(self) -> str:
        return self.data.get("process_name", "")


# ---------------------------------------------------------------------------
# Monitoring Panel
# ---------------------------------------------------------------------------

class MonitoringPanel(Gtk.Box):
    """Live-updating table of active network connections."""

    def __init__(self, monitor: ConnectionMonitor) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self._monitor = monitor
        self._timer_id: int = 0
        self._paused: bool = False

        # --- Toolbar / filter bar ---
        toolbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        toolbar.set_margin_top(4)
        toolbar.set_margin_bottom(4)
        toolbar.set_margin_start(8)
        toolbar.set_margin_end(8)

        # Protocol filter
        toolbar.append(Gtk.Label(label="Protocol:"))
        self._proto_filter = Gtk.DropDown.new_from_strings(
            ["All", "TCP", "UDP", "ICMP"]
        )
        self._proto_filter.connect("notify::selected", lambda *_: self.refresh())
        toolbar.append(self._proto_filter)

        # State filter
        toolbar.append(Gtk.Label(label="State:"))
        self._state_filter = Gtk.DropDown.new_from_strings(
            ["All", "ESTABLISHED", "LISTEN", "TIME_WAIT", "CLOSE_WAIT", "BLOCKED"]
        )
        self._state_filter.connect("notify::selected", lambda *_: self.refresh())
        toolbar.append(self._state_filter)

        # Process filter (text entry)
        toolbar.append(Gtk.Label(label="Process:"))
        self._process_filter = Gtk.Entry()
        self._process_filter.set_placeholder_text("Filter by name...")
        self._process_filter.set_width_chars(15)
        self._process_filter.connect("changed", lambda *_: self.refresh())
        toolbar.append(self._process_filter)

        spacer = Gtk.Box()
        spacer.set_hexpand(True)
        toolbar.append(spacer)

        # Pause / Resume button
        self._pause_btn = Gtk.ToggleButton()
        self._pause_btn.set_icon_name("media-playback-pause-symbolic")
        self._pause_btn.set_tooltip_text("Pause auto-refresh")
        self._pause_btn.connect("toggled", self._on_pause_toggled)
        toolbar.append(self._pause_btn)

        # Manual refresh
        refresh_btn = Gtk.Button.new_from_icon_name("view-refresh-symbolic")
        refresh_btn.set_tooltip_text("Refresh now")
        refresh_btn.connect("clicked", lambda _: self.refresh())
        toolbar.append(refresh_btn)

        self.append(toolbar)
        self.append(Gtk.Separator())

        # --- Legend row ---
        legend = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
        legend.set_margin_start(8)
        legend.set_margin_top(2)
        legend.set_margin_bottom(2)

        for text, css in [
            ("Established", "success"),
            ("Listening", "warning"),
            ("Blocked", "error"),
        ]:
            dot = Gtk.Label(label=f"\u25CF {text}")
            dot.add_css_class(css)
            legend.append(dot)

        self.append(legend)
        self.append(Gtk.Separator())

        # --- Connection table (ColumnView) ---
        self._model = Gio.ListStore.new(ConnectionObject)
        self._selection = Gtk.SingleSelection.new(self._model)

        column_view = Gtk.ColumnView.new(self._selection)
        column_view.set_show_row_separators(True)
        column_view.set_show_column_separators(True)
        column_view.add_css_class("data-table")

        columns_spec: list[tuple[str, str, int]] = [
            ("protocol", "Proto", 60),
            ("local", "Local Address", 180),
            ("remote", "Remote Address", 180),
            ("state", "State", 110),
            ("pid", "PID", 65),
            ("process_name", "Process", 150),
        ]

        for prop, title, width in columns_spec:
            factory = Gtk.SignalListItemFactory()
            factory.connect("setup", self._on_factory_setup, prop)
            factory.connect("bind", self._on_factory_bind, prop)
            col = Gtk.ColumnViewColumn.new(title, factory)
            col.set_fixed_width(width)
            col.set_resizable(True)
            column_view.append_column(col)

        scrolled = Gtk.ScrolledWindow()
        scrolled.set_vexpand(True)
        scrolled.set_hexpand(True)
        scrolled.set_child(column_view)
        self.append(scrolled)

        # --- Status label ---
        self._status_label = Gtk.Label()
        self._status_label.set_halign(Gtk.Align.START)
        self._status_label.set_margin_start(8)
        self._status_label.set_margin_top(4)
        self._status_label.set_margin_bottom(4)
        self._status_label.add_css_class("dim-label")
        self.append(Gtk.Separator())
        self.append(self._status_label)

        # Start auto-refresh
        self._start_timer()
        self.refresh()

    # -- Auto-refresh timer ------------------------------------------------

    def _start_timer(self) -> None:
        if self._timer_id:
            GLib.source_remove(self._timer_id)
        self._timer_id = GLib.timeout_add(DEFAULT_REFRESH_MS, self._on_timer)

    def _stop_timer(self) -> None:
        """Remove the auto-refresh GLib source -- call from parent on close."""
        if self._timer_id:
            try:
                GLib.source_remove(self._timer_id)
            except Exception:
                pass
            self._timer_id = 0

    def _on_timer(self) -> bool:
        """Called every refresh interval. Returns True to keep timer alive.

        If the widget has been unparented (window closed before the
        timer tick), suppress the refresh -- accessing the monitor or
        the filter widgets after destruction raises GLib warnings that
        clutter the journal.
        """
        if self._paused:
            return True
        # get_root() returns None once the widget has been removed from
        # its toplevel; that's the clearest "I'm no longer shown" signal
        # Gtk4 gives us without a dedicated destroy handler.
        if self.get_root() is None:
            self._timer_id = 0
            return False
        self.refresh()
        return True

    def _on_pause_toggled(self, btn: Gtk.ToggleButton) -> None:
        was_paused = self._paused
        self._paused = btn.get_active()
        if self._paused:
            btn.set_icon_name("media-playback-start-symbolic")
            btn.set_tooltip_text("Resume auto-refresh")
        else:
            btn.set_icon_name("media-playback-pause-symbolic")
            btn.set_tooltip_text("Pause auto-refresh")
            # On resume, pull fresh data immediately instead of making
            # the user wait up to DEFAULT_REFRESH_MS for the next tick.
            if was_paused:
                self.refresh()

    # -- ColumnView factories ----------------------------------------------

    @staticmethod
    def _on_factory_setup(
        _factory: Gtk.SignalListItemFactory,
        list_item: Gtk.ListItem,
        prop: str,
    ) -> None:
        label = Gtk.Label()
        label.set_halign(Gtk.Align.START)
        label.set_margin_start(4)
        label.set_margin_end(4)
        list_item.set_child(label)

    @staticmethod
    def _on_factory_bind(
        _factory: Gtk.SignalListItemFactory,
        list_item: Gtk.ListItem,
        prop: str,
    ) -> None:
        obj: ConnectionObject = list_item.get_item()
        label: Gtk.Label = list_item.get_child()

        if prop == "protocol":
            label.set_text(obj.protocol)
        elif prop == "local":
            label.set_text(obj.local)
        elif prop == "remote":
            label.set_text(obj.remote)
        elif prop == "state":
            state = obj.state
            label.set_text(state)
            # Only strip the previously-applied state class (stashed on
            # the widget) rather than looping over every possible class
            # on every bind.
            prev = getattr(label, "_fw_state_css", None)
            css_cls = STATE_CSS.get(state.upper())
            if prev and prev != css_cls:
                label.remove_css_class(prev)
            if css_cls and css_cls != prev:
                label.add_css_class(css_cls)
            label._fw_state_css = css_cls
        elif prop == "pid":
            label.set_text(str(obj.pid) if obj.pid else "-")
        elif prop == "process_name":
            label.set_text(obj.process_name or "-")

    # -- Filtering & data load ---------------------------------------------

    def _get_active_filters(self) -> tuple[Optional[str], Optional[str], Optional[str]]:
        """Return (protocol, state, process) filter values, None means 'all'."""
        proto_idx = self._proto_filter.get_selected()
        proto_map = {0: None, 1: "tcp", 2: "udp", 3: "icmp"}
        proto = proto_map.get(proto_idx)

        state_idx = self._state_filter.get_selected()
        state_map = {
            0: None, 1: "ESTABLISHED", 2: "LISTEN",
            3: "TIME_WAIT", 4: "CLOSE_WAIT", 5: "BLOCKED",
        }
        state = state_map.get(state_idx)

        proc_text = self._process_filter.get_text().strip().lower() or None
        return proto, state, proc_text

    def refresh(self) -> None:
        """Reload active connections, applying current filters.

        Instead of ``remove_all()`` + re-append (which destroys and
        re-creates every row widget in GTK), diff against the previously
        displayed set and only touch rows that changed.  On a typical
        system with dozens to hundreds of connections and a 2 s poll
        timer, this removes the bulk of per-tick redraw cost.
        """
        proto_filter, state_filter, proc_filter = self._get_active_filters()

        try:
            connections = self._monitor.get_connections()
        except Exception as exc:
            logger.error("Failed to fetch connections: %s", exc)
            connections = []

        # Build filtered list and keep insertion order
        filtered: list[dict] = []
        for conn in connections:
            if proto_filter and conn.get("protocol", "").lower() != proto_filter:
                continue
            if state_filter and conn.get("state", "").upper() != state_filter:
                continue
            if proc_filter:
                pname = conn.get("process_name", "").lower()
                if proc_filter not in pname:
                    continue
            filtered.append(conn)

        def _key(c: dict) -> tuple:
            return (
                c.get("protocol", ""),
                c.get("local_addr", c.get("local_address", "")),
                c.get("local_port", 0),
                c.get("remote_addr", c.get("remote_address", "")),
                c.get("remote_port", 0),
            )

        n_existing = self._model.get_n_items()

        # Walk filtered list; replace in-place where possible, append new.
        for i, conn in enumerate(filtered):
            k = _key(conn)
            if i < n_existing:
                existing_obj = self._model.get_item(i)
                existing_key = _key(existing_obj.data)
                # Only replace the row object when the identity or the
                # mutable state actually changed -- unchanged rows keep
                # their widget and avoid a bind cycle.
                if (existing_key != k
                        or existing_obj.data.get("state") != conn.get("state")
                        or existing_obj.data.get("pid") != conn.get("pid")
                        or existing_obj.data.get("process_name")
                        != conn.get("process_name")):
                    # splice takes (position, n_removals, additions)
                    self._model.splice(i, 1, [ConnectionObject(conn)])
            else:
                self._model.append(ConnectionObject(conn))

        # Drop trailing rows that are no longer present.
        target_len = len(filtered)
        current_len = self._model.get_n_items()
        if current_len > target_len:
            self._model.splice(target_len, current_len - target_len, [])

        displayed = len(filtered)
        total = len(connections)
        self._status_label.set_text(
            f"Showing {displayed} of {total} connection(s)  |  "
            f"Auto-refresh: {'paused' if self._paused else f'every {DEFAULT_REFRESH_MS // 1000}s'}"
        )
