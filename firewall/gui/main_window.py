#!/usr/bin/env python3
"""
PE-Compat Firewall GUI - Main Window

GTK4/Adwaita application window mimicking the Windows Defender Firewall
with Advanced Security interface. Provides navigation between rule panels,
connection monitoring, and firewall configuration.
"""

from __future__ import annotations

import sys
import logging
from pathlib import Path
from typing import Optional

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
gi.require_version("Gio", "2.0")
gi.require_version("GLib", "2.0")

from gi.repository import Gtk, Adw, Gio, GLib  # noqa: E402

# Backend imports - these live alongside us in the firewall package
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from backend import NftManager, RuleStore, ConnectionMonitor, ProfileManager  # noqa: E402
from gui.inbound_rules import InboundRulesPanel  # noqa: E402
from gui.outbound_rules import OutboundRulesPanel  # noqa: E402
from gui.monitoring import MonitoringPanel  # noqa: E402
from gui.notifications import NotificationManager  # noqa: E402

logger = logging.getLogger("pe-compat.firewall.gui")

APP_ID = "com.pe_compat.firewall"
APP_TITLE = "Windows Defender Firewall with Advanced Security"


# ---------------------------------------------------------------------------
# Overview page (landing / dashboard)
# ---------------------------------------------------------------------------

class OverviewPage(Gtk.Box):
    """Dashboard page showing firewall status, active profile, and quick stats."""

    def __init__(self, nft: NftManager, store: RuleStore, profiles: ProfileManager) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.set_margin_top(16)
        self.set_margin_bottom(16)
        self.set_margin_start(16)
        self.set_margin_end(16)

        self._nft = nft
        self._store = store
        self._profiles = profiles

        # --- Header ---
        header = Gtk.Label(label=APP_TITLE)
        header.add_css_class("title-1")
        header.set_halign(Gtk.Align.START)
        self.append(header)

        self.append(Gtk.Separator())

        # --- Firewall status row ---
        status_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        status_box.set_margin_top(8)

        status_label = Gtk.Label(label="Firewall Status:")
        status_label.add_css_class("heading")
        status_box.append(status_label)

        self._status_icon = Gtk.Image()
        status_box.append(self._status_icon)

        self._status_text = Gtk.Label()
        self._status_text.add_css_class("heading")
        status_box.append(self._status_text)

        spacer = Gtk.Box()
        spacer.set_hexpand(True)
        status_box.append(spacer)

        self._toggle_btn = Gtk.Switch()
        self._toggle_btn.set_valign(Gtk.Align.CENTER)
        self._toggle_btn.connect("state-set", self._on_toggle_firewall)
        status_box.append(self._toggle_btn)

        self.append(status_box)

        # --- Active profile ---
        profile_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        profile_box.set_margin_top(4)
        profile_label = Gtk.Label(label="Active Profile:")
        profile_label.add_css_class("dim-label")
        profile_box.append(profile_label)

        self._profile_label = Gtk.Label()
        profile_box.append(self._profile_label)
        self.append(profile_box)

        self.append(Gtk.Separator())

        # --- Quick stats grid ---
        stats_header = Gtk.Label(label="Quick Statistics")
        stats_header.add_css_class("title-3")
        stats_header.set_halign(Gtk.Align.START)
        stats_header.set_margin_top(12)
        self.append(stats_header)

        stats_grid = Gtk.Grid()
        stats_grid.set_row_spacing(8)
        stats_grid.set_column_spacing(24)
        stats_grid.set_margin_top(8)

        self._stat_labels: dict[str, Gtk.Label] = {}
        stat_items = [
            ("inbound_rules", "Inbound Rules"),
            ("outbound_rules", "Outbound Rules"),
            ("active_connections", "Active Connections"),
            ("blocked_today", "Blocked Connections (Today)"),
        ]

        for row, (key, text) in enumerate(stat_items):
            name_label = Gtk.Label(label=f"{text}:")
            name_label.set_halign(Gtk.Align.START)
            name_label.add_css_class("dim-label")
            stats_grid.attach(name_label, 0, row, 1, 1)

            value_label = Gtk.Label(label="--")
            value_label.set_halign(Gtk.Align.START)
            value_label.add_css_class("heading")
            stats_grid.attach(value_label, 1, row, 1, 1)
            self._stat_labels[key] = value_label

        self.append(stats_grid)

        # --- Profiles overview ---
        self.append(Gtk.Separator())
        profiles_header = Gtk.Label(label="Network Profiles")
        profiles_header.add_css_class("title-3")
        profiles_header.set_halign(Gtk.Align.START)
        profiles_header.set_margin_top(12)
        self.append(profiles_header)

        self._profiles_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
        self._profiles_box.set_margin_top(8)

        for profile_name in ("Domain", "Private", "Public"):
            card = self._build_profile_card(profile_name)
            self._profiles_box.append(card)

        self.append(self._profiles_box)

        # Populate initial data
        self.refresh()

    def _build_profile_card(self, name: str) -> Gtk.Frame:
        """Build a small card summarising a network profile."""
        frame = Gtk.Frame()
        frame.add_css_class("card")

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        box.set_margin_top(12)
        box.set_margin_bottom(12)
        box.set_margin_start(16)
        box.set_margin_end(16)

        title = Gtk.Label(label=f"{name} Profile")
        title.add_css_class("heading")
        box.append(title)

        try:
            current = self._profiles.get_active_profile_name()
            is_active = name.lower() == current.lower()
        except Exception:
            is_active = name.lower() == "private"
        status = Gtk.Label(label="Active" if is_active else "Inactive")
        status.add_css_class("dim-label")
        box.append(status)

        frame.set_child(box)
        return frame

    # -- Actions / Refresh -------------------------------------------------

    def _on_toggle_firewall(self, switch: Gtk.Switch, state: bool) -> bool:
        """Enable or disable the firewall."""
        try:
            if state:
                self._nft.enable()
                logger.info("Firewall enabled via GUI toggle")
            else:
                self._nft.disable()
                logger.info("Firewall disabled via GUI toggle")
        except Exception as exc:
            logger.error("Failed to toggle firewall: %s", exc)
            dialog = Gtk.AlertDialog()
            dialog.set_message(f"Error toggling firewall: {exc}")
            dialog.show(self.get_root())
            return True  # prevent toggle
        self.refresh()
        return False

    def refresh(self) -> None:
        """Reload all dashboard data from backends."""
        try:
            enabled = self._nft.is_enabled()
        except Exception:
            enabled = False

        self._toggle_btn.set_active(enabled)
        if enabled:
            self._status_icon.set_from_icon_name("security-high-symbolic")
            self._status_text.set_text("ON (Active)")
        else:
            self._status_icon.set_from_icon_name("security-low-symbolic")
            self._status_text.set_text("OFF (Inactive)")

        try:
            profile_name = self._profiles.get_active_profile_name()
        except Exception:
            profile_name = "private"
        self._profile_label.set_text(profile_name.capitalize())

        try:
            inbound = self._store.count_rules(direction="inbound")
            outbound = self._store.count_rules(direction="outbound")
        except Exception:
            inbound = outbound = 0

        self._stat_labels["inbound_rules"].set_text(str(inbound))
        self._stat_labels["outbound_rules"].set_text(str(outbound))

        try:
            active = self._nft.active_connection_count()
        except Exception:
            active = 0
        self._stat_labels["active_connections"].set_text(str(active))

        try:
            blocked = self._store.blocked_count_today()
        except Exception:
            blocked = 0
        self._stat_labels["blocked_today"].set_text(str(blocked))


# ---------------------------------------------------------------------------
# Settings page
# ---------------------------------------------------------------------------

class SettingsPage(Gtk.Box):
    """Configuration page for firewall settings."""

    def __init__(self, profiles: ProfileManager, nft: Optional[NftManager] = None, store: Optional[RuleStore] = None) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.set_margin_top(16)
        self.set_margin_bottom(16)
        self.set_margin_start(16)
        self.set_margin_end(16)

        self._profiles = profiles
        self._nft = nft
        self._store = store

        header = Gtk.Label(label="Firewall Settings")
        header.add_css_class("title-1")
        header.set_halign(Gtk.Align.START)
        self.append(header)
        self.append(Gtk.Separator())

        # --- Profile selector ---
        profile_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        profile_row.set_margin_top(8)
        profile_row.append(Gtk.Label(label="Active Network Profile:"))

        self._profile_dropdown = Gtk.DropDown.new_from_strings(["Public", "Private", "Domain"])
        self._profile_dropdown.connect("notify::selected", self._on_profile_changed)
        profile_row.append(self._profile_dropdown)
        self.append(profile_row)

        # --- Logging toggle ---
        log_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        log_row.set_margin_top(8)
        log_row.append(Gtk.Label(label="Log Blocked Connections:"))
        self._log_switch = Gtk.Switch()
        self._log_switch.set_active(True)
        log_row.append(self._log_switch)
        self.append(log_row)

        # --- Notification toggle ---
        notify_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        notify_row.set_margin_top(8)
        notify_row.append(Gtk.Label(label="Show Block Notifications:"))
        self._notify_switch = Gtk.Switch()
        self._notify_switch.set_active(True)
        notify_row.append(self._notify_switch)
        self.append(notify_row)

        # --- Default inbound action ---
        in_action_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        in_action_row.set_margin_top(8)
        in_action_row.append(Gtk.Label(label="Default Inbound Action:"))
        self._inbound_action = Gtk.DropDown.new_from_strings(["Block", "Allow"])
        in_action_row.append(self._inbound_action)
        self.append(in_action_row)

        # --- Default outbound action ---
        out_action_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        out_action_row.set_margin_top(8)
        out_action_row.append(Gtk.Label(label="Default Outbound Action:"))
        self._outbound_action = Gtk.DropDown.new_from_strings(["Allow", "Block"])
        out_action_row.append(self._outbound_action)
        self.append(out_action_row)

        self.append(Gtk.Separator())

        # --- Apply / Reset buttons ---
        btn_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        btn_row.set_margin_top(12)
        btn_row.set_halign(Gtk.Align.END)

        reset_btn = Gtk.Button(label="Reset Defaults")
        reset_btn.connect("clicked", self._on_reset)
        btn_row.append(reset_btn)

        apply_btn = Gtk.Button(label="Apply")
        apply_btn.add_css_class("suggested-action")
        apply_btn.connect("clicked", self._on_apply)
        btn_row.append(apply_btn)

        self.append(btn_row)

    def _on_profile_changed(self, dropdown: Gtk.DropDown, _pspec: object) -> None:
        """Handle profile dropdown change."""
        pass  # Applied on "Apply" click

    def _on_apply(self, _btn: Gtk.Button) -> None:
        """Persist current settings and reload firewall rules."""
        profiles = ["public", "private", "domain"]
        selected = profiles[self._profile_dropdown.get_selected()]
        try:
            self._profiles.set_active_profile(selected)
            if self._nft:
                # Reload rules from the store into the NftManager before applying
                if self._store:
                    rules = self._store.list_rules()
                    self._nft.load_rules(rules)
                self._nft.apply_rules(profile=selected)
            logger.info("Settings applied: profile=%s, rules reloaded", selected)
        except Exception as exc:
            logger.error("Failed to apply settings: %s", exc)

    def _on_reset(self, _btn: Gtk.Button) -> None:
        """Restore factory defaults."""
        self._profile_dropdown.set_selected(1)  # Private
        self._log_switch.set_active(True)
        self._notify_switch.set_active(True)
        self._inbound_action.set_selected(0)  # Block
        self._outbound_action.set_selected(0)  # Allow


# ---------------------------------------------------------------------------
# Main application window
# ---------------------------------------------------------------------------

class MainWindow(Gtk.ApplicationWindow):
    """Primary firewall management window with sidebar navigation."""

    NAV_ITEMS: list[tuple[str, str, str]] = [
        ("overview", "Overview", "computer-symbolic"),
        ("inbound", "Inbound Rules", "go-previous-symbolic"),
        ("outbound", "Outbound Rules", "go-next-symbolic"),
        ("monitor", "Connection Monitor", "network-wired-symbolic"),
        ("settings", "Settings", "emblem-system-symbolic"),
    ]

    def __init__(self, app: Gtk.Application) -> None:
        super().__init__(application=app, title=APP_TITLE)
        self.set_default_size(1000, 700)

        # --- Backend handles ---
        self._nft = NftManager()
        self._store = RuleStore()
        self._profiles = ProfileManager()
        self._monitor = ConnectionMonitor()
        self._monitor.start()
        self._notifier = NotificationManager(app=app)

        # --- Header bar with toolbar buttons ---
        header_bar = Gtk.HeaderBar()

        enable_btn = Gtk.Button(label="Enable")
        enable_btn.set_tooltip_text("Enable Firewall")
        enable_btn.connect("clicked", self._on_enable)
        header_bar.pack_start(enable_btn)

        disable_btn = Gtk.Button(label="Disable")
        disable_btn.set_tooltip_text("Disable Firewall")
        disable_btn.connect("clicked", self._on_disable)
        header_bar.pack_start(disable_btn)

        refresh_btn = Gtk.Button.new_from_icon_name("view-refresh-symbolic")
        refresh_btn.set_tooltip_text("Refresh")
        refresh_btn.connect("clicked", self._on_refresh)
        header_bar.pack_end(refresh_btn)

        # Import / export menu
        ie_menu = Gio.Menu()
        ie_menu.append("Import Rules...", "win.import-rules")
        ie_menu.append("Export Rules...", "win.export-rules")

        ie_btn = Gtk.MenuButton()
        ie_btn.set_icon_name("document-save-symbolic")
        ie_btn.set_tooltip_text("Import / Export")
        ie_btn.set_menu_model(ie_menu)
        header_bar.pack_end(ie_btn)

        self.set_titlebar(header_bar)

        # Register actions for import/export
        import_action = Gio.SimpleAction.new("import-rules", None)
        import_action.connect("activate", self._on_import_rules)
        self.add_action(import_action)

        export_action = Gio.SimpleAction.new("export-rules", None)
        export_action.connect("activate", self._on_export_rules)
        self.add_action(export_action)

        # --- Main layout: sidebar + content ---
        paned = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
        paned.set_position(200)
        paned.set_shrink_start_child(False)

        # Sidebar navigation
        sidebar = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        sidebar.set_size_request(200, -1)
        sidebar.add_css_class("sidebar")

        sidebar_header = Gtk.Label(label="Navigation")
        sidebar_header.add_css_class("title-4")
        sidebar_header.set_margin_top(12)
        sidebar_header.set_margin_bottom(8)
        sidebar.append(sidebar_header)
        sidebar.append(Gtk.Separator())

        self._nav_list = Gtk.ListBox()
        self._nav_list.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self._nav_list.add_css_class("navigation-sidebar")

        for _key, label, icon_name in self.NAV_ITEMS:
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            row.set_margin_top(6)
            row.set_margin_bottom(6)
            row.set_margin_start(12)
            row.set_margin_end(12)
            icon = Gtk.Image.new_from_icon_name(icon_name)
            row.append(icon)
            row.append(Gtk.Label(label=label))
            self._nav_list.append(row)

        self._nav_list.connect("row-selected", self._on_nav_selected)
        sidebar.append(self._nav_list)

        paned.set_start_child(sidebar)

        # Content stack (one page per nav item)
        self._stack = Gtk.Stack()
        self._stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        self._stack.set_transition_duration(150)

        self._overview = OverviewPage(self._nft, self._store, self._profiles)
        self._stack.add_named(self._overview, "overview")

        self._inbound_panel = InboundRulesPanel(self._store, self._nft)
        self._stack.add_named(self._inbound_panel, "inbound")

        self._outbound_panel = OutboundRulesPanel(self._store, self._nft)
        self._stack.add_named(self._outbound_panel, "outbound")

        self._monitor_panel = MonitoringPanel(self._monitor)
        self._stack.add_named(self._monitor_panel, "monitor")

        self._settings_page = SettingsPage(self._profiles, nft=self._nft, store=self._store)
        self._stack.add_named(self._settings_page, "settings")

        paned.set_end_child(self._stack)
        self.set_child(paned)

        # --- Status bar ---
        # We overlay a status bar at the bottom using a Box wrapping paned
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        outer.append(paned)

        self._statusbar = Gtk.Label()
        self._statusbar.set_halign(Gtk.Align.START)
        self._statusbar.set_margin_start(8)
        self._statusbar.set_margin_top(4)
        self._statusbar.set_margin_bottom(4)
        self._statusbar.add_css_class("dim-label")
        outer.append(Gtk.Separator())
        outer.append(self._statusbar)

        self.set_child(outer)

        # Select first nav item
        first_row = self._nav_list.get_row_at_index(0)
        if first_row:
            self._nav_list.select_row(first_row)

        # Periodically update status bar
        self._statusbar_timer_id = GLib.timeout_add_seconds(3, self._update_statusbar)
        self._update_statusbar()

        # Stop the background connection monitor thread and close the DB
        # when the window closes, so we don't leak a polling thread if the
        # app is left running in the background.
        self.connect("close-request", self._on_close_request)

    # -- Navigation --------------------------------------------------------

    def _on_nav_selected(self, listbox: Gtk.ListBox, row: Optional[Gtk.ListBoxRow]) -> None:
        """Switch the content stack based on sidebar selection."""
        if row is None:
            return
        index = row.get_index()
        page_name = self.NAV_ITEMS[index][0]
        self._stack.set_visible_child_name(page_name)
        logger.debug("Navigated to %s", page_name)

    # -- Toolbar actions ---------------------------------------------------

    def _on_enable(self, _btn: Gtk.Button) -> None:
        try:
            # Load rules from the persistent store before enabling
            rules = self._store.list_rules()
            self._nft.load_rules(rules)
            self._nft.enable()
            logger.info("Firewall enabled")
        except Exception as exc:
            logger.error("Failed to enable firewall: %s", exc)
        self._overview.refresh()
        self._update_statusbar()

    def _on_disable(self, _btn: Gtk.Button) -> None:
        try:
            self._nft.disable()
            logger.info("Firewall disabled")
        except Exception as exc:
            logger.error("Failed to disable firewall: %s", exc)
        self._overview.refresh()
        self._update_statusbar()

    def _on_refresh(self, _btn: Gtk.Button) -> None:
        """Refresh all panels."""
        self._overview.refresh()
        self._inbound_panel.refresh()
        self._outbound_panel.refresh()
        self._monitor_panel.refresh()
        self._update_statusbar()
        logger.info("All panels refreshed")

    def _on_import_rules(self, _action: Gio.SimpleAction, _param: object) -> None:
        """Show file chooser to import rules from JSON."""
        dialog = Gtk.FileDialog()
        dialog.set_title("Import Firewall Rules")

        json_filter = Gtk.FileFilter()
        json_filter.set_name("JSON Files")
        json_filter.add_pattern("*.json")
        filters = Gio.ListStore.new(Gtk.FileFilter)
        filters.append(json_filter)
        dialog.set_filters(filters)

        dialog.open(self, None, self._import_rules_cb)

    def _import_rules_cb(self, dialog: Gtk.FileDialog, result: Gio.AsyncResult) -> None:
        try:
            gfile = dialog.open_finish(result)
            if gfile:
                path = gfile.get_path()
                self._store.import_rules(path)
                # Pull freshly-imported rules into the NftManager before
                # applying so the rule set compiled into nft matches what
                # the user just imported.
                self._nft.load_rules(self._store.list_rules())
                self._nft.apply_rules()
                self._on_refresh(None)
                logger.info("Rules imported from %s", path)
        except Exception as exc:
            logger.error("Import failed: %s", exc)

    def _on_export_rules(self, _action: Gio.SimpleAction, _param: object) -> None:
        """Show file chooser to export rules to JSON."""
        dialog = Gtk.FileDialog()
        dialog.set_title("Export Firewall Rules")
        dialog.save(self, None, self._export_rules_cb)

    def _export_rules_cb(self, dialog: Gtk.FileDialog, result: Gio.AsyncResult) -> None:
        try:
            gfile = dialog.save_finish(result)
            if gfile:
                path = gfile.get_path()
                self._store.export_rules(path)
                logger.info("Rules exported to %s", path)
        except Exception as exc:
            logger.error("Export failed: %s", exc)

    # -- Status bar --------------------------------------------------------

    def _on_close_request(self, _win: Gtk.ApplicationWindow) -> bool:
        """Clean up background resources when the window closes."""
        try:
            if getattr(self, "_statusbar_timer_id", 0):
                GLib.source_remove(self._statusbar_timer_id)
                self._statusbar_timer_id = 0
        except Exception:
            pass
        # Stop the monitor panel's own GLib.timeout_add timer before
        # the backend goes away; otherwise the next tick fires and we
        # access a closed ConnectionMonitor / dead filter widgets.
        try:
            stop_timer = getattr(self._monitor_panel, "_stop_timer", None)
            if callable(stop_timer):
                stop_timer()
        except Exception:
            logger.exception("Failed to stop monitor panel timer")
        try:
            self._monitor.stop()
        except Exception:
            logger.exception("Failed to stop connection monitor")
        try:
            self._store.close()
        except Exception:
            logger.exception("Failed to close rule store")
        return False  # allow window to close

    def _update_statusbar(self) -> bool:
        """Refresh the status bar text. Returns True to keep the timer alive."""
        try:
            enabled = self._nft.is_enabled()
            status = "ON" if enabled else "OFF"
            profile = self._profiles.get_active_profile_name().capitalize()
            conns = self._nft.active_connection_count()
            self._statusbar.set_text(
                f"Firewall: {status}  |  Profile: {profile}  |  "
                f"Active Connections: {conns}"
            )
        except Exception:
            self._statusbar.set_text("Firewall: status unavailable")
        return True  # keep GLib timer running


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

class FirewallApp(Adw.Application):
    """GTK Application wrapper for the firewall GUI."""

    def __init__(self) -> None:
        super().__init__(
            application_id=APP_ID,
            flags=Gio.ApplicationFlags.DEFAULT_FLAGS,
        )
        self.connect("activate", self._on_activate)

    def _on_activate(self, app: Gtk.Application) -> None:
        win = MainWindow(app)
        win.present()


def main() -> None:
    """Entry point for the firewall GUI application."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )
    app = FirewallApp()
    app.run(sys.argv)


if __name__ == "__main__":
    main()
