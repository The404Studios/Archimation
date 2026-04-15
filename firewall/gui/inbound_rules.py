#!/usr/bin/env python3
"""
PE-Compat Firewall GUI - Inbound Rules Panel

Displays, creates, edits, and deletes inbound firewall rules in a
sortable list view with a toolbar, context menu, and add/edit dialogs.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Gio", "2.0")
gi.require_version("GLib", "2.0")
gi.require_version("Gdk", "4.0")

from gi.repository import Gtk, Gio, GLib, GObject, Gdk  # noqa: E402

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from backend import NftManager, RuleStore  # noqa: E402
from backend.nft_manager import FirewallRule  # noqa: E402

logger = logging.getLogger("pe-compat.firewall.gui.inbound")


# ---------------------------------------------------------------------------
# Data model - one row in the rule list
# ---------------------------------------------------------------------------

class RuleObject(GObject.Object):
    """GObject wrapper around a single firewall rule dict for use in ListView."""

    __gtype_name__ = "InboundRuleObject"

    def __init__(self, data: dict[str, Any]) -> None:
        super().__init__()
        self.data = data

    @GObject.Property(type=str)
    def rule_id(self) -> str:
        return str(self.data.get("id", ""))

    @GObject.Property(type=str)
    def name(self) -> str:
        return self.data.get("name", "")

    @GObject.Property(type=str)
    def action(self) -> str:
        return self.data.get("action", "block").capitalize()

    @GObject.Property(type=str)
    def protocol(self) -> str:
        return self.data.get("protocol", "any").upper()

    @GObject.Property(type=str)
    def port(self) -> str:
        p = self.data.get("port")
        return str(p) if p is not None else "Any"

    @GObject.Property(type=bool, default=True)
    def enabled(self) -> bool:
        return self.data.get("enabled", True)


# ---------------------------------------------------------------------------
# Add / Edit Rule Dialog
# ---------------------------------------------------------------------------

class RuleDialog(Gtk.Dialog):
    """Modal dialog to add or edit a firewall rule."""

    def __init__(
        self,
        parent: Gtk.Window,
        *,
        direction: str = "inbound",
        rule_data: Optional[dict[str, Any]] = None,
    ) -> None:
        editing = rule_data is not None
        title = f"{'Edit' if editing else 'New'} {direction.capitalize()} Rule"
        super().__init__(
            title=title,
            transient_for=parent,
            modal=True,
        )
        self.set_default_size(450, 0)
        self.add_button("Cancel", Gtk.ResponseType.CANCEL)
        ok_btn = self.add_button("OK", Gtk.ResponseType.OK)
        ok_btn.add_css_class("suggested-action")

        self._direction = direction
        data = rule_data or {}

        content = self.get_content_area()
        content.set_spacing(8)
        content.set_margin_top(12)
        content.set_margin_bottom(12)
        content.set_margin_start(12)
        content.set_margin_end(12)

        grid = Gtk.Grid()
        grid.set_row_spacing(8)
        grid.set_column_spacing(12)
        content.append(grid)

        row = 0

        # Name
        grid.attach(Gtk.Label(label="Name:", halign=Gtk.Align.END), 0, row, 1, 1)
        self.name_entry = Gtk.Entry()
        self.name_entry.set_hexpand(True)
        self.name_entry.set_text(data.get("name", ""))
        grid.attach(self.name_entry, 1, row, 1, 1)
        row += 1

        # Action
        grid.attach(Gtk.Label(label="Action:", halign=Gtk.Align.END), 0, row, 1, 1)
        self.action_dropdown = Gtk.DropDown.new_from_strings(["Allow", "Block"])
        if data.get("action", "block").lower() == "allow":
            self.action_dropdown.set_selected(0)
        else:
            self.action_dropdown.set_selected(1)
        grid.attach(self.action_dropdown, 1, row, 1, 1)
        row += 1

        # Protocol
        grid.attach(Gtk.Label(label="Protocol:", halign=Gtk.Align.END), 0, row, 1, 1)
        self.protocol_dropdown = Gtk.DropDown.new_from_strings(["TCP", "UDP", "ICMP", "Any"])
        proto_map = {"tcp": 0, "udp": 1, "icmp": 2, "any": 3}
        self.protocol_dropdown.set_selected(
            proto_map.get(data.get("protocol", "any").lower(), 3)
        )
        grid.attach(self.protocol_dropdown, 1, row, 1, 1)
        row += 1

        # Local port
        grid.attach(Gtk.Label(label="Local Port:", halign=Gtk.Align.END), 0, row, 1, 1)
        self.local_port_entry = Gtk.Entry()
        self.local_port_entry.set_placeholder_text("Any")
        lp = data.get("local_port")
        if lp is not None:
            self.local_port_entry.set_text(str(lp))
        grid.attach(self.local_port_entry, 1, row, 1, 1)
        row += 1

        # Remote port
        grid.attach(Gtk.Label(label="Remote Port:", halign=Gtk.Align.END), 0, row, 1, 1)
        self.remote_port_entry = Gtk.Entry()
        self.remote_port_entry.set_placeholder_text("Any")
        rp = data.get("remote_port")
        if rp is not None:
            self.remote_port_entry.set_text(str(rp))
        grid.attach(self.remote_port_entry, 1, row, 1, 1)
        row += 1

        # Remote address
        grid.attach(Gtk.Label(label="Remote Address:", halign=Gtk.Align.END), 0, row, 1, 1)
        self.remote_addr_entry = Gtk.Entry()
        self.remote_addr_entry.set_placeholder_text("Any")
        self.remote_addr_entry.set_text(data.get("remote_address") or "")
        grid.attach(self.remote_addr_entry, 1, row, 1, 1)
        row += 1

        # Application
        grid.attach(Gtk.Label(label="Application:", halign=Gtk.Align.END), 0, row, 1, 1)
        app_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
        self.app_entry = Gtk.Entry()
        self.app_entry.set_hexpand(True)
        self.app_entry.set_placeholder_text("/usr/bin/...")
        self.app_entry.set_text(data.get("application") or "")
        app_box.append(self.app_entry)

        browse_btn = Gtk.Button.new_from_icon_name("document-open-symbolic")
        browse_btn.set_tooltip_text("Browse")
        browse_btn.connect("clicked", self._on_browse_app)
        app_box.append(browse_btn)
        grid.attach(app_box, 1, row, 1, 1)
        row += 1

        # Enabled
        grid.attach(Gtk.Label(label="Enabled:", halign=Gtk.Align.END), 0, row, 1, 1)
        self.enabled_switch = Gtk.Switch()
        self.enabled_switch.set_active(data.get("enabled", True))
        self.enabled_switch.set_halign(Gtk.Align.START)
        grid.attach(self.enabled_switch, 1, row, 1, 1)

    def _on_browse_app(self, _btn: Gtk.Button) -> None:
        """Open a file chooser to select an application binary."""
        dialog = Gtk.FileDialog()
        dialog.set_title("Select Application")
        dialog.open(self.get_transient_for(), None, self._browse_app_cb)

    def _browse_app_cb(self, dialog: Gtk.FileDialog, result: Gio.AsyncResult) -> None:
        try:
            gfile = dialog.open_finish(result)
            if gfile:
                self.app_entry.set_text(gfile.get_path())
        except Exception:
            pass

    def get_rule_data(self) -> dict[str, Any]:
        """Extract the rule dict from the dialog fields.

        Maps local_port/remote_port into the FirewallRule ``port`` field:
        for inbound rules the local port is the match target (dport),
        for outbound rules the remote port is the match target (dport).
        """
        actions = ["allow", "block"]
        protocols = ["tcp", "udp", "icmp", "any"]

        lp_text = self.local_port_entry.get_text().strip()
        rp_text = self.remote_port_entry.get_text().strip()

        local_port = int(lp_text) if lp_text.isdigit() else None
        remote_port = int(rp_text) if rp_text.isdigit() else None

        # FirewallRule uses a single 'port' field (always matched as dport)
        if self._direction == "inbound":
            port = local_port
        else:
            port = remote_port

        return {
            "name": self.name_entry.get_text().strip(),
            "direction": self._direction,
            "action": actions[self.action_dropdown.get_selected()],
            "protocol": protocols[self.protocol_dropdown.get_selected()],
            "port": port,
            "remote_address": self.remote_addr_entry.get_text().strip() or None,
            "application": self.app_entry.get_text().strip() or None,
            "enabled": self.enabled_switch.get_active(),
        }


# ---------------------------------------------------------------------------
# Inbound Rules Panel
# ---------------------------------------------------------------------------

class InboundRulesPanel(Gtk.Box):
    """Panel listing all inbound firewall rules with management toolbar."""

    DIRECTION = "inbound"

    def __init__(self, store: RuleStore, nft: NftManager) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self._store = store
        self._nft = nft

        # --- Toolbar ---
        toolbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
        toolbar.set_margin_top(4)
        toolbar.set_margin_bottom(4)
        toolbar.set_margin_start(8)
        toolbar.set_margin_end(8)

        add_btn = Gtk.Button(label="Add Rule")
        add_btn.set_icon_name("list-add-symbolic")
        add_btn.connect("clicked", self._on_add_rule)
        toolbar.append(add_btn)

        edit_btn = Gtk.Button(label="Edit")
        edit_btn.set_icon_name("document-edit-symbolic")
        edit_btn.connect("clicked", self._on_edit_rule)
        toolbar.append(edit_btn)

        delete_btn = Gtk.Button(label="Delete")
        delete_btn.set_icon_name("list-remove-symbolic")
        delete_btn.connect("clicked", self._on_delete_rule)
        toolbar.append(delete_btn)

        toggle_btn = Gtk.Button(label="Enable/Disable")
        toggle_btn.connect("clicked", self._on_toggle_rule)
        toolbar.append(toggle_btn)

        spacer = Gtk.Box()
        spacer.set_hexpand(True)
        toolbar.append(spacer)

        refresh_btn = Gtk.Button.new_from_icon_name("view-refresh-symbolic")
        refresh_btn.set_tooltip_text("Refresh")
        refresh_btn.connect("clicked", lambda _: self.refresh())
        toolbar.append(refresh_btn)

        self.append(toolbar)
        self.append(Gtk.Separator())

        # --- Column view (table) ---
        self._model = Gio.ListStore.new(RuleObject)
        self._selection = Gtk.SingleSelection.new(self._model)

        column_view = Gtk.ColumnView.new(self._selection)
        column_view.set_show_row_separators(True)
        column_view.set_show_column_separators(True)
        column_view.add_css_class("data-table")

        # Columns: Enabled | Name | Action | Protocol | Port
        columns_spec: list[tuple[str, str, int]] = [
            ("enabled", "Enabled", 70),
            ("name", "Name", 250),
            ("action", "Action", 80),
            ("protocol", "Protocol", 80),
            ("port", "Port", 120),
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

        # --- Context menu (right-click) ---
        self._context_menu = Gio.Menu()
        self._context_menu.append("Edit Rule", "inbound.edit-rule")
        self._context_menu.append("Delete Rule", "inbound.delete-rule")
        self._context_menu.append("Toggle Enable/Disable", "inbound.toggle-rule")

        popover = Gtk.PopoverMenu.new_from_model(self._context_menu)
        popover.set_parent(column_view)
        popover.set_has_arrow(False)
        self._context_popover = popover

        # Right-click gesture
        gesture = Gtk.GestureClick.new()
        gesture.set_button(Gdk.BUTTON_SECONDARY)
        gesture.connect("pressed", self._on_right_click)
        column_view.add_controller(gesture)

        # Double-click gesture
        dbl_gesture = Gtk.GestureClick.new()
        dbl_gesture.set_button(Gdk.BUTTON_PRIMARY)
        dbl_gesture.connect("released", self._on_double_click)
        column_view.add_controller(dbl_gesture)

        # Register actions for context menu
        action_group = Gio.SimpleActionGroup()
        for action_name, callback in [
            ("edit-rule", lambda *_: self._on_edit_rule(None)),
            ("delete-rule", lambda *_: self._on_delete_rule(None)),
            ("toggle-rule", lambda *_: self._on_toggle_rule(None)),
        ]:
            action = Gio.SimpleAction.new(action_name, None)
            action.connect("activate", callback)
            action_group.add_action(action)
        self.insert_action_group("inbound", action_group)

        # Info label
        self._info_label = Gtk.Label()
        self._info_label.set_halign(Gtk.Align.START)
        self._info_label.set_margin_start(8)
        self._info_label.set_margin_top(4)
        self._info_label.set_margin_bottom(4)
        self._info_label.add_css_class("dim-label")
        self.append(Gtk.Separator())
        self.append(self._info_label)

        self.refresh()

    # -- ColumnView factories ----------------------------------------------

    @staticmethod
    def _on_factory_setup(
        _factory: Gtk.SignalListItemFactory,
        list_item: Gtk.ListItem,
        prop: str,
    ) -> None:
        if prop == "enabled":
            icon = Gtk.Image()
            list_item.set_child(icon)
        else:
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
        obj: RuleObject = list_item.get_item()
        widget = list_item.get_child()

        if prop == "enabled":
            icon_name = (
                "emblem-ok-symbolic" if obj.enabled else "window-close-symbolic"
            )
            widget.set_from_icon_name(icon_name)
        elif prop == "name":
            widget.set_text(obj.name)
        elif prop == "action":
            widget.set_text(obj.action)
            # Toggle exactly one of error/success -- previously bind()
            # just add-only, so a cell that was ever "block" kept the
            # error class forever even when its rule switched to "allow".
            is_block = obj.action.lower() == "block"
            want = "error" if is_block else "success"
            drop = "success" if is_block else "error"
            prev = getattr(widget, "_fw_action_css", None)
            if prev == want:
                pass
            else:
                if prev:
                    widget.remove_css_class(prev)
                widget.remove_css_class(drop)
                widget.add_css_class(want)
                widget._fw_action_css = want
        elif prop == "protocol":
            widget.set_text(obj.protocol)
        elif prop == "port":
            widget.set_text(obj.port)

    # -- Data loading ------------------------------------------------------

    def refresh(self) -> None:
        """Reload rules from the rule store.

        Diff-updates the list model rather than remove-all + re-add so
        that toggle / edit operations don't force GTK to rebuild every
        row widget.  With 50+ rules on old hardware this is the
        difference between an imperceptible refresh and a visible stall.
        """
        try:
            rules = self._store.get_rules(direction=self.DIRECTION)
        except Exception as exc:
            logger.error("Failed to load %s rules: %s", self.DIRECTION, exc)
            rules = []

        n_existing = self._model.get_n_items()
        for i, rule in enumerate(rules):
            if i < n_existing:
                existing = self._model.get_item(i)
                if existing.data != rule:
                    self._model.splice(i, 1, [RuleObject(rule)])
            else:
                self._model.append(RuleObject(rule))

        target_len = len(rules)
        current_len = self._model.get_n_items()
        if current_len > target_len:
            self._model.splice(target_len, current_len - target_len, [])

        count = self._model.get_n_items()
        self._info_label.set_text(f"{count} {self.DIRECTION} rule(s)")

    # -- Selected rule helper ----------------------------------------------

    def _get_selected_rule(self) -> Optional[RuleObject]:
        pos = self._selection.get_selected()
        if pos == Gtk.INVALID_LIST_POSITION:
            return None
        return self._model.get_item(pos)

    # -- Toolbar actions ---------------------------------------------------

    def _on_add_rule(self, _btn: Optional[Gtk.Button]) -> None:
        win = self.get_root()
        dialog = RuleDialog(win, direction=self.DIRECTION)
        dialog.connect("response", self._on_add_dialog_response)
        dialog.present()

    def _on_add_dialog_response(self, dialog: RuleDialog, response: int) -> None:
        if response == Gtk.ResponseType.OK:
            data = dialog.get_rule_data()
            if data["name"]:
                try:
                    rule = FirewallRule.from_dict(data)
                    self._store.add_rule(rule)
                    # Sync the NftManager's in-memory rule set from the
                    # persistent store before re-applying.  Previously only
                    # ``reload()`` was called, which re-applies the current
                    # in-memory dict -- but newly-added rules in the store
                    # were never loaded into the manager, so the rule
                    # appeared in the GUI and DB but never hit nftables.
                    self._nft.load_rules(self._store.list_rules())
                    self._nft.apply_rules()
                    self.refresh()
                    logger.info("Added %s rule: %s", self.DIRECTION, data["name"])
                except Exception as exc:
                    logger.error("Failed to add rule: %s", exc)
        dialog.destroy()

    def _on_edit_rule(self, _btn: Optional[Gtk.Button]) -> None:
        rule = self._get_selected_rule()
        if rule is None:
            return
        win = self.get_root()
        dialog = RuleDialog(win, direction=self.DIRECTION, rule_data=rule.data)
        dialog.connect("response", self._on_edit_dialog_response, rule)
        dialog.present()

    def _on_edit_dialog_response(
        self, dialog: RuleDialog, response: int, rule: RuleObject
    ) -> None:
        if response == Gtk.ResponseType.OK:
            data = dialog.get_rule_data()
            data["id"] = rule.rule_id
            try:
                fw_rule = FirewallRule.from_dict(data)
                self._store.update_rule(fw_rule)
                self._nft.load_rules(self._store.list_rules())
                self._nft.apply_rules()
                self.refresh()
                logger.info("Updated rule id=%s", rule.rule_id)
            except Exception as exc:
                logger.error("Failed to update rule: %s", exc)
        dialog.destroy()

    def _on_delete_rule(self, _btn: Optional[Gtk.Button]) -> None:
        rule = self._get_selected_rule()
        if rule is None:
            return

        # Confirm deletion
        dialog = Gtk.AlertDialog()
        dialog.set_message(f"Delete rule '{rule.name}'?")
        dialog.set_detail("This action cannot be undone.")
        dialog.set_buttons(["Cancel", "Delete"])
        dialog.set_cancel_button(0)
        dialog.set_default_button(1)
        dialog.choose(self.get_root(), None, self._on_delete_confirmed, rule)

    def _on_delete_confirmed(
        self,
        dialog: Gtk.AlertDialog,
        result: Gio.AsyncResult,
        rule: RuleObject,
    ) -> None:
        try:
            choice = dialog.choose_finish(result)
        except Exception:
            return
        if choice == 1:  # "Delete"
            try:
                self._store.delete_rule(rule.rule_id)
                self._nft.load_rules(self._store.list_rules())
                self._nft.apply_rules()
                self.refresh()
                logger.info("Deleted rule id=%s (%s)", rule.rule_id, rule.name)
            except Exception as exc:
                logger.error("Failed to delete rule: %s", exc)

    def _on_toggle_rule(self, _btn: Optional[Gtk.Button]) -> None:
        rule = self._get_selected_rule()
        if rule is None:
            return
        try:
            new_state = not rule.enabled
            self._store.set_rule_enabled(rule.rule_id, new_state)
            self._nft.load_rules(self._store.list_rules())
            self._nft.apply_rules()
            self.refresh()
            state_str = "enabled" if new_state else "disabled"
            logger.info("Rule '%s' %s", rule.name, state_str)
        except Exception as exc:
            logger.error("Failed to toggle rule: %s", exc)

    # -- Context menu & double-click ---------------------------------------

    def _on_right_click(
        self,
        gesture: Gtk.GestureClick,
        _n_press: int,
        x: float,
        y: float,
    ) -> None:
        rect = Gdk.Rectangle()
        rect.x = int(x)
        rect.y = int(y)
        rect.width = 1
        rect.height = 1
        self._context_popover.set_pointing_to(rect)
        self._context_popover.popup()

    def _on_double_click(
        self,
        gesture: Gtk.GestureClick,
        n_press: int,
        _x: float,
        _y: float,
    ) -> None:
        # Only open the edit dialog on a genuine double-click
        if n_press == 2:
            self._on_edit_rule(None)
