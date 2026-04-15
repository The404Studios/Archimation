#!/usr/bin/env python3
"""
PE-Compat Firewall GUI - Outbound Rules Panel

Displays, creates, edits, and deletes outbound firewall rules.
Structurally identical to the inbound panel but operates on
the "outbound" direction.
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
from gui.inbound_rules import RuleDialog  # noqa: E402
from backend.nft_manager import FirewallRule  # noqa: E402

logger = logging.getLogger("pe-compat.firewall.gui.outbound")


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

class OutboundRuleObject(GObject.Object):
    """GObject wrapper for an outbound firewall rule."""

    __gtype_name__ = "OutboundRuleObject"

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
        return self.data.get("action", "allow").capitalize()

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
# Outbound Rules Panel
# ---------------------------------------------------------------------------

class OutboundRulesPanel(Gtk.Box):
    """Panel listing all outbound firewall rules with management toolbar."""

    DIRECTION = "outbound"

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

        # --- Column view ---
        self._model = Gio.ListStore.new(OutboundRuleObject)
        self._selection = Gtk.SingleSelection.new(self._model)

        column_view = Gtk.ColumnView.new(self._selection)
        column_view.set_show_row_separators(True)
        column_view.set_show_column_separators(True)
        column_view.add_css_class("data-table")

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

        # --- Context menu ---
        self._context_menu = Gio.Menu()
        self._context_menu.append("Edit Rule", "outbound.edit-rule")
        self._context_menu.append("Delete Rule", "outbound.delete-rule")
        self._context_menu.append("Toggle Enable/Disable", "outbound.toggle-rule")

        popover = Gtk.PopoverMenu.new_from_model(self._context_menu)
        popover.set_parent(column_view)
        popover.set_has_arrow(False)
        self._context_popover = popover

        gesture = Gtk.GestureClick.new()
        gesture.set_button(Gdk.BUTTON_SECONDARY)
        gesture.connect("pressed", self._on_right_click)
        column_view.add_controller(gesture)

        dbl_gesture = Gtk.GestureClick.new()
        dbl_gesture.set_button(Gdk.BUTTON_PRIMARY)
        dbl_gesture.connect("released", self._on_double_click)
        column_view.add_controller(dbl_gesture)

        # Register actions
        action_group = Gio.SimpleActionGroup()
        for action_name, callback in [
            ("edit-rule", lambda *_: self._on_edit_rule(None)),
            ("delete-rule", lambda *_: self._on_delete_rule(None)),
            ("toggle-rule", lambda *_: self._on_toggle_rule(None)),
        ]:
            action = Gio.SimpleAction.new(action_name, None)
            action.connect("activate", callback)
            action_group.add_action(action)
        self.insert_action_group("outbound", action_group)

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
        obj: OutboundRuleObject = list_item.get_item()
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
            is_block = obj.action.lower() == "block"
            want = "error" if is_block else "success"
            drop = "success" if is_block else "error"
            prev = getattr(widget, "_fw_action_css", None)
            if prev != want:
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
        """Reload outbound rules from the rule store.

        Diff-updates the list model rather than remove-all + re-add so
        that toggle / edit operations don't force GTK to rebuild every
        row widget.
        """
        try:
            rules = self._store.get_rules(direction=self.DIRECTION)
        except Exception as exc:
            logger.error("Failed to load outbound rules: %s", exc)
            rules = []

        n_existing = self._model.get_n_items()
        for i, rule in enumerate(rules):
            if i < n_existing:
                existing = self._model.get_item(i)
                if existing.data != rule:
                    self._model.splice(i, 1, [OutboundRuleObject(rule)])
            else:
                self._model.append(OutboundRuleObject(rule))

        target_len = len(rules)
        current_len = self._model.get_n_items()
        if current_len > target_len:
            self._model.splice(target_len, current_len - target_len, [])

        count = self._model.get_n_items()
        self._info_label.set_text(f"{count} outbound rule(s)")

    # -- Selected rule helper ----------------------------------------------

    def _get_selected_rule(self) -> Optional[OutboundRuleObject]:
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
                    # reload() alone only re-applies the in-memory rule
                    # set, which never saw the newly-added rule.  Sync
                    # from the store first so the nft ruleset actually
                    # reflects what the user just added.
                    self._nft.load_rules(self._store.list_rules())
                    self._nft.apply_rules()
                    self.refresh()
                    logger.info("Added outbound rule: %s", data["name"])
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
        self, dialog: RuleDialog, response: int, rule: OutboundRuleObject
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
                logger.info("Updated outbound rule id=%s", rule.rule_id)
            except Exception as exc:
                logger.error("Failed to update rule: %s", exc)
        dialog.destroy()

    def _on_delete_rule(self, _btn: Optional[Gtk.Button]) -> None:
        rule = self._get_selected_rule()
        if rule is None:
            return

        dialog = Gtk.AlertDialog()
        dialog.set_message(f"Delete outbound rule '{rule.name}'?")
        dialog.set_detail("This action cannot be undone.")
        dialog.set_buttons(["Cancel", "Delete"])
        dialog.set_cancel_button(0)
        dialog.set_default_button(1)
        dialog.choose(self.get_root(), None, self._on_delete_confirmed, rule)

    def _on_delete_confirmed(
        self,
        dialog: Gtk.AlertDialog,
        result: Gio.AsyncResult,
        rule: OutboundRuleObject,
    ) -> None:
        try:
            choice = dialog.choose_finish(result)
        except Exception:
            return
        if choice == 1:
            try:
                self._store.delete_rule(rule.rule_id)
                self._nft.load_rules(self._store.list_rules())
                self._nft.apply_rules()
                self.refresh()
                logger.info("Deleted outbound rule id=%s (%s)", rule.rule_id, rule.name)
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
            logger.info("Outbound rule '%s' %s", rule.name, state_str)
        except Exception as exc:
            logger.error("Failed to toggle outbound rule: %s", exc)

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
