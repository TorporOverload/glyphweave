"""Centred-card modal that lists sync conflicts and drives resolution."""

from __future__ import annotations

from typing import Iterable

from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtGui import QKeyEvent
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from app.services.models import SyncConflictInfo
from app.services.sync.folder_handlers import original_name
from app.ui.gui.screens.file_view.models import FileEntry
from app.ui.gui.setup import TOKENS

from .detail import DetailPane
from .helpers import format_short_date, original_parent_path
from .overlays import (
    AliasOverlay,
    DeleteOverlay,
    InspectOverlay,
    RestoreOverlay,
)


class _TabButton(QPushButton):
    """Checkable tab button used in the header segmented control."""

    def __init__(self, label: str, parent: QWidget | None = None) -> None:
        super().__init__(label, parent)
        self._label = label
        self.setCheckable(True)
        self.setObjectName("CfTabBtn")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFlat(True)
        self.setStyleSheet(
            "QPushButton#CfTabBtn {"
            " background: transparent; border: none; border-radius: 5px;"
            ' font-family: "IBM Plex Sans"; font-size: 11px;'
            " color: #6B7383; padding: 3px 10px; min-width: 68px;"
            "}"
            "QPushButton#CfTabBtn:checked {"
            " background-color: #FFFFFF; color: #2E3440; font-weight: 600;"
            "}"
            "QPushButton#CfTabBtn:hover:!checked {"
            " background-color: #D5DCE8;"
            "}"
        )

    def set_count(self, count: int) -> None:
        self.setText(f"{self._label}  {count}")


class ConflictResolutionDialog(QDialog):
    """Bell-target modal showing active and historical sync conflicts.

    The dialog talks to ``VaultService`` directly via the methods added
    in this round (``list_sync_conflicts(include_resolved=True)``,
    ``restore_sync_conflict``, ``delete_archived_conflict``,
    ``get_trigger_event_payload``, ``set_device_alias``,
    ``resolve_device_alias``). After every successful action it asks the
    parent window to refresh the file view and re-counts conflicts so
    the bell red-dot stays in sync.
    """

    state_changed = Signal()
    open_file_requested = Signal(int)  # archived_file_ref_id

    _SIZE = QSize(880, 560)
    _RAIL_W = 320

    def __init__(
        self,
        service,
        *,
        entries: Iterable[FileEntry] | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._service = service
        self._entries: list[FileEntry] = list(entries or [])
        self._active_conflicts: list[SyncConflictInfo] = []
        self._history_conflicts: list[SyncConflictInfo] = []
        self._current_tab: str = "active"

        self.setModal(True)
        self.setWindowFlag(Qt.WindowType.FramelessWindowHint, True)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setFixedSize(self._SIZE)
        self.setStyleSheet(
            "QDialog { background-color: #FFFFFF;"
            " border: 2px solid #4C566A; border-radius: 8px; }"
        )

        self._build_ui()
        self.refresh()

    # Public API

    def set_entries(self, entries: Iterable[FileEntry]) -> None:
        self._entries = list(entries)

    def refresh(self) -> None:
        """Reload conflicts from the service and rebuild the list."""
        try:
            all_conflicts = self._service.list_sync_conflicts(include_resolved=True)
        except Exception:  # noqa: BLE001
            all_conflicts = []

        self._active_conflicts = [c for c in all_conflicts if c.status == "active"]
        self._history_conflicts = [c for c in all_conflicts if c.status != "active"]

        self._tab_active.set_count(len(self._active_conflicts))
        self._tab_history.set_count(len(self._history_conflicts))
        self._set_count_pill(len(self._active_conflicts), tone="active")

        self._populate_list()
        if self._get_current_conflicts():
            self._list.setCurrentRow(0)
        else:
            self._detail.set_conflict(None)

    # Build

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        outer.addWidget(self._build_header())

        body = QFrame(self)
        body.setStyleSheet("background-color: #FFFFFF;")
        body_layout = QHBoxLayout(body)
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(0)

        body_layout.addWidget(self._build_list_rail(), 0)

        v_divider = QFrame(body)
        v_divider.setFixedWidth(1)
        v_divider.setStyleSheet("background-color: #C0C9D6;")
        body_layout.addWidget(v_divider)

        self._detail = DetailPane(body)
        self._detail.set_device_alias_resolver(
            lambda dev_id: self._safe_resolve_alias(dev_id)
        )
        self._detail.open_archived_requested.connect(self._emit_open_for_selected)
        body_layout.addWidget(self._detail, 1)

        outer.addWidget(body, 1)

    def _build_header(self) -> QWidget:
        from app.ui.gui.setup.icons import tinted_icon

        header = QFrame(self)
        header.setFixedHeight(44)
        header.setObjectName("CfPanelHead")
        header.setStyleSheet(
            "QFrame#CfPanelHead {"
            " background-color: #F1F4F8;"
            " border-bottom: 1px solid #C0C9D6;"
            "}"
        )
        layout = QHBoxLayout(header)
        layout.setContentsMargins(14, 0, 10, 0)
        layout.setSpacing(8)

        # Left cluster: warn icon + title + count pill
        warn = QLabel(header)
        warn.setPixmap(
            tinted_icon(
                "warning", size=16, color=TOKENS.colors.status_error_text
            ).pixmap(16, 16)
        )
        warn.setFixedSize(QSize(18, 18))
        layout.addWidget(warn, 0, Qt.AlignmentFlag.AlignVCenter)

        title = QLabel("Sync conflicts", header)
        title.setStyleSheet(
            'font-family: "IBM Plex Sans"; font-size: 13px;'
            " font-weight: 700; color: #2E3440;"
        )
        layout.addWidget(title)

        self._count_pill = QLabel("0", header)
        self._count_pill.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._count_pill.setFixedHeight(18)
        self._count_pill.setMinimumWidth(26)
        self._set_count_pill(0)
        layout.addWidget(self._count_pill, 0, Qt.AlignmentFlag.AlignVCenter)

        layout.addStretch(1)

        # Center: segmented tab control
        tab_tray = QFrame(header)
        tab_tray.setObjectName("CfTabTray")
        tab_tray.setStyleSheet(
            "QFrame#CfTabTray {"
            " background-color: #E0E6F0;"
            " border: 1px solid #C0C9D6;"
            " border-radius: 6px;"
            "}"
        )
        tab_layout = QHBoxLayout(tab_tray)
        tab_layout.setContentsMargins(2, 2, 2, 2)
        tab_layout.setSpacing(0)

        self._tab_active = _TabButton("Active", tab_tray)
        self._tab_history = _TabButton("History", tab_tray)
        self._tab_active.setChecked(True)
        self._tab_active.clicked.connect(lambda: self._switch_tab("active"))
        self._tab_history.clicked.connect(lambda: self._switch_tab("history"))

        tab_layout.addWidget(self._tab_active)
        tab_layout.addWidget(self._tab_history)
        layout.addWidget(tab_tray)

        layout.addStretch(1)

        # Right: close button
        close = QPushButton(header)
        close.setObjectName("ConflictDialogClose")
        close.setIcon(tinted_icon("x", size=12, color=TOKENS.colors.text_secondary))
        close.setIconSize(QSize(12, 12))
        close.setFixedSize(24, 24)
        close.setFlat(True)
        close.setCursor(Qt.CursorShape.PointingHandCursor)
        close.setStyleSheet(
            "QPushButton#ConflictDialogClose {"
            " background: transparent; border: none; border-radius: 4px;"
            "}"
            "QPushButton#ConflictDialogClose:hover { background: #E0E6F0; }"
        )
        close.clicked.connect(self.reject)
        layout.addWidget(close, 0, Qt.AlignmentFlag.AlignVCenter)
        return header

    def _set_count_pill(self, count: int, *, tone: str = "active") -> None:
        if tone == "active" and count > 0:
            bg, fg, border = "#FAEEEF", "#5A2027", "#E5C0C5"
        else:
            bg, fg, border = "#E8ECF4", "#4C566A", "#C0C9D6"
        self._count_pill.setText(str(count))
        self._count_pill.setStyleSheet(
            f"QLabel {{ background-color: {bg}; color: {fg};"
            f" border: 1px solid {border}; border-radius: 9px;"
            ' font-family: "IBM Plex Mono"; font-size: 10px;'
            " font-weight: 600; padding: 1px 7px; }}"
        )

    def _build_list_rail(self) -> QWidget:
        rail = QFrame(self)
        rail.setObjectName("ConflictListRail")
        rail.setFixedWidth(self._RAIL_W)
        rail.setStyleSheet("QFrame#ConflictListRail { background-color: #FAFBFD; }")
        layout = QVBoxLayout(rail)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # List header bar: eyebrow + count chip
        list_head = QFrame(rail)
        list_head.setObjectName("CfListHead")
        list_head.setStyleSheet(
            "QFrame#CfListHead {"
            " background-color: #F4F6FA;"
            " border-bottom: 1px solid #E0E4EC;"
            "}"
        )
        list_head.setFixedHeight(32)
        head_layout = QHBoxLayout(list_head)
        head_layout.setContentsMargins(12, 0, 12, 0)
        head_layout.setSpacing(0)

        self._eyebrow = QLabel("ACTIVE CONFLICTS", list_head)
        self._eyebrow.setStyleSheet(
            'font-family: "IBM Plex Mono"; font-size: 10px;'
            " letter-spacing: 0.06em; color: #6B7383;"
        )
        head_layout.addWidget(self._eyebrow)
        head_layout.addStretch(1)

        self._list_count_chip = QLabel("0", list_head)
        self._list_count_chip.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._list_count_chip.setStyleSheet(
            "QLabel { background-color: #E8ECF4; color: #4C566A;"
            " border: 1px solid #C0C9D6; border-radius: 8px;"
            ' font-family: "IBM Plex Mono"; font-size: 10px; padding: 1px 6px; }'
        )
        head_layout.addWidget(self._list_count_chip)
        layout.addWidget(list_head)

        # Scrollable list
        self._list = QListWidget(rail)
        self._list.setStyleSheet(
            "QListWidget { background: transparent; border: none; outline: none;"
            " padding: 5px; }"
            "QListWidget::item { padding: 0px; margin: 1px 0; border-radius: 5px;"
            " border: 1px solid transparent; }"
            "QListWidget::item:selected { background: #FFFFFF;"
            " border: 1px solid #B8C2D0; }"
            "QListWidget::item:hover:!selected { background: #F1F4F8; }"
        )
        self._list.itemSelectionChanged.connect(self._on_selection_changed)
        layout.addWidget(self._list, 1)

        return rail

    # Tab and list management

    def _get_current_conflicts(self) -> list[SyncConflictInfo]:
        if self._current_tab == "active":
            return self._active_conflicts
        return self._history_conflicts

    def _switch_tab(self, tab: str) -> None:
        self._current_tab = tab
        self._tab_active.setChecked(tab == "active")
        self._tab_history.setChecked(tab == "history")
        self._eyebrow.setText(
            "ACTIVE CONFLICTS" if tab == "active" else "PAST RESOLUTIONS"
        )
        self._populate_list()
        self._detail.set_conflict(None)

    def _populate_list(self) -> None:
        self._list.clear()
        conflicts = self._get_current_conflicts()
        self._list_count_chip.setText(str(len(conflicts)))
        for conflict in conflicts:
            row = self._build_list_row(conflict)
            item = QListWidgetItem()
            item.setSizeHint(QSize(0, 50))
            item.setData(Qt.ItemDataRole.UserRole, conflict.conflict_id)
            self._list.addItem(item)
            self._list.setItemWidget(item, row)

    def _build_list_row(self, conflict: SyncConflictInfo) -> QWidget:
        row = QFrame()
        row.setStyleSheet("QFrame { background: transparent; }")
        layout = QVBoxLayout(row)
        layout.setContentsMargins(8, 6, 8, 6)
        layout.setSpacing(2)

        # Top line: dot + name + date
        top = QHBoxLayout()
        top.setContentsMargins(0, 0, 0, 0)
        top.setSpacing(6)

        is_active = conflict.status == "active"
        dot = QLabel(row)
        dot.setFixedSize(8, 8)
        dot.setStyleSheet(
            "background-color: "
            + ("#BF616A" if is_active else "#88909F")
            + "; border-radius: 4px;"
        )
        top.addWidget(dot, 0, Qt.AlignmentFlag.AlignVCenter)

        name = QLabel(conflict.archived_name or "(unnamed)", row)
        name.setStyleSheet(
            'font-family: "IBM Plex Sans"; font-size: 12px; color: #2E3440;'
        )
        name.setMinimumWidth(0)
        top.addWidget(name, 1)

        if self._current_tab != "active":
            is_resolved = conflict.status == "resolved"
            pill_bg = "#EEF5F0" if is_resolved else "#F4F6FA"
            pill_fg = "#2D6A4F" if is_resolved else "#4C566A"
            pill_border = "#C3E6CB" if is_resolved else "#D0D6E0"
            pill_text = "Resolved" if is_resolved else "Deleted"
            pill = QLabel(pill_text, row)
            pill.setStyleSheet(
                f"QLabel {{ background-color: {pill_bg}; color: {pill_fg};"
                f" border: 1px solid {pill_border}; border-radius: 4px;"
                ' font-family: "IBM Plex Sans"; font-size: 10px;'
                " padding: 1px 5px; }"
            )
            top.addWidget(pill, 0)

        date = QLabel(format_short_date(conflict.created_at), row)
        date.setStyleSheet(
            'font-family: "IBM Plex Mono"; font-size: 10px; color: #6B7383;'
        )
        top.addWidget(date, 0)
        layout.addLayout(top)

        # Bottom line: device · path
        device_alias = (
            self._safe_resolve_alias(conflict.origin_device_id)
            or conflict.origin_device_id
            or "unknown"
        )
        sub = QLabel(
            f"{device_alias} · {conflict.archived_virtual_path or '/'}",
            row,
        )
        sub.setStyleSheet(
            'font-family: "IBM Plex Mono"; font-size: 10px; color: #6B7383;'
        )
        sub.setMinimumWidth(0)
        layout.addWidget(sub)
        return row

    # Selection and action wiring

    def _on_selection_changed(self) -> None:
        item = self._list.currentItem()
        if item is None:
            self._detail.set_conflict(None)
            return
        conflict = self._find_conflict(item.data(Qt.ItemDataRole.UserRole))
        self._detail.set_conflict(conflict)
        if conflict and conflict.status == "active":
            self._wire_actions(conflict)

    def _emit_open_for_selected(self, _archived_path: str) -> None:
        self._request_open(self._detail.selected_conflict())

    def _request_open(self, conflict: SyncConflictInfo | None) -> None:
        if conflict is None or conflict.archived_file_ref_id is None:
            self._toast("info", "Archived copy is no longer available to open.")
            return
        self.open_file_requested.emit(conflict.archived_file_ref_id)

    def _wire_actions(self, conflict: SyncConflictInfo | None) -> None:
        # Disconnect previous selections before re-wiring - otherwise every
        # click cycle stacks another lambda on each button, and a Restore
        # click after navigating through three conflicts would fire the
        # handler three times with stale ``conflict`` references.
        for button in (
            self._detail.restore_button,
            self._detail.delete_button,
            self._detail.alias_button,
            self._detail.inspect_button,
        ):
            try:
                button.clicked.disconnect()
            except (TypeError, RuntimeError):
                # No prior connections, or button was deleted by Qt.
                pass

        if conflict is None:
            return
        self._detail.restore_button.clicked.connect(
            lambda _checked=False, c=conflict: self._handle_restore(c)
        )
        self._detail.delete_button.clicked.connect(
            lambda _checked=False, c=conflict: self._handle_delete(c)
        )
        self._detail.alias_button.clicked.connect(
            lambda _checked=False, c=conflict: self._handle_alias(c)
        )
        self._detail.inspect_button.clicked.connect(
            lambda _checked=False, c=conflict: self._handle_inspect(c)
        )

    # ------------------------------------------------------------------
    # Action handlers
    # ------------------------------------------------------------------

    def _handle_restore(self, conflict: SyncConflictInfo) -> None:
        overlay = RestoreOverlay(
            conflict,
            self._entries,
            default_destination=original_parent_path(conflict.archived_virtual_path),
            default_name=original_name(conflict.archived_name),
            parent=self,
        )
        if overlay.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            self._service.restore_sync_conflict(
                conflict.conflict_id,
                destination_folder_virtual_path=overlay.destination_folder(),
                new_name=overlay.new_name(),
            )
        except Exception as exc:  # noqa: BLE001
            self._toast("error", f"Restore failed: {exc}")
            return
        self._toast("success", f"Restored {conflict.archived_name}.")
        self.state_changed.emit()
        self.refresh()

    def _handle_delete(self, conflict: SyncConflictInfo) -> None:
        overlay = DeleteOverlay(conflict, parent=self)
        if overlay.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            self._service.delete_archived_conflict(conflict.conflict_id)
        except Exception as exc:  # noqa: BLE001
            self._toast("error", f"Delete failed: {exc}")
            return
        self._toast("success", f"Deleted archived {conflict.archived_name}.")
        self.state_changed.emit()
        self.refresh()

    def _handle_alias(self, conflict: SyncConflictInfo) -> None:
        device_id = conflict.origin_device_id or ""
        if not device_id:
            self._toast("warn", "No device id on this conflict.")
            return
        current = self._safe_resolve_alias(device_id)
        overlay = AliasOverlay(device_id, current, parent=self)
        if overlay.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            self._service.set_device_alias(device_id, overlay.alias())
        except Exception as exc:  # noqa: BLE001
            self._toast("error", f"Alias save failed: {exc}")
            return
        new_alias = overlay.alias()
        self._toast(
            "success",
            (
                f"Alias for {device_id} set to {new_alias}."
                if new_alias
                else f"Alias for {device_id} cleared."
            ),
        )
        self.refresh()

    def _handle_inspect(self, conflict: SyncConflictInfo) -> None:
        try:
            payload = self._service.get_trigger_event_payload(conflict.conflict_id)
        except Exception:  # noqa: BLE001
            payload = None
        InspectOverlay(payload, parent=self).exec()

    # Utilities

    def _find_conflict(self, conflict_id: object) -> SyncConflictInfo | None:
        if not isinstance(conflict_id, str):
            return None
        for c in self._active_conflicts + self._history_conflicts:
            if c.conflict_id == conflict_id:
                return c
        return None

    def _safe_resolve_alias(self, device_id: str) -> str | None:
        if not device_id:
            return None
        try:
            return self._service.resolve_device_alias(device_id)
        except Exception:  # noqa: BLE001
            return None

    def _toast(self, kind: str, text: str) -> None:
        window = self.parent()
        while window is not None and not hasattr(window, "add_toast"):
            window = window.parent()
        if window is not None:
            window.add_toast(kind, text)

    # Qt overrides

    def keyPressEvent(self, event: QKeyEvent) -> None:  # type: ignore[override]
        if event.key() == Qt.Key.Key_Escape:
            self.reject()
            return
        super().keyPressEvent(event)


__all__ = ["ConflictResolutionDialog"]
