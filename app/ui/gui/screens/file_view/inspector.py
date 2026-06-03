"""Inspector-panel helpers for :class:`FileViewScreen`.
tab switching, property-row rendering, and per-action slot handlers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QPixmap
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QWidget

from app.ui.gui.setup import TOKENS

from .helpers import ElidedLabel, IconLabel, css, force_wrap, tinted_icon
from .models import FileEntry
from .widgets import UnlockedFileCard

if TYPE_CHECKING:
    from .screen import FileViewScreen


def populate_unlocked_cards(screen: "FileViewScreen") -> None:
    screen._unlocked_cards.clear()
    while screen.unlocked_layout.count():
        item = screen.unlocked_layout.takeAt(0)
        widget = item.widget()
        if widget is not None:
            widget.hide()
            widget.deleteLater()
    for entry in screen._unlocked_entries:
        card = UnlockedFileCard(entry, parent=screen)
        card.mouse_press = (
            lambda e, ref=entry: screen.unlocked_open_requested.emit(
                ref.file_ref_id
            )
        )
        card.reopen_clicked = (
            lambda e, ref=entry: screen.unlocked_open_requested.emit(
                ref.file_ref_id
            )
        )
        card.lock_clicked = (
            lambda e, ref=entry: screen.unlocked_lock_requested.emit(
                ref.file_ref_id
            )
        )
        screen.unlocked_layout.addWidget(card)
        screen._unlocked_cards[entry.path] = card
    # Push cards to the top; without this stretch the layout distributes
    # remaining space between rows, giving large gaps between cards.
    screen.unlocked_layout.addStretch(1)
    if hasattr(screen, "unlocked_tab"):
        screen.unlocked_tab.set_count(len(screen._unlocked_entries))


def set_active_tab(screen: "FileViewScreen", name: str) -> None:
    is_props = name == "properties"
    screen.inspector_stack.setCurrentIndex(0 if is_props else 1)
    if hasattr(screen, "properties_tab"):
        screen.properties_tab.set_active(is_props)
    if hasattr(screen, "unlocked_tab"):
        screen.unlocked_tab.set_active(not is_props)


def update_selection(screen: "FileViewScreen", path: str) -> None:
    entry = next(
        (e for e in screen._file_entries if e.path == path), None
    )
    if entry is None:
        return
    if (
        entry.file_ref_id is not None
        and entry.file_ref_id in screen._pending_actions
    ):
        return
    screen._selected_path = entry.path
    is_unlocked = any(
        item.file_ref_id == entry.file_ref_id
        for item in screen._unlocked_entries
    )
    # Match the design: small inline icon next to the filename. Unlocked
    # files surface the open-lock glyph in the warning hue; everything else
    # uses the extension icon tinted with the accent.
    if entry.is_folder:
        icon_glyph, icon_color = "folder", TOKENS.colors.text_secondary
    elif is_unlocked:
        icon_glyph, icon_color = (
            "lock-simple-open",
            TOKENS.colors.status_warning_text,
        )
    else:
        icon_glyph, icon_color = entry.icon_name, QColor(entry.accent)
    screen.properties_icon.setPixmap(
        tinted_icon(icon_glyph, size=20, color=icon_color).pixmap(20, 20)
    )
    screen.properties_name.setText(force_wrap(entry.name))
    rebuild_property_rows(screen, entry)
    preview = (entry.preview_text or "").strip()
    if preview and preview.lower() != "no content preview available":
        screen.properties_preview.setPlainText(preview)
        screen._preview_box_layout.setCurrentWidget(screen.properties_preview)
    else:
        screen.properties_preview.setPlainText("")
        screen.preview_empty_text.setText("No preview available")
        screen._preview_box_layout.setCurrentWidget(screen.preview_empty_state)
    screen._properties_page_stack.setCurrentIndex(1)
    screen.properties_lock_button.setEnabled(
        bool(entry.file_ref_id) and not entry.is_folder and is_unlocked
    )
    screen.properties_export_button.setEnabled(
        not entry.is_folder and bool(entry.path)
    )
    screen.properties_open_button.setEnabled(
        not entry.is_folder and bool(entry.file_ref_id)
    )
    for card_path, card in screen._unlocked_cards.items():
        card.set_selected(card_path == path)


def show_multi_selection(
    screen: "FileViewScreen", paths: list[str]
) -> None:
    screen._selected_path = None
    screen.properties_icon.setPixmap(QPixmap())
    screen.properties_name.setText(f"{len(paths)} items selected")
    clear_property_rows(screen)
    screen.properties_preview.setPlainText("")
    screen.preview_empty_text.setText("No preview available")
    screen._preview_box_layout.setCurrentWidget(screen.preview_empty_state)
    screen.properties_open_button.setEnabled(False)
    screen.properties_lock_button.setEnabled(False)
    screen.properties_export_button.setEnabled(False)
    screen._properties_page_stack.setCurrentIndex(1)
    for card in screen._unlocked_cards.values():
        card.set_selected(False)


def clear_properties(screen: "FileViewScreen") -> None:
    screen._selected_path = None
    screen.properties_icon.setPixmap(QPixmap())
    screen.properties_name.setText("")
    clear_property_rows(screen)
    screen.properties_preview.setPlainText("")
    screen.preview_empty_text.setText("Select a file or folder to see details")
    screen._preview_box_layout.setCurrentWidget(screen.preview_empty_state)
    screen.properties_lock_button.setEnabled(False)
    screen.properties_export_button.setEnabled(False)
    screen.properties_open_button.setEnabled(False)
    # Hide all sub-widgets - only the centred placeholder label is visible.
    screen._properties_page_stack.setCurrentIndex(0)


def clear_property_rows(screen: "FileViewScreen") -> None:
    # hide() before deleteLater() so the widget doesn't briefly appear as a
    # top-level window - setParent(None) on a visible child promotes it.
    while screen.properties_rows_layout.count():
        item = screen.properties_rows_layout.takeAt(0)
        widget = item.widget()
        if widget is not None:
            widget.hide()
            widget.deleteLater()


def rebuild_property_rows(
    screen: "FileViewScreen", entry: FileEntry
) -> None:
    c = TOKENS.colors
    key_css = (
        f'font-family: "IBM Plex Mono"; font-size: 11px; '
        f"color: {css(c.text_muted)};"
    )
    val_css = (
        f'font-family: "IBM Plex Mono"; font-size: 11px; '
        f"color: {css(c.text_primary)};"
    )
    clear_property_rows(screen)
    for label_text, value_text in entry.property_rows:
        row = QFrame(screen.properties_rows_frame)
        row_layout = QHBoxLayout(row)
        row_layout.setContentsMargins(0, 0, 0, 0)
        row_layout.setSpacing(14)

        label = QLabel(label_text, row)
        label.setStyleSheet(key_css)
        label.setFixedWidth(78)
        row_layout.addWidget(label, 0)

        value_host = QWidget(row)
        value_layout = QHBoxLayout(value_host)
        value_layout.setContentsMargins(0, 0, 0, 0)
        value_layout.setSpacing(TOKENS.spacing.xs)
        if label_text.lower() == "author":
            value_layout.addWidget(
                IconLabel(
                    "user-circle",
                    size=14,
                    color=c.text_muted,
                    parent=value_host,
                )
            )
        value = QLabel(force_wrap(value_text), value_host)
        value.setWordWrap(True)
        value.setMinimumWidth(0)
        value.setAlignment(
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop
        )
        value.setStyleSheet(val_css)
        value_layout.addWidget(value, 1)
        row_layout.addWidget(value_host, 1)
        screen.properties_rows_layout.addWidget(row)


def selected_entry(screen: "FileViewScreen") -> FileEntry | None:
    if screen._selected_path is None:
        return None
    return next(
        (
            entry
            for entry in screen._file_entries
            if entry.path == screen._selected_path
        ),
        None,
    )


def open_selected_file(screen: "FileViewScreen") -> None:
    entry = selected_entry(screen)
    if entry is None or entry.file_ref_id is None or entry.is_folder:
        return
    screen.file_open_requested.emit(entry.file_ref_id)


def lock_selected_from_properties(screen: "FileViewScreen") -> None:
    entry = selected_entry(screen)
    if entry is None or entry.file_ref_id is None:
        return
    screen.unlocked_lock_requested.emit(entry.file_ref_id)


def export_selected_from_properties(screen: "FileViewScreen") -> None:
    entry = selected_entry(screen)
    if entry is None or not entry.path:
        return
    screen.export_requested.emit([entry.path])
