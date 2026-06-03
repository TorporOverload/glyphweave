"""Confirmation overlay dialogs for conflict actions.

Each overlay is a small QDialog that returns its result via accept/reject;
the parent dialog reads the data via the overlay's getter methods. The
dialogs sit on top of the main conflict modal rather than inline-replacing
the action ladder.

Each overlay uses a structured head / body / foot layout:
  - head (40px): icon + title on a slightly elevated surface
  - body: padded white area for the main content
  - foot (48px): right-aligned Cancel + primary button on elevated surface
"""

from __future__ import annotations

import json
from typing import Iterable

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.services.models import SyncConflictInfo
from app.ui.gui.screens.file_view.models import FileEntry, _TREE_PATH_ROLE
from app.ui.gui.setup import (
    ButtonVariant,
    apply_button,
)
from app.ui.gui.setup import TOKENS


_EYEBROW_CSS = (
    'font-family: "IBM Plex Mono"; font-size: 10px;'
    " letter-spacing: 0.08em; color: #6B7383;"
)
_LEAD_CSS = (
    'font-family: "IBM Plex Sans"; font-size: 11px;'
    " color: #434C5E; line-height: 1.5;"
)
_INPUT_CSS = (
    "QLineEdit {"
    ' font-family: "IBM Plex Mono"; font-size: 11px;'
    " padding: 5px 8px; height: 30px;"
    " border: 1px solid #C0C9D6; border-radius: 4px;"
    " background: #FFFFFF;"
    "}"
    "QLineEdit:focus { border-color: #81A1C1; }"
)


class _BaseConfirmDialog(QDialog):
    """Common chrome for the four confirmation overlays.

    Layout: head strip (40px, elevated surface) + body (white, flexible) +
    foot strip (48px, elevated surface). Subclasses populate the body by
    calling ``self._root.addWidget(...)`` and add the foot by calling
    ``self._add_footer()``.
    """

    def __init__(
        self,
        title: str,
        *,
        icon_name: str | None = None,
        icon_danger: bool = False,
        size: tuple[int, int] = (520, 360),
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setModal(True)
        self.setWindowTitle(title)
        self.setFixedSize(*size)
        self.setWindowFlag(Qt.WindowType.FramelessWindowHint, True)
        self.setStyleSheet(
            "QDialog {"
            " background-color: #F4F6FA;"
            " border: 1px solid #B8C2D0;"
            " border-radius: 8px;"
            "}"
        )

        self._outer = QVBoxLayout(self)
        self._outer.setContentsMargins(0, 0, 0, 0)
        self._outer.setSpacing(0)

        # Head strip
        head = QFrame(self)
        head.setObjectName("CfConfirmHead")
        head.setFixedHeight(40)
        head.setStyleSheet(
            "QFrame#CfConfirmHead {"
            " background-color: #F8FAFC;"
            " border-bottom: 1px solid #C0C9D6;"
            "}"
        )
        head_layout = QHBoxLayout(head)
        head_layout.setContentsMargins(14, 0, 14, 0)
        head_layout.setSpacing(8)

        if icon_name:
            from app.ui.gui.setup.icons import tinted_icon
            icon_color = (
                TOKENS.colors.status_error_text if icon_danger else TOKENS.colors.focus_ring
            )
            icon_lbl = QLabel(head)
            icon_lbl.setPixmap(tinted_icon(icon_name, size=13, color=icon_color).pixmap(13, 13))
            icon_lbl.setFixedSize(15, 15)
            head_layout.addWidget(icon_lbl, 0, Qt.AlignmentFlag.AlignVCenter)

        title_lbl = QLabel(title, head)
        title_lbl.setStyleSheet(
            'font-family: "IBM Plex Sans"; font-size: 12px;'
            " font-weight: 700; color: #2E3440;"
        )
        head_layout.addWidget(title_lbl)
        head_layout.addStretch(1)
        self._outer.addWidget(head)

        # Body (white)
        body = QFrame(self)
        body.setObjectName("CfConfirmBody")
        body.setStyleSheet("QFrame#CfConfirmBody { background-color: #FFFFFF; border: none; }")
        self._root = QVBoxLayout(body)
        self._root.setContentsMargins(14, 14, 14, 12)
        self._root.setSpacing(10)
        self._outer.addWidget(body, 1)

    def _add_footer(
        self,
        primary_text: str,
        *,
        primary_variant: ButtonVariant = ButtonVariant.PRIMARY,
    ) -> QPushButton:
        foot = QFrame(self)
        foot.setObjectName("CfConfirmFoot")
        foot.setFixedHeight(48)
        foot.setStyleSheet(
            "QFrame#CfConfirmFoot {"
            " background-color: #F8FAFC;"
            " border-top: 1px solid #C0C9D6;"
            "}"
        )
        foot_layout = QHBoxLayout(foot)
        foot_layout.setContentsMargins(14, 0, 14, 0)
        foot_layout.setSpacing(8)
        foot_layout.addStretch(1)

        cancel = QPushButton("Cancel", foot)
        apply_button(cancel, ButtonVariant.GHOST)
        cancel.clicked.connect(self.reject)
        foot_layout.addWidget(cancel)

        primary = QPushButton(primary_text, foot)
        apply_button(primary, primary_variant)
        foot_layout.addWidget(primary)

        self._outer.addWidget(foot)
        return primary


class RestoreOverlay(_BaseConfirmDialog):
    """Destination folder picker + rename input + live preview."""

    def __init__(
        self,
        conflict: SyncConflictInfo,
        entries: Iterable[FileEntry],
        default_destination: str,
        *,
        default_name: str | None = None,
        title: str = "Restore from archive",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(
            title,
            icon_name="arrow-counter-clockwise",
            size=(560, 520),
            parent=parent,
        )
        self._conflict = conflict
        self._entries = list(entries)
        self._destination: str = default_destination or "/"

        # Destination tree
        dest_eyebrow = QLabel("DESTINATION FOLDER", self)
        dest_eyebrow.setStyleSheet(_EYEBROW_CSS)
        self._root.addWidget(dest_eyebrow)

        self._tree = QTreeWidget(self)
        self._tree.setHeaderHidden(True)
        self._tree.setIndentation(14)
        self._tree.setUniformRowHeights(True)
        self._tree.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._tree.setStyleSheet(
            "QTreeWidget { background: #F4F6FA; border: 1px solid #C0C9D6;"
            " border-radius: 4px; outline: none; }"
            "QTreeWidget::item {"
            ' font-family: "IBM Plex Mono"; font-size: 11px; padding: 3px 4px;'
            "}"
            "QTreeWidget::item:selected {"
            " background: #D8E4F0; color: #2E3440;"
            "}"
        )
        self._populate_tree()
        self._tree.itemSelectionChanged.connect(self._on_selection_changed)
        self._root.addWidget(self._tree, 1)

        # Rename input
        name_eyebrow = QLabel("NEW NAME  (blank = keep)", self)
        name_eyebrow.setStyleSheet(_EYEBROW_CSS)
        self._root.addWidget(name_eyebrow)

        self._name_input = QLineEdit(self)
        self._name_input.setPlaceholderText(conflict.archived_name)
        if default_name:
            self._name_input.setText(default_name)
        self._name_input.setStyleSheet(_INPUT_CSS)
        self._name_input.textChanged.connect(self._update_preview)
        self._root.addWidget(self._name_input)

        # Live preview
        preview_eyebrow = QLabel("PREVIEW", self)
        preview_eyebrow.setStyleSheet(_EYEBROW_CSS)
        self._root.addWidget(preview_eyebrow)

        self._preview = QLabel("", self)
        self._preview.setStyleSheet(
            'font-family: "IBM Plex Mono"; font-size: 11px; color: #2E3440;'
            " background-color: #F4F6FA; border: 1px solid #C0C9D6;"
            " border-radius: 4px; padding: 7px 10px;"
        )
        self._preview.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self._root.addWidget(self._preview)

        confirm = self._add_footer(
            "Restore" if title == "Restore from archive" else "Restore copy"
        )
        confirm.clicked.connect(self.accept)

        self._select_default()
        self._update_preview()

    def _populate_tree(self) -> None:
        path_to_item: dict[str, QTreeWidgetItem] = {}
        root_item = QTreeWidgetItem(["/"])
        root_item.setData(0, _TREE_PATH_ROLE, "/")
        self._tree.addTopLevelItem(root_item)
        path_to_item["/"] = root_item

        folder_entries = [e for e in self._entries if e.is_folder]
        for entry in folder_entries:
            item = QTreeWidgetItem([entry.name])
            item.setData(0, _TREE_PATH_ROLE, entry.path)
            path_to_item[entry.path] = item
        for entry in folder_entries:
            parent = path_to_item.get(entry.parent_path.rstrip("/") or "/")
            if parent is not None:
                parent.addChild(path_to_item[entry.path])
        self._tree.expandAll()

    def _select_default(self) -> None:
        target = self._destination or "/"
        item = self._find_item(target) or self._find_item("/")
        if item is not None:
            self._tree.setCurrentItem(item)

    def _find_item(self, path: str) -> QTreeWidgetItem | None:
        from PySide6.QtWidgets import QTreeWidgetItemIterator
        iterator = QTreeWidgetItemIterator(self._tree)
        while iterator.value():
            it = iterator.value()
            if it.data(0, _TREE_PATH_ROLE) == path:
                return it
            iterator += 1
        return None

    def _on_selection_changed(self) -> None:
        items = self._tree.selectedItems()
        if items:
            self._destination = items[0].data(0, _TREE_PATH_ROLE) or "/"
        self._update_preview()

    def _update_preview(self) -> None:
        name = self._name_input.text().strip() or self._conflict.archived_name
        dest = self._destination if self._destination.endswith("/") else self._destination + "/"
        if dest == "//":
            dest = "/"
        path = (dest + name).replace("//", "/")
        self._preview.setText(path)

    def destination_folder(self) -> str:
        return self._destination or "/"

    def new_name(self) -> str | None:
        text = self._name_input.text().strip()
        return text or None


class DeleteOverlay(_BaseConfirmDialog):
    """Type-DELETE confirmation overlay."""

    def __init__(
        self,
        conflict: SyncConflictInfo,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(
            "Delete archived item",
            icon_name="trash",
            icon_danger=True,
            size=(480, 280),
            parent=parent,
        )
        lead = QLabel(
            f"This permanently removes the archived copy of "
            f'"{conflict.archived_name}". '
            "The live entry, if any, is unaffected.",
            self,
        )
        lead.setWordWrap(True)
        lead.setStyleSheet(_LEAD_CSS)
        self._root.addWidget(lead)

        eyebrow = QLabel("TYPE DELETE TO CONFIRM", self)
        eyebrow.setStyleSheet(_EYEBROW_CSS)
        self._root.addWidget(eyebrow)

        self._input = QLineEdit(self)
        self._input.setPlaceholderText("DELETE")
        self._input.setStyleSheet(_INPUT_CSS)
        self._root.addWidget(self._input)

        confirm = self._add_footer("Delete archive", primary_variant=ButtonVariant.DANGER)
        confirm.setEnabled(False)
        confirm.clicked.connect(self.accept)
        self._input.textChanged.connect(
            lambda text: confirm.setEnabled(text.strip() == "DELETE")
        )


class AliasOverlay(_BaseConfirmDialog):
    """Single-input device alias editor."""

    def __init__(
        self,
        device_id: str,
        current_alias: str | None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(
            "Set global device alias",
            icon_name="user-circle",
            size=(480, 240),
            parent=parent,
        )
        lead = QLabel(
            f"Labels device <b>{device_id}</b> in future listings. "
            "Doesn't touch this conflict.",
            self,
        )
        lead.setWordWrap(True)
        lead.setTextFormat(Qt.TextFormat.RichText)
        lead.setStyleSheet(_LEAD_CSS)
        self._root.addWidget(lead)

        eyebrow = QLabel("ALIAS  (blank to clear)", self)
        eyebrow.setStyleSheet(_EYEBROW_CSS)
        self._root.addWidget(eyebrow)

        self._input = QLineEdit(self)
        if current_alias:
            self._input.setText(current_alias)
        self._input.setPlaceholderText("e.g. ahmed-laptop")
        self._input.setStyleSheet(_INPUT_CSS)
        self._root.addWidget(self._input)

        confirm = self._add_footer("Save alias")
        confirm.clicked.connect(self.accept)

    def alias(self) -> str | None:
        text = self._input.text().strip()
        return text or None


class InspectOverlay(_BaseConfirmDialog):
    """Read-only JSON viewer for the trigger event payload."""

    def __init__(
        self,
        payload: dict | None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(
            "Trigger event payload",
            icon_name="code",
            size=(640, 520),
            parent=parent,
        )
        viewer = QPlainTextEdit(self)
        viewer.setReadOnly(True)
        viewer.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        viewer.setFont(QFont("IBM Plex Mono", 10))
        viewer.setStyleSheet(
            "QPlainTextEdit {"
            " background-color: #F4F6FA; border: 1px solid #C0C9D6;"
            " border-radius: 4px; padding: 8px;"
            "}"
        )
        if payload is None:
            viewer.setPlainText(
                "Trigger event payload is unavailable.\n\n"
                "The event store may have been pruned, or the trigger "
                "event hash isn't recorded for this conflict."
            )
        else:
            viewer.setPlainText(json.dumps(payload, indent=2, sort_keys=False))
        self._root.addWidget(viewer, 1)

        foot = QFrame(self)
        foot.setObjectName("CfConfirmFoot")
        foot.setFixedHeight(48)
        foot.setStyleSheet(
            "QFrame#CfConfirmFoot {"
            " background-color: #F8FAFC;"
            " border-top: 1px solid #C0C9D6;"
            "}"
        )
        foot_layout = QHBoxLayout(foot)
        foot_layout.setContentsMargins(14, 0, 14, 0)
        foot_layout.addStretch(1)

        close = QPushButton("Close", foot)
        apply_button(close, ButtonVariant.GHOST)
        close.clicked.connect(self.accept)
        foot_layout.addWidget(close)

        self._outer.addWidget(foot)


__all__ = [
    "AliasOverlay",
    "DeleteOverlay",
    "InspectOverlay",
    "RestoreOverlay",
]
