"""Modal dialogs invoked from the file view: New folder, Rename, Move."""

from __future__ import annotations

from pathlib import PurePosixPath

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.ui.gui.setup import (
    TOKENS,
    ButtonVariant,
    Role,
    apply_button,
    apply_text_style,
    set_properties,
)
from app.ui.gui.setup.icons import IconLabel, tinted_icon

from .models import FileEntry, _TREE_PATH_ROLE


# The dialog widget itself is transparent (WA_TranslucentBackground) so the
# frameless window's rectangular corners don't peek out behind the rounded
# QSS background. The visible "panel" is an inner QFrame that paints the
# bg-colored rounded rectangle.
_MODAL_PANEL_STYLE = """
    #ModalPanel {
        background-color: #e5e9f0;
        border: 1px solid #434c5e;
        border-radius: 28px;
    }
"""


class CreateFolderDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setModal(True)
        self.setWindowTitle("New folder")
        self.setFixedSize(460, 240)
        self.setWindowFlag(Qt.WindowType.FramelessWindowHint, True)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self._build_ui()

    def _build_ui(self) -> None:
        self.setStyleSheet(_MODAL_PANEL_STYLE)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        panel = QFrame(self)
        panel.setObjectName("ModalPanel")
        outer.addWidget(panel)

        root = QVBoxLayout(panel)
        root.setContentsMargins(
            TOKENS.spacing.xxl,
            TOKENS.spacing.xxl,
            TOKENS.spacing.xxl,
            TOKENS.spacing.xxl,
        )
        root.setSpacing(TOKENS.spacing.xl)

        title = QLabel("New folder", panel)
        apply_text_style(title, TOKENS.typography.page_title)
        set_properties(title, role=Role.CREATE_FOLDER_TITLE)
        root.addWidget(title)

        self.name_input = QLineEdit(panel)
        self.name_input.setText("Untitled folder")
        self.name_input.setSelection(0, len(self.name_input.text()))
        self.name_input.setFixedHeight(60)
        set_properties(self.name_input, role=Role.CREATE_FOLDER_FIELD)
        root.addWidget(self.name_input)

        root.addStretch(1)

        actions = QHBoxLayout()
        actions.setContentsMargins(0, 0, 0, 0)
        actions.setSpacing(TOKENS.spacing.lg)
        actions.addStretch(1)

        cancel = QPushButton("Cancel", panel)
        apply_button(cancel, ButtonVariant.GHOST)
        cancel.clicked.connect(self.reject)
        actions.addWidget(cancel)

        create = QPushButton("Create", panel)
        apply_button(create, ButtonVariant.PRIMARY)
        create.clicked.connect(self.accept)
        actions.addWidget(create)
        root.addLayout(actions)

        self.name_input.returnPressed.connect(self.accept)

    def showEvent(self, event) -> None:  # type: ignore[override]
        super().showEvent(event)
        _center_on_parent(self)
        self.name_input.setFocus()
        self.name_input.selectAll()

    def folder_name(self) -> str:
        return self.name_input.text().strip()


class RenameDialog(QDialog):
    def __init__(self, current_name: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setModal(True)
        self.setWindowTitle("Rename")
        self.setFixedSize(460, 240)
        self.setWindowFlag(Qt.WindowType.FramelessWindowHint, True)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self._current_name = current_name
        path = PurePosixPath(current_name)
        self._stem = path.stem
        self._ext = path.suffix
        self._build_ui()

    def _build_ui(self) -> None:
        self.setStyleSheet(_MODAL_PANEL_STYLE)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        panel = QFrame(self)
        panel.setObjectName("ModalPanel")
        outer.addWidget(panel)

        root = QVBoxLayout(panel)
        root.setContentsMargins(
            TOKENS.spacing.xxl,
            TOKENS.spacing.xxl,
            TOKENS.spacing.xxl,
            TOKENS.spacing.xxl,
        )
        root.setSpacing(TOKENS.spacing.xl)

        title = QLabel("Rename", panel)
        apply_text_style(title, TOKENS.typography.page_title)
        set_properties(title, role=Role.CREATE_FOLDER_TITLE)
        root.addWidget(title)

        self.name_input = QLineEdit(panel)
        self.name_input.setText(self._current_name)
        self.name_input.setSelection(0, len(self.name_input.text()))
        self.name_input.setFixedHeight(60)
        set_properties(self.name_input, role=Role.CREATE_FOLDER_FIELD)
        root.addWidget(self.name_input)

        root.addStretch(1)

        actions = QHBoxLayout()
        actions.setContentsMargins(0, 0, 0, 0)
        actions.setSpacing(TOKENS.spacing.lg)
        actions.addStretch(1)

        cancel = QPushButton("Cancel", panel)
        apply_button(cancel, ButtonVariant.GHOST)
        cancel.clicked.connect(self.reject)
        actions.addWidget(cancel)

        rename_btn = QPushButton("Rename", panel)
        apply_button(rename_btn, ButtonVariant.PRIMARY)
        rename_btn.clicked.connect(self.accept)
        actions.addWidget(rename_btn)
        root.addLayout(actions)

        self.name_input.returnPressed.connect(self.accept)

    def showEvent(self, event) -> None:  # type: ignore[override]
        super().showEvent(event)
        _center_on_screen(self)
        self.name_input.setFocus()
        # Select only the stem so the user cannot accidentally edit the
        # extension. The extension is also re-applied in ``new_name`` if the
        # user manages to overwrite it.
        if self._ext:
            self.name_input.setSelection(0, len(self._stem))
        else:
            self.name_input.selectAll()

    def new_name(self) -> str:
        text = self.name_input.text().strip()
        if not self._ext:
            return text
        if text.endswith(self._ext):
            return text
        # User changed or removed the extension - restore the original.
        if "." in text and not text.startswith("."):
            text = text.rsplit(".", 1)[0]
        return text + self._ext


class MoveDialog(QDialog):
    def __init__(
        self,
        current_path: str,
        entries: list[FileEntry],
        vault_name: str,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setModal(True)
        self.setWindowTitle("Move")
        self.setFixedSize(560, 520)
        self.setWindowFlag(Qt.WindowType.FramelessWindowHint, True)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self._current_path = current_path
        self._entries = entries
        self._vault_name = vault_name
        self._selected_dest: str | None = None
        self._current_parent = (
            self._extract_parent(current_path)
            if current_path.startswith("/")
            else None
        )
        self._build_ui()

    @staticmethod
    def _extract_parent(path: str) -> str:
        clean = path.rstrip("/")
        if "/" in clean:
            parent = clean.rsplit("/", 1)[0]
            return parent if parent else "/"
        return "/"

    def _build_ui(self) -> None:
        self.setStyleSheet(self._local_qss())

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        panel = QFrame(self)
        panel.setObjectName("ModalPanel")
        outer.addWidget(panel)

        root = QVBoxLayout(panel)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        pad = TOKENS.spacing.xxl
        body = QVBoxLayout()
        body.setContentsMargins(pad, pad, pad, TOKENS.spacing.lg)
        body.setSpacing(TOKENS.spacing.lg)

        # ── header: title + close ──
        header = QHBoxLayout()
        header.setContentsMargins(0, 0, 0, 0)

        title = QLabel("Move", self)
        apply_text_style(title, TOKENS.typography.page_title)
        set_properties(title, role=Role.CREATE_FOLDER_TITLE)
        header.addWidget(title)
        header.addStretch(1)

        close_btn = QPushButton("×", self)
        close_btn.setObjectName("MoveCloseBtn")
        close_btn.setFixedSize(28, 28)
        close_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        close_btn.clicked.connect(self.reject)
        header.addWidget(close_btn)
        body.addLayout(header)

        # ── hint banner ──
        banner = QFrame(self)
        banner.setObjectName("MoveHintBanner")
        bl = QHBoxLayout(banner)
        bl.setContentsMargins(14, 10, 14, 10)
        bl.setSpacing(10)
        bl.addWidget(
            IconLabel(
                "arrows-out-cardinal",
                size=16,
                color=QColor("#5e81ac"),
                parent=banner,
            )
        )
        hint = QLabel(
            f'Select destination for "{self._current_path}"', self
        )
        hint.setObjectName("MoveHintText")
        hint.setWordWrap(True)
        bl.addWidget(hint, 1)
        body.addWidget(banner)

        # ── filter field ──
        search_frame = QFrame(self)
        search_frame.setObjectName("MoveSearchFrame")
        sl = QHBoxLayout(search_frame)
        sl.setContentsMargins(12, 0, 12, 0)
        sl.setSpacing(8)
        sl.addWidget(
            IconLabel(
                "magnifying-glass",
                size=14,
                color=QColor("#858c9b"),
                parent=search_frame,
            )
        )
        self._filter_input = QLineEdit(self)
        self._filter_input.setPlaceholderText("Filter folders…")
        self._filter_input.setObjectName("MoveFilterInput")
        self._filter_input.textChanged.connect(self._apply_filter)
        sl.addWidget(self._filter_input, 1)
        body.addWidget(search_frame)

        # ── folder tree ──
        self.tree = QTreeWidget(self)
        self.tree.setColumnCount(2)
        self.tree.setHeaderHidden(True)
        self.tree.setRootIsDecorated(True)
        self.tree.setIndentation(20)
        self.tree.setUniformRowHeights(True)
        self.tree.setAnimated(False)
        self.tree.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.tree.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection
        )
        self.tree.setProperty("showDropIndicator", False)
        set_properties(self.tree, role=Role.FILE_TREE)

        self._populate_tree()
        self.tree.itemSelectionChanged.connect(self._on_selection_changed)

        hdr = self.tree.header()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)

        body.addWidget(self.tree, 1)
        root.addLayout(body, 1)

        # __ footer separator __
        sep = QFrame(self)
        sep.setObjectName("MoveFooterSep")
        sep.setFixedHeight(1)
        root.addWidget(sep)

        # __ footer __
        footer = QHBoxLayout()
        footer.setContentsMargins(pad, TOKENS.spacing.lg, pad, pad)
        footer.setSpacing(TOKENS.spacing.lg)

        dest_block = QVBoxLayout()
        dest_block.setSpacing(2)
        lbl = QLabel("DESTINATION", self)
        lbl.setObjectName("MoveDestLabel")
        dest_block.addWidget(lbl)
        self._dest_path_label = QLabel("-", self)
        self._dest_path_label.setObjectName("MoveDestPath")
        dest_block.addWidget(self._dest_path_label)
        footer.addLayout(dest_block)

        footer.addStretch(1)

        cancel = QPushButton("Cancel", self)
        apply_button(cancel, ButtonVariant.GHOST)
        cancel.clicked.connect(self.reject)
        footer.addWidget(cancel)

        self.ok_btn = QPushButton("Move here", self)
        apply_button(self.ok_btn, ButtonVariant.PRIMARY)
        self.ok_btn.clicked.connect(self._on_ok_clicked)
        self.ok_btn.setEnabled(False)
        footer.addWidget(self.ok_btn)

        root.addLayout(footer)

    @staticmethod
    def _local_qss() -> str:
        return """
            #ModalPanel {
                background-color: #e5e9f0;
                border: 1px solid #434c5e;
                border-radius: 28px;
            }
            #MoveCloseBtn {
                background: transparent;
                border: none;
                color: #858c9b;
                font-size: 18px;
                font-weight: bold;
                border-radius: 14px;
            }
            #MoveCloseBtn:hover {
                background-color: #d8dee9;
                color: #2e3440;
            }
            #MoveHintBanner {
                background-color: rgba(94, 129, 172, 0.12);
                border-radius: 8px;
            }
            #MoveHintText {
                color: #4c566a;
                font-size: 13px;
                font-family: "IBM Plex Sans";
            }
            #MoveSearchFrame {
                background-color: #ffffff;
                border: 1px solid #c0c9d6;
                border-radius: 8px;
                min-height: 36px;
                max-height: 36px;
            }
            #MoveFilterInput {
                background: transparent;
                border: none;
                color: #2e3440;
                font-size: 13px;
                font-family: "IBM Plex Sans";
            }
            #MoveFooterSep {
                background-color: #c0c9d6;
                border: none;
            }
            #MoveDestLabel {
                color: #858c9b;
                font-size: 10px;
                font-weight: 600;
                letter-spacing: 1px;
                font-family: "IBM Plex Sans";
            }
            #MoveDestPath {
                color: #4c566a;
                font-size: 13px;
                font-family: "IBM Plex Sans";
            }
        """

    def _populate_tree(self) -> None:
        folder_entries = [e for e in self._entries if e.is_folder]
        path_to_item: dict[str, QTreeWidgetItem] = {}

        muted = QColor("#858c9b")
        folder_icon = tinted_icon("folder", size=16, color=muted)
        current_font = QFont("IBM Plex Sans", 10)

        root_item = QTreeWidgetItem(["/"])
        root_item.setData(0, _TREE_PATH_ROLE, "/")
        root_item.setIcon(0, folder_icon)
        self.tree.addTopLevelItem(root_item)
        path_to_item["/"] = root_item

        if self._current_parent == "/":
            root_item.setText(1, "CURRENT")
            root_item.setFont(1, current_font)
            root_item.setForeground(1, muted)
            root_item.setFlags(
                root_item.flags() & ~Qt.ItemFlag.ItemIsSelectable
            )

        for entry in folder_entries:
            item = QTreeWidgetItem([entry.name])
            item.setData(0, _TREE_PATH_ROLE, entry.path)
            item.setIcon(0, folder_icon)
            path_to_item[entry.path] = item

            if (
                self._current_parent is not None
                and entry.path == self._current_parent
            ):
                item.setText(1, "CURRENT")
                item.setFont(1, current_font)
                item.setForeground(1, muted)
                item.setFlags(
                    item.flags() & ~Qt.ItemFlag.ItemIsSelectable
                )

        for entry in folder_entries:
            parent_path = entry.parent_path.rstrip("/") or "/"
            parent_item = path_to_item.get(parent_path)
            if parent_item is not None:
                parent_item.addChild(path_to_item[entry.path])

        self.tree.expandAll()

    def _on_selection_changed(self) -> None:
        selected = self.tree.selectedItems()
        if selected:
            dest = selected[0].data(0, _TREE_PATH_ROLE)
            self._selected_dest = dest
            self.ok_btn.setEnabled(True)
            display = dest if dest.endswith("/") else dest + "/"
            self._dest_path_label.setText(display)
        else:
            self._selected_dest = None
            self.ok_btn.setEnabled(False)
            self._dest_path_label.setText("-")

    def _apply_filter(self, text: str) -> None:
        text = text.strip().lower()
        root = self.tree.topLevelItem(0)
        if root is None:
            return
        if not text:
            self._set_all_visible(root)
            self.tree.expandAll()
        else:
            self._filter_recursive(root, text)

    def _set_all_visible(self, item: QTreeWidgetItem) -> None:
        item.setHidden(False)
        for i in range(item.childCount()):
            self._set_all_visible(item.child(i))

    def _filter_recursive(
        self, item: QTreeWidgetItem, text: str
    ) -> bool:
        matches = text in item.text(0).lower()
        child_visible = False
        for i in range(item.childCount()):
            if self._filter_recursive(item.child(i), text):
                child_visible = True
        visible = matches or child_visible
        item.setHidden(not visible)
        if visible:
            item.setExpanded(True)
        return visible

    def _on_ok_clicked(self) -> None:
        if self._selected_dest is not None:
            self.accept()

    def showEvent(self, event) -> None:  # type: ignore[override]
        super().showEvent(event)
        _center_on_screen(self)

    @property
    def destination_path(self) -> str | None:
        return self._selected_dest


def _center_on_parent(dialog: QDialog) -> None:
    """Move ``dialog`` so it centers on its parent widget's frame, if any."""
    parent = dialog.parentWidget()
    if parent is None:
        return
    geometry = parent.frameGeometry()
    dialog.move(
        geometry.center().x() - dialog.width() // 2,
        geometry.center().y() - dialog.height() // 2,
    )


def _center_on_screen(dialog: QDialog) -> None:
    """Move ``dialog`` so it centers on the screen."""
    parent = dialog.parentWidget()
    screen = (
        parent.screen() if parent is not None else QApplication.primaryScreen()
    )
    if screen is None:
        return
    geo = screen.availableGeometry()
    dialog.move(
        geo.center().x() - dialog.width() // 2,
        geo.center().y() - dialog.height() // 2,
    )
