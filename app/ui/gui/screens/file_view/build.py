"""UI builders for :class:`FileViewScreen`. Each ``build_*`` function takes
the screen and assigns the section's child widgets as attributes on it"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QSizePolicy,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from app.ui.gui.setup import TOKENS, Role, set_properties

from . import inspector_pages
from .helpers import css
from .widgets import (
    ImportDropTableWidget,
    InspectorTab,
    ToolButton,
)

if TYPE_CHECKING:
    from .screen import FileViewScreen


def build_ui(screen: "FileViewScreen") -> None:
    """Top-level builder that assembles the center panel + inspector and stores
    references on the screen instance."""
    set_properties(screen, role=Role.FILE_VIEW)

    root = QHBoxLayout(screen)
    root.setContentsMargins(0, 0, 0, 0)
    root.setSpacing(0)
    root.addWidget(_build_center_panel(screen), 1)
    root.addWidget(_build_inspector_panel(screen))


def _build_center_panel(screen: "FileViewScreen") -> QWidget:
    panel = QFrame(screen)
    panel.setObjectName("FileViewCenterPanel")
    panel_layout = QVBoxLayout(panel)
    panel_layout.setContentsMargins(0, 0, 0, 0)
    panel_layout.setSpacing(0)

    panel_layout.addWidget(_build_action_toolbar(screen, panel))
    panel_layout.addWidget(_build_file_table(screen, panel), 1)
    return panel


def _build_action_toolbar(screen: "FileViewScreen", parent: QWidget) -> QWidget:
    c = TOKENS.colors
    toolbar = QFrame(parent)
    toolbar.setObjectName("FileViewToolbar")
    toolbar.setFixedHeight(44)
    layout = QHBoxLayout(toolbar)
    layout.setContentsMargins(16, 0, 16, 0)
    layout.setSpacing(4)

    _V = Qt.AlignmentFlag.AlignVCenter

    screen.import_button = ToolButton("file-arrow-down", "Import", parent=toolbar)
    screen.import_button.clicked.connect(screen._request_import)
    layout.addWidget(screen.import_button, 0, _V)

    screen.export_button = ToolButton("export", "Export", parent=toolbar)
    screen.export_button.setEnabled(False)
    screen.export_button.clicked.connect(
        lambda: screen.export_requested.emit(screen._selected_table_paths())
    )
    layout.addWidget(screen.export_button, 0, _V)

    sep = QFrame(toolbar)
    sep.setFixedSize(1, 18)
    sep.setStyleSheet(f"background-color: {css(c.border_soft)};")
    layout.addWidget(sep, 0, _V)

    screen.copy_button = ToolButton("copy", "Copy", parent=toolbar)
    screen.copy_button.setEnabled(False)
    screen.copy_button.clicked.connect(
        lambda: screen._on_copy(screen._selected_table_paths())
    )
    layout.addWidget(screen.copy_button, 0, _V)

    screen.paste_button = ToolButton("clipboard", "Paste", parent=toolbar)
    screen.paste_button.setEnabled(False)
    screen.paste_button.clicked.connect(screen._on_paste)
    layout.addWidget(screen.paste_button, 0, _V)

    screen.create_folder_button = ToolButton(
        "folder-plus", "New folder", parent=toolbar
    )
    screen.create_folder_button.clicked.connect(screen._prompt_create_folder)
    layout.addWidget(screen.create_folder_button, 0, _V)

    screen.rename_button = ToolButton("pencil-simple", "Rename", parent=toolbar)
    screen.rename_button.setEnabled(False)
    screen.rename_button.clicked.connect(screen._prompt_rename)
    layout.addWidget(screen.rename_button, 0, _V)

    screen.move_button = ToolButton("arrows-out-cardinal", "Move", parent=toolbar)
    screen.move_button.setEnabled(False)
    screen.move_button.clicked.connect(screen._prompt_move)
    layout.addWidget(screen.move_button, 0, _V)

    screen.delete_button = ToolButton(
        "trash", "Delete", icon_color=c.status_error_text, parent=toolbar
    )
    screen.delete_button.setEnabled(False)
    screen.delete_button.clicked.connect(screen._request_delete)
    layout.addWidget(screen.delete_button, 0, _V)

    layout.addStretch(1)

    screen.items_count_label = QLabel("0 items", toolbar)
    screen.items_count_label.setStyleSheet(
        f'font-family: "IBM Plex Mono"; font-size: 11px; color: {css(c.text_muted)};'
    )
    layout.addWidget(screen.items_count_label, 0, _V)
    return toolbar


def _build_file_table(screen: "FileViewScreen", parent: QWidget) -> QWidget:
    screen.table = ImportDropTableWidget(0, 3, parent)
    screen.table.setHorizontalHeaderLabels(["NAME", "TYPE", "MODIFIED"])
    screen.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    screen.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
    screen.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    screen.table.setShowGrid(False)
    screen.table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
    screen.table.verticalHeader().setVisible(False)
    screen.table.verticalHeader().setDefaultSectionSize(36)
    screen.table.setAlternatingRowColors(False)
    header = screen.table.horizontalHeader()
    header.setStretchLastSection(False)
    header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
    header.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
    header.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
    screen.table.setColumnWidth(1, 90)
    screen.table.setColumnWidth(2, 130)
    header.setFixedHeight(30)
    screen.table.horizontalHeaderItem(1).setTextAlignment(
        Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignVCenter
    )
    screen.table.horizontalHeaderItem(2).setTextAlignment(
        Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignVCenter
    )
    set_properties(screen.table, role=Role.FILE_TABLE)
    # Header / table styling lives in section_shell.py via the file-table
    # role selector; no inline stylesheet here.
    screen.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
    screen.table.itemSelectionChanged.connect(screen._sync_selected_file_from_table)
    screen.table.itemDoubleClicked.connect(screen._activate_selected_table_item)
    screen.table.paths_dropped.connect(screen._handle_dropped_paths)
    screen.table.customContextMenuRequested.connect(screen._show_table_context_menu)
    return screen.table


def _build_inspector_panel(screen: "FileViewScreen") -> QWidget:
    panel = QFrame(screen)
    panel.setObjectName("FileViewInspector")
    # 380px gives the property key/value rows enough room for typical
    # values (timestamps, full paths, MIME types) without truncating mid
    # word. The 330px the design originally used was tuned against short
    # demo data.
    panel.setFixedWidth(380)
    panel.setSizePolicy(
        QSizePolicy.Policy.Preferred, QSizePolicy.Policy.MinimumExpanding
    )

    panel_layout = QVBoxLayout(panel)
    panel_layout.setContentsMargins(0, 0, 0, 0)
    panel_layout.setSpacing(0)

    # Tabs row - segmented buttons centered, separator below.
    tabs_row = QFrame(panel)
    tabs_row.setObjectName("FileViewInspectorTabs")
    tabs_row.setFixedHeight(40)
    tabs_row.setStyleSheet(f"""
        QFrame#FileViewInspectorTabs {{
            background-color: transparent;
            border-bottom: 1px solid {css(TOKENS.palette.nord4)};
        }}
    """)
    tabs_layout = QHBoxLayout(tabs_row)
    tabs_layout.setContentsMargins(8, 0, 8, 0)
    tabs_layout.setSpacing(4)
    tabs_layout.addStretch(1)
    screen.properties_tab = InspectorTab("Properties", parent=tabs_row)
    screen.properties_tab.clicked.connect(lambda: screen._set_active_tab("properties"))
    tabs_layout.addWidget(screen.properties_tab)
    screen.unlocked_tab = InspectorTab("Unlocked", count=0, parent=tabs_row)
    screen.unlocked_tab.clicked.connect(lambda: screen._set_active_tab("unlocked"))
    tabs_layout.addWidget(screen.unlocked_tab)
    tabs_layout.addStretch(1)
    panel_layout.addWidget(tabs_row)

    screen.inspector_stack = QStackedWidget(panel)
    panel_layout.addWidget(screen.inspector_stack, 1)

    # Properties + Unlocked pages - built in _inspector_pages so this file
    # stays under the per-file line cap.
    screen.inspector_stack.addWidget(
        inspector_pages.build_properties_page(screen, panel)
    )
    screen.inspector_stack.addWidget(inspector_pages.build_unlocked_page(screen, panel))
    return panel
