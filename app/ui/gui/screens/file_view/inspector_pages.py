"""Factory functions that construct the two inspector-panel pages.

The file-view inspector is a narrow right-hand sidebar with two distinct
pages, each built once at screen construction time and shown/hidden via the
tab bar above:

``build_properties_page``
    Builds the *File Properties* page.  The outer panel wraps a
    ``QScrollArea`` so long property lists remain accessible.  Inside, a
    ``QStackedLayout`` switches between an empty-state placeholder (shown
    when nothing is selected) and a content page that holds:

    * A filename header row (tinted icon + bold ``QLabel``).
    * A row of four action icon-buttons: open, export, lock, delete.
    * A dynamically populated key/value grid (``properties_rows_frame``).
    * A 340 px fixed-height preview box with its own ``QStackedLayout``
      toggling between a ``QTextEdit`` snippet and a centred empty state.

    Widgets that need to be updated at selection-change time are attached
    directly to ``screen`` as named attributes (e.g.
    ``screen.properties_name``, ``screen.properties_preview``).

``build_unlocked_page``
    Builds the *Unlocked Files* page - a scrollable list of cards for
    files currently exported/unlocked outside the vault.  The scroll area
    (``screen.unlocked_scroll``) and its inner layout
    (``screen.unlocked_layout``) are stored on ``screen`` so the inspector
    controller can add and remove cards without touching this module.

Both functions receive the owning ``FileViewScreen`` instance so they can
set attributes on it, and a ``parent`` widget to use as the Qt parent for
top-level frames.  They return the outermost widget ready to be inserted
into the inspector's page stack.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QSize, Qt
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QStackedLayout,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app.ui.gui.setup import TOKENS, apply_text_style, load_icon

from .helpers import ElidedLabel, css, force_wrap, tinted_icon

if TYPE_CHECKING:
    from .screen import FileViewScreen


def build_properties_page(
    screen: "FileViewScreen", parent: QWidget
) -> QWidget:
    c = TOKENS.colors

    # Outer panel - fixed #eceff4 background. A QStackedLayout switches
    # between an empty placeholder (no widgets visible besides a centred
    # label) and the full content page once a file/folder is selected.
    properties_page = QFrame(parent)
    properties_page.setObjectName("propertiesPanel")
    properties_page.setStyleSheet(
        "#propertiesPanel { background-color: #eceff4; }"
    )
    properties_page.setMinimumHeight(300)

    pp_scroll = QScrollArea(parent)
    pp_scroll.setWidgetResizable(True)
    pp_scroll.setFrameShape(QFrame.Shape.NoFrame)
    pp_scroll.setStyleSheet(
        "QScrollArea { background: transparent; border: none; }"
    )
    pp_scroll.setWidget(properties_page)

    eyebrow_css = (
        f'font-family: "IBM Plex Mono"; font-size: 10px; '
        f"color: {css(c.text_muted)}; letter-spacing: 0.06em;"
    )

    page_stack = QStackedLayout(properties_page)
    page_stack.setContentsMargins(0, 0, 0, 0)
    page_stack.setSpacing(0)
    screen._properties_page_stack = page_stack

    # Empty state - only a centred label in the FILE PROPERTIES shade.
    empty_widget = QWidget(properties_page)
    empty_widget.setStyleSheet("background: transparent;")
    placeholder_layout = QVBoxLayout(empty_widget)
    placeholder_layout.setContentsMargins(16, 16, 16, 16)
    placeholder_layout.addStretch(1)
    screen.properties_empty_label = QLabel(
        "select a file to view its properties", empty_widget
    )
    screen.properties_empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
    screen.properties_empty_label.setStyleSheet(
        f'font-family: "IBM Plex Sans"; font-size: 13px; '
        f"color: {css(c.text_muted)}; background: transparent;"
    )
    placeholder_layout.addWidget(screen.properties_empty_label)
    placeholder_layout.addStretch(1)
    page_stack.addWidget(empty_widget)

    # Content page - populated by inspector.update_selection().
    content_widget = QWidget(properties_page)
    content_widget.setStyleSheet("background: transparent;")
    pp_layout = QVBoxLayout(content_widget)
    pp_layout.setContentsMargins(16, 16, 16, 16)
    pp_layout.setSpacing(10)

    screen.properties_eyebrow = QLabel("FILE PROPERTIES", content_widget)
    screen.properties_eyebrow.setStyleSheet(eyebrow_css)
    pp_layout.addWidget(screen.properties_eyebrow)

    # Filename row (lock/file icon + bold name).
    header_row = QHBoxLayout()
    header_row.setContentsMargins(0, 0, 0, 0)
    header_row.setSpacing(8)
    screen.properties_icon = QLabel(content_widget)
    screen.properties_icon.setFixedSize(20, 20)
    header_row.addWidget(
        screen.properties_icon, 0, Qt.AlignmentFlag.AlignVCenter
    )
    # Wrapping QLabel - paired with force_wrap() at set-time so even
    # filenames with no whitespace (URLs, snake/kebab/camel-case) can break
    # onto multiple lines instead of pushing the inspector wider than 300px.
    screen.properties_name = QLabel("", content_widget)
    screen.properties_name.setStyleSheet(
        f'font-family: "IBM Plex Sans"; font-size: 13px; '
        f"font-weight: 700; color: {css(c.text_primary)}; "
        "background: transparent;"
    )
    screen.properties_name.setAlignment(Qt.AlignmentFlag.AlignLeft)
    screen.properties_name.setMinimumWidth(0)
    screen.properties_name.setWordWrap(True)
    header_row.addWidget(screen.properties_name, 1)
    pp_layout.addLayout(header_row)

    # Action icons (open file, export, lock, delete).
    actions_row = QHBoxLayout()
    actions_row.setContentsMargins(0, 0, 0, 0)
    actions_row.setSpacing(4)
    for icon_name, tooltip, attr, slot in (
        (
            "arrow-square-out",
            "Open file",
            "properties_open_button",
            screen._open_selected_file,
        ),
        (
            "download-simple",
            "Export",
            "properties_export_button",
            screen._export_selected_from_properties,
        ),
        (
            "lock-simple",
            "Lock",
            "properties_lock_button",
            screen._lock_selected_from_properties,
        ),
        (
            "trash",
            "Delete",
            "properties_delete_button",
            screen._request_delete,
        ),
    ):
        btn = QPushButton(content_widget)
        btn.setObjectName("InspectorActionIcon")
        btn.setFixedSize(28, 28)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.setFlat(True)
        ic_color = (
            c.status_error_text
            if icon_name == "trash"
            else c.text_secondary
        )
        btn.setIcon(tinted_icon(icon_name, size=14, color=ic_color))
        btn.setIconSize(QSize(14, 14))
        btn.setToolTip(tooltip)
        btn.setStyleSheet(f"""
            QPushButton#InspectorActionIcon {{
                background-color: {css(c.bg_base)};
                border: 1px solid {css(c.border_soft)};
                border-radius: 4px;
                padding: 0;
                min-width: 28px;
                max-width: 28px;
                min-height: 28px;
                max-height: 28px;
            }}
            QPushButton#InspectorActionIcon:hover {{
                background-color: {css(c.bg_elevated)};
                border-color: {css(c.border_default)};
            }}
            QPushButton#InspectorActionIcon:disabled {{
                background-color: {css(c.bg_base)};
                border-color: {css(c.border_soft)};
            }}
        """)
        btn.clicked.connect(slot)
        setattr(screen, attr, btn)
        actions_row.addWidget(btn)
    actions_row.addStretch(1)
    pp_layout.addLayout(actions_row)

    # Property key/value grid (filled by _rebuild_property_rows).
    screen.properties_rows_frame = QFrame(content_widget)
    screen.properties_rows_frame.setStyleSheet("background: transparent;")
    screen.properties_rows_layout = QVBoxLayout(screen.properties_rows_frame)
    screen.properties_rows_layout.setContentsMargins(0, 0, 0, 0)
    screen.properties_rows_layout.setSpacing(8)
    pp_layout.addWidget(screen.properties_rows_frame)

    divider = QFrame(content_widget)
    divider.setFixedHeight(1)
    divider.setStyleSheet(f"background-color: {css(c.border_soft)};")
    pp_layout.addWidget(divider)

    screen.preview_eyebrow = QLabel("TEXT PREVIEW", content_widget)
    screen.preview_eyebrow.setStyleSheet(eyebrow_css)
    pp_layout.addWidget(screen.preview_eyebrow)

    preview_box = QFrame(content_widget)
    preview_box.setObjectName("PreviewBox")
    preview_box.setFixedHeight(340)
    preview_box.setStyleSheet(f"""
        QFrame#PreviewBox {{
            background-color: {css(c.bg_elevated)};
            border: 1px solid {css(c.border_soft)};
            border-radius: 6px;
        }}
    """)
    preview_box_layout = QStackedLayout(preview_box)
    preview_box_layout.setContentsMargins(0, 0, 0, 0)
    preview_box_layout.setSpacing(0)
    screen._preview_box_layout = preview_box_layout

    screen.properties_preview = QTextEdit(content_widget)
    screen.properties_preview.setObjectName("filePreviewSnippet")
    screen.properties_preview.setReadOnly(True)
    screen.properties_preview.setFrameShape(QFrame.Shape.NoFrame)
    screen.properties_preview.setStyleSheet(f"""
        QTextEdit#filePreviewSnippet {{
            background-color: transparent;
            border: none;
            font-family: "IBM Plex Sans";
            font-size: 11px;
            color: {css(c.text_secondary)};
            padding: 10px 12px;
        }}
    """)
    preview_box_layout.addWidget(screen.properties_preview)

    screen.preview_empty_state = QWidget(preview_box)
    screen.preview_empty_state.setObjectName("PreviewEmptyState")
    screen.preview_empty_state.setStyleSheet("""
        QWidget#PreviewEmptyState {
            background-color: transparent;
        }
    """)
    empty_layout = QVBoxLayout(screen.preview_empty_state)
    empty_layout.setContentsMargins(0, 0, 0, 0)
    empty_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
    empty_icon_label = QLabel(screen.preview_empty_state)
    empty_icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
    empty_icon_label.setPixmap(
        load_icon("file-text.svg").pixmap(32, 32)
    )
    empty_layout.addWidget(empty_icon_label)
    screen.preview_empty_text = QLabel(
        "Select a file or folder to see details", screen.preview_empty_state
    )
    screen.preview_empty_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
    apply_text_style(screen.preview_empty_text, TOKENS.typography.caption)
    empty_layout.addWidget(screen.preview_empty_text)
    preview_box_layout.addWidget(screen.preview_empty_state)
    preview_box_layout.setCurrentIndex(1)

    pp_layout.addWidget(preview_box)

    page_stack.addWidget(content_widget)
    page_stack.setCurrentIndex(0)
    return pp_scroll


def build_unlocked_page(
    screen: "FileViewScreen", parent: QWidget
) -> QWidget:
    c = TOKENS.colors
    unlocked_page = QFrame(parent)
    unlocked_page.setObjectName("unlockedFilesArea")
    unlocked_page.setStyleSheet(
        "#unlockedFilesArea { background-color: #eceff4; }"
    )
    up_layout = QVBoxLayout(unlocked_page)
    up_layout.setContentsMargins(16, 16, 16, 16)
    up_layout.setSpacing(12)

    up_header = QLabel("Unlocked files", unlocked_page)
    up_header.setStyleSheet(
        f'font-family: "IBM Plex Sans"; font-size: 13px; '
        f"font-weight: 700; color: {css(c.text_primary)}; "
        "background: transparent;"
    )
    up_layout.addWidget(up_header)

    screen.unlocked_scroll = QScrollArea(unlocked_page)
    screen.unlocked_scroll.setWidgetResizable(True)
    screen.unlocked_scroll.setFrameShape(QFrame.Shape.NoFrame)
    screen.unlocked_scroll.setStyleSheet("background: transparent;")
    screen.unlocked_scroll.viewport().setStyleSheet("background: transparent;")
    screen.unlocked_content = QWidget(screen.unlocked_scroll)
    screen.unlocked_content.setStyleSheet("background: transparent;")
    screen.unlocked_layout = QVBoxLayout(screen.unlocked_content)
    screen.unlocked_layout.setSpacing(8)
    screen.unlocked_layout.setContentsMargins(0, 0, 0, 0)
    screen.unlocked_scroll.setWidget(screen.unlocked_content)
    # stretch=1 so the scroll area expands to fill the remaining panel height
    # rather than collapsing to its default sizeHint (which is nearly zero
    # when the content is empty and would hide all cards added later).
    up_layout.addWidget(screen.unlocked_scroll, 1)
    return unlocked_page
