"""Shell-level QSS. surface tones, sidebar pill items, search bar shape,
toolbar buttons, table, inspector, status footer.

Appended LAST in build_stylesheet so its object-name selectors override
earlier section rules. Targets only chrome surfaces; per-screen rules
under section_screens / section_file_view continue to drive content."""

from __future__ import annotations

from pathlib import Path

from .helpers import StyleCtx

# Absolute forward-slash paths to the muted-fill caret SVGs used for the
# sidebar tree's expand/collapse branch indicators.  The muted SVGs are
# pre-tinted (#6B7383) because QSS `image: url()` cannot recolour SVGs at
# runtime the way tinted_icon() does.
_ICONS = Path(__file__).resolve().parent.parent.parent / "assets" / "icons" / "ph-icons"
_CARET_RIGHT = str(_ICONS / "caret-right-muted.svg").replace("\\", "/")
_CARET_DOWN = str(_ICONS / "caret-down-muted.svg").replace("\\", "/")


# surface tones (light theme, Nord-aligned):
#   #ECEFF4 - sidebar / topbar / status footer / breadcrumbs / inspector
#   #FFFFFF - content area + file table (the ONE white surface)
#   #C0C9D6 - 1px panel borders (must remain visible against both #ECEFF4
#             and #FFFFFF; #D8DEE9 was indistinguishable from the chrome)
#   #5E81AC - accent (focus ring, selected pill)
SURFACE_CHROME = "#ECEFF4"
SURFACE_CONTENT = "#FFFFFF"
SURFACE_HOVER = "#E5E9F0"
SURFACE_SELECTED = "#D8DEE9"
BORDER_SOFT = "#C0C9D6"
TEXT_PRIMARY = "#2E3440"
TEXT_MUTED = "#6B7383"
ACCENT = "#5E81AC"


def build(ctx: StyleCtx) -> str:
    return f"""
/* ------ Shell surfaces ------ */

QMainWindow {{
    background-color: {SURFACE_CHROME};
}}

QWidget#AppShell {{
    background-color: {SURFACE_CHROME};
}}

QWidget#TopBar {{
    background-color: {SURFACE_CHROME};
    border-bottom: 1px solid {BORDER_SOFT};
}}

QWidget#BreadcrumbsBar {{
    background-color: {SURFACE_CONTENT};
    border-bottom: 1px solid {BORDER_SOFT};
}}

QWidget#VaultTreePanel {{
    background-color: {SURFACE_CHROME};
    border-right: 1px solid {BORDER_SOFT};
}}

QFrame#VaultTreeContainer {{
    background-color: {SURFACE_CHROME};
    border: none;
}}

QFrame#FileViewCenterPanel {{
    background-color: {SURFACE_CONTENT};
    border-right: 1px solid {BORDER_SOFT};
}}

QFrame#FileViewToolbar {{
    background-color: {SURFACE_CONTENT};
    border-bottom: 1px solid {BORDER_SOFT};
}}

QFrame#FileViewInspector {{
    background-color: {SURFACE_CHROME};
    border-left: 1px solid {BORDER_SOFT};
}}

QWidget#StatusFooter {{
    background-color: {SURFACE_CHROME};
    border-top: 1px solid {BORDER_SOFT};
}}

/* ------ Sidebar tree (vault root + folder list) ------ */

QTreeWidget[role="file-tree"] {{
    background: transparent;
    border: none;
    outline: none;
    font-family: "IBM Plex Sans";
    font-size: 13px;
    color: {TEXT_MUTED};
    show-decoration-selected: 1;
}}

QTreeWidget[role="file-tree"]::item {{
    padding: 4px 8px;
    color: {TEXT_MUTED};
}}

QTreeWidget[role="file-tree"]::item:hover {{
    background-color: {SURFACE_HOVER};
    color: {TEXT_PRIMARY};
}}

QTreeWidget[role="file-tree"]::item:selected {{
    background-color: {SURFACE_SELECTED};
    color: {TEXT_PRIMARY};
}}

QTreeWidget[role="file-tree"]::item:selected:!active {{
    background-color: {SURFACE_SELECTED};
    color: {TEXT_PRIMARY};
}}

/* Branch indicators - caret-right (collapsed) / caret-down (expanded).
   Pre-tinted muted-gray SVGs are used because QSS url() cannot recolour
   SVGs at runtime. */
QTreeWidget[role="file-tree"]::branch:has-children:!has-siblings:closed,
QTreeWidget[role="file-tree"]::branch:closed:has-children:has-siblings {{
    border-image: none;
    image: url({_CARET_RIGHT});
}}
QTreeWidget[role="file-tree"]::branch:open:has-children:!has-siblings,
QTreeWidget[role="file-tree"]::branch:open:has-children:has-siblings {{
    border-image: none;
    image: url({_CARET_DOWN});
}}

/* ------ Search input ------ */

QLineEdit#TopBarSearch {{
    background-color: {SURFACE_CONTENT};
    border: 1px solid {BORDER_SOFT};
    border-radius: 8px;
    padding: 0 12px;
    font-family: "IBM Plex Sans";
    font-size: 12px;
    color: {TEXT_PRIMARY};
    selection-background-color: {ACCENT};
    selection-color: white;
}}

QLineEdit#TopBarSearch:focus {{
    border: 1px solid {ACCENT};
}}

QLabel#TopBarSearchHint {{
    background-color: {SURFACE_HOVER};
    color: {TEXT_MUTED};
    font-family: "IBM Plex Mono";
    font-size: 10px;
    border: 1px solid {BORDER_SOFT};
    border-radius: 4px;
    padding: 1px 6px;
}}

QLabel#TopBarBrand {{
    background: transparent;
    color: {TEXT_PRIMARY};
    font-family: "IBM Plex Sans";
    font-size: 14px;
    font-weight: 700;
    letter-spacing: -0.3px;
}}

QPushButton#TopBarBell {{
    background-color: {SURFACE_CONTENT};
    border: 1px solid {BORDER_SOFT};
    border-radius: 6px;
}}

QPushButton#TopBarBell:hover {{
    background-color: {SURFACE_HOVER};
    border-color: #B8C0CC;
}}


/* ------ Toolbar buttons (flat, muted, pill on hover) ------ */
QPushButton#FileViewToolBtn {{
    background-color: transparent;
    border: 1px solid transparent;
    border-radius: 6px;
    padding: 0 10px;
    font-family: "IBM Plex Sans";
    font-size: 12px;
    color: {TEXT_MUTED};
    text-align: left;
}}

QPushButton#FileViewToolBtn:hover {{
    background-color: {SURFACE_HOVER};
    color: {TEXT_PRIMARY};
    border-color: transparent;
}}

QPushButton#FileViewToolBtn:disabled {{
    color: #B8C0CC;
}}

QPushButton#FileViewToolBtn:disabled:hover {{
    background-color: transparent;
}}

/* ------ File table - white surface, no grid ------ */

QTableWidget[role="file-table"] {{
    background-color: {SURFACE_CONTENT};
    alternate-background-color: {SURFACE_CONTENT};
    border: none;
    gridline-color: transparent;
    outline: none;
    selection-background-color: {SURFACE_SELECTED};
    selection-color: {TEXT_PRIMARY};
}}

QTableWidget[role="file-table"]::item {{
    border: none;
    border-bottom: 1px solid #EEF1F5;
    padding: 0;
}}

QTableWidget[role="file-table"]::item:hover {{
    background-color: #F4F6FA;
}}

QTableWidget[role="file-table"]::item:selected {{
    background-color: #E8ECF4;
    color: {TEXT_PRIMARY};
}}

QTableWidget[role="file-table"] QHeaderView {{
    background-color: {SURFACE_CONTENT};
    border: none;
}}

QTableWidget[role="file-table"] QHeaderView::section {{
    background-color: {SURFACE_CONTENT};
    color: {TEXT_MUTED};
    font-family: "IBM Plex Mono";
    font-size: 10px;
    font-weight: 600;
    padding: 0 12px;
    border: none;
    border-bottom: 1px solid {BORDER_SOFT};
}}

/* ------ Scrollbars ------ */
/*
   Default for every QScrollBar in the app: the narrow-dark style that
   used to be scoped to the file tree only - 6px track, TEXT_MUTED handle,
   darkens on hover. Keeps chrome visually quiet across the file table,
   inspector grid, search results, conflict dialog list, etc.

   The text preview inside the inspector overrides this back to a wider
   light style further down - its container is small enough that a 6px
   handle is hard to grab when there's a lot of extracted text.
*/

QScrollBar:vertical {{
    background: transparent;
    width: 6px;
    margin: 0;
}}
QScrollBar::handle:vertical {{
    background: {TEXT_MUTED};
    border-radius: 3px;
    min-height: 24px;
}}
QScrollBar::handle:vertical:hover {{
    background: {TEXT_PRIMARY};
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical,
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{
    background: none; border: none; height: 0;
}}

QScrollBar:horizontal {{
    background: transparent;
    height: 6px;
    margin: 0;
}}
QScrollBar::handle:horizontal {{
    background: {TEXT_MUTED};
    border-radius: 3px;
    min-width: 24px;
}}
QScrollBar::handle:horizontal:hover {{
    background: {TEXT_PRIMARY};
}}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal,
QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {{
    background: none; border: none; width: 0;
}}

/* ------ Text-preview scrollbar override ------
   Restores the wider light style on the inspector's preview text edit.
   The preview can hold a lot of extracted text, and the narrow dark
   handle reads as too heavy inside a small panel. */

QTextEdit#filePreviewSnippet QScrollBar:vertical {{
    background: transparent;
    width: 10px;
    margin: 0;
}}
QTextEdit#filePreviewSnippet QScrollBar::handle:vertical {{
    background: {BORDER_SOFT};
    border-radius: 5px;
    min-height: 30px;
}}
QTextEdit#filePreviewSnippet QScrollBar::handle:vertical:hover {{
    background: #B8C0CC;
}}

QTextEdit#filePreviewSnippet QScrollBar:horizontal {{
    background: transparent;
    height: 10px;
    margin: 0;
}}
QTextEdit#filePreviewSnippet QScrollBar::handle:horizontal {{
    background: {BORDER_SOFT};
    border-radius: 5px;
    min-width: 30px;
}}
QTextEdit#filePreviewSnippet QScrollBar::handle:horizontal:hover {{
    background: #B8C0CC;
}}
"""
