"""Status footer (bottom bar) - indexing pill, import progress bar, file
counts, and the right-aligned Lock-vault button."""

from __future__ import annotations

from PySide6.QtCore import QRectF, QSize, Qt, Signal
from PySide6.QtGui import QColor, QPainter, QPainterPath
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QWidget,
)

from app.ui.gui.setup import (
    TOKENS,
    ButtonVariant,
    Tone,
    apply_button,
    apply_text_style,
    set_tone,
)

from .helpers import css_color


# Filename cap inside the import pill. Anything longer collapses with a
# middle ellipsis so the pill width stays predictable regardless of the
# user's path lengths. Spec: 30 visible chars including the ellipsis.
_FILENAME_MAX_CHARS = 30


def _truncate_middle(text: str, max_len: int = _FILENAME_MAX_CHARS) -> str:
    """Collapse ``text`` to at most ``max_len`` chars by inserting a single
    middle ellipsis. Preserves the file extension when present so the
    truncated label still reads as e.g. ``field_no…es_03.md`` rather than
    losing the type suffix."""
    if len(text) <= max_len:
        return text
    if "." in text:
        stem, _, ext = text.rpartition(".")
        ext_with_dot = "." + ext
        # Only preserve the extension when there's room for at least
        # ``head…tail.ext`` (4 chars before/after the ellipsis minimum).
        if len(ext_with_dot) <= max_len - 5:
            keep = max_len - len(ext_with_dot) - 1  # 1 for ellipsis
            head = (keep + 1) // 2
            tail = keep // 2
            return f"{stem[:head]}…{stem[-tail:] if tail else ''}{ext_with_dot}"
    keep = max_len - 1
    head = (keep + 1) // 2
    tail = keep // 2
    return f"{text[:head]}…{text[-tail:] if tail else ''}"


class StatusPill(QWidget):
    """Compact status indicator pill used inside :class:`StatusFooter`."""

    def __init__(
        self,
        text: str,
        *,
        tone: Tone = Tone.INFO,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._text = text
        self._tone = tone
        self._build_ui()

    def _build_ui(self) -> None:
        tone_colors = {
            Tone.INFO: TOKENS.colors.status_info_bg,
            Tone.SUCCESS: TOKENS.colors.status_success_bg,
            Tone.WARNING: TOKENS.colors.status_warning_bg,
            Tone.ERROR: TOKENS.colors.status_error_bg,
        }
        bg_color = tone_colors.get(self._tone, TOKENS.colors.bg_elevated)

        self.setStyleSheet(f"""
            QWidget {{
                background-color: {css_color(bg_color)};
                border: 1px solid {css_color(TOKENS.colors.border_soft)};
                border-radius: 12px;
                padding: 4px 12px;
            }}
        """)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 4, 8, 4)
        layout.setSpacing(6)

        self.text_label = QLabel(self._text, self)
        apply_text_style(self.text_label, TOKENS.typography.caption)
        layout.addWidget(self.text_label)

    def set_text(self, text: str) -> None:
        self._text = text
        self.text_label.setText(text)


class _ProgressTrack(QFrame):
    """Thin horizontal track with an accent fill - used as the leading
    visual element inside :class:`ImportProgressPill`.

    Painted manually (rather than via a styled child) so the fill clips
    to the rounded ends of the track at any percentage.
    """

    _TRACK_BG = QColor("#D8DEE9")
    _TRACK_FILL = QColor("#5E81AC")

    def __init__(
        self, parent: QWidget | None = None, *, fill_color: QColor | None = None
    ) -> None:
        super().__init__(parent)
        self.setFixedSize(80, 6)
        self._percent: int = 0
        self._fill_color = fill_color or self._TRACK_FILL

    def set_percent(self, percent: int) -> None:
        clamped = max(0, min(100, int(percent)))
        if clamped == self._percent:
            return
        self._percent = clamped
        self.update()

    def paintEvent(self, event):  # type: ignore[override]
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        rect = QRectF(self.rect())
        radius = rect.height() / 2

        # Track
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(self._TRACK_BG)
        painter.drawRoundedRect(rect, radius, radius)

        # Fill, clipped to the rounded track shape.
        if self._percent > 0:
            path = QPainterPath()
            path.addRoundedRect(rect, radius, radius)
            painter.save()
            painter.setClipPath(path)
            painter.setBrush(self._fill_color)
            painter.drawRect(
                QRectF(
                    rect.x(),
                    rect.y(),
                    rect.width() * self._percent / 100.0,
                    rect.height(),
                )
            )
            painter.restore()


class ImportProgressPill(QFrame):
    """Status-footer import indicator: ``[track] filename   X/Y • Z%``.

    Layout (left → right):
      * Thin progress track (6px tall, accent fill)
      * Filename label, medium-weight primary text, middle-ellipsis if
        too long for the available width
      * Right-aligned mono metadata: ``current/total • percent%`` in a
        muted secondary tone

    The pill itself is a QSS-styled rounded container so it picks up
    matching tones from the rest of the chrome.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("ImportProgressPill")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setFixedHeight(28)
        self.setMinimumWidth(360)
        self.setStyleSheet(
            """
            QFrame#ImportProgressPill {
                background-color: #ECEFF4;
                border: 1px solid #C0C9D6;
                border-radius: 14px;
            }
            QFrame#ImportProgressPill QLabel {
                background: transparent;
                border: none;
            }
            """
        )

        self._raw_filename: str = ""

        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 0, 14, 0)
        layout.setSpacing(10)

        self._track = _ProgressTrack(self)
        layout.addWidget(self._track, 0, Qt.AlignmentFlag.AlignVCenter)

        self._filename = QLabel("", self)
        self._filename.setStyleSheet(
            'font-family: "IBM Plex Sans"; font-size: 12px; '
            "font-weight: 500; color: #2E3440;"
        )

        self._filename.setMinimumWidth(0)
        self._filename.setSizePolicy(
            self._filename.sizePolicy().horizontalPolicy(),
            self._filename.sizePolicy().verticalPolicy(),
        )
        layout.addWidget(self._filename, 1)

        self._meta = QLabel("", self)
        self._meta.setStyleSheet(
            'font-family: "IBM Plex Mono"; font-size: 11px; '
            "font-weight: 500; color: #6B7383;"
        )
        self._meta.setAlignment(
            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
        )
        layout.addWidget(self._meta, 0)

    def update_progress(
        self, current: int, total: int, filename: str
    ) -> None:
        if total > 0:
            percent = max(0, min(100, int(round(current * 100 / total))))
        else:
            percent = 0
        self._track.set_percent(percent)

        self._raw_filename = filename or ""
        display_name = (
            _truncate_middle(filename) if filename else "Importing…"
        )
        self._filename.setText(display_name)
        self._filename.setToolTip(filename or "")

        if total > 0:
            self._meta.setText(f"{current}/{total} • {percent}%")
        else:
            self._meta.setText("")

    def reset(self) -> None:
        self._track.set_percent(0)
        self._raw_filename = ""
        self._filename.setText("")
        self._filename.setToolTip("")
        self._meta.setText("")


class SyncProgressPill(QFrame):
    """Purple-tinted progress pill for sync operations."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("SyncProgressPill")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setFixedHeight(28)
        self.setMinimumWidth(360)
        self.setStyleSheet(
            """
            QFrame#SyncProgressPill {
                background-color: #EDE9FE;
                border: 1px solid #C4B5FD;
                border-radius: 14px;
            }
            QFrame#SyncProgressPill QLabel {
                background: transparent;
                border: none;
            }
            """
        )

        self._raw_label: str = ""

        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 0, 14, 0)
        layout.setSpacing(10)

        self._track = _ProgressTrack(self, fill_color=QColor("#7C3AED"))
        layout.addWidget(self._track, 0, Qt.AlignmentFlag.AlignVCenter)

        self._label = QLabel("", self)
        self._label.setStyleSheet(
            'font-family: "IBM Plex Sans"; font-size: 12px; '
            "font-weight: 500; color: #2E3440;"
        )
        self._label.setMinimumWidth(0)
        self._label.setSizePolicy(
            self._label.sizePolicy().horizontalPolicy(),
            self._label.sizePolicy().verticalPolicy(),
        )
        layout.addWidget(self._label, 1)

        self._meta = QLabel("", self)
        self._meta.setStyleSheet(
            'font-family: "IBM Plex Mono"; font-size: 11px; '
            "font-weight: 500; color: #6B7383;"
        )
        self._meta.setAlignment(
            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
        )
        layout.addWidget(self._meta, 0)

    def update_progress(
        self, current: int, total: int, label: str
    ) -> None:
        if total > 0:
            percent = max(0, min(100, int(round(current * 100 / total))))
        else:
            percent = 0
        self._track.set_percent(percent)

        self._raw_label = label or ""
        self._label.setText(label or "Syncing…")

        if total > 0:
            self._meta.setText(f"{current}/{total} • {percent}%")
        else:
            self._meta.setText("")

    def reset(self) -> None:
        self._track.set_percent(0)
        self._raw_label = ""
        self._label.setText("")
        self._meta.setText("")


class StatusFooter(QWidget):
    """Bottom footer:

    ``[indexing pill]   X files · Y unlocked   [importing progress bar]
                                                          [Lock vault]``

    The indexing pill and import progress bar auto-hide when no work is
    in progress; the middle counts label and the right-side Lock-vault
    button stay visible.
    """

    lock_vault_clicked = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self) -> None:
        from app.ui.gui.setup.icons import tinted_icon

        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setObjectName("StatusFooter")
        self.setFixedHeight(40)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(20, 0, 20, 0)
        layout.setSpacing(10)

        self.indexing_pill = StatusPill("", parent=self)
        self.indexing_pill.setVisible(False)
        layout.addWidget(self.indexing_pill)

        self._counts_label = QLabel("", self)
        apply_text_style(self._counts_label, TOKENS.typography.caption)
        set_tone(self._counts_label, Tone.MUTED)
        layout.addWidget(self._counts_label)

        # Import progress bar sits immediately to the right of the unlocked
        # counter. 
        # 
        
        self.importing_pill = ImportProgressPill(parent=self)
        self.importing_pill.setVisible(False)
        layout.addWidget(self.importing_pill)

        self.syncing_pill = SyncProgressPill(parent=self)
        self.syncing_pill.setVisible(False)
        layout.addWidget(self.syncing_pill)

        layout.addStretch(1)

        self._lock_button = QPushButton("Lock vault", self)
        self._lock_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self._lock_button.setIcon(
            tinted_icon("lock-simple", size=12, color=TOKENS.colors.text_primary)
        )
        self._lock_button.setIconSize(QSize(12, 12))
        apply_button(self._lock_button, ButtonVariant.GHOST, size="sm")
        self._lock_button.clicked.connect(self.lock_vault_clicked.emit)
        layout.addWidget(self._lock_button)

    # Pill visibility toggles

    def show_indexing(self, message: str = "Indexing") -> None:
        self.indexing_pill.set_text(message)
        self.indexing_pill.setVisible(True)

    def hide_indexing(self) -> None:
        self.indexing_pill.setVisible(False)

    def show_importing(self) -> None:
        """Reveal the import progress bar at 0% (use before any progress
        ticks have arrived)."""
        self.importing_pill.reset()
        self.importing_pill.setVisible(True)

    def update_importing(
        self, current: int, total: int, filename: str
    ) -> None:
        """Update the import progress bar's fill width and text."""
        self.importing_pill.setVisible(True)
        self.importing_pill.update_progress(current, total, filename)

    def hide_importing(self) -> None:
        self.importing_pill.setVisible(False)
        self.importing_pill.reset()

    def show_syncing(self) -> None:
        self.syncing_pill.reset()
        self.syncing_pill.setVisible(True)

    def update_syncing(
        self, current: int, total: int, label: str
    ) -> None:
        self.syncing_pill.setVisible(True)
        self.syncing_pill.update_progress(current, total, label)

    def hide_syncing(self) -> None:
        self.syncing_pill.setVisible(False)
        self.syncing_pill.reset()

    # Counts

    def set_counts(self, file_count: int, unlocked_count: int) -> None:
        files = "file" if file_count == 1 else "files"
        self._counts_label.setText(f"{file_count} {files} · {unlocked_count} unlocked")
