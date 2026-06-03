"""Pill widgets used by `confirm_phrase`"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QHBoxLayout, QLabel, QLineEdit, QWidget

from app.ui.gui.setup import (
    TOKENS,
    Role,
    Tone,
    apply_field,
    apply_text_style,
    set_field_error,
    set_tone,
)


def make_index_label(index: int, parent: QWidget) -> QLabel:
    """Small muted label rendered as a left-side superscript next to a cell."""
    num = QLabel(str(index), parent)
    num.setFixedWidth(20)
    num.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignRight)
    num.setContentsMargins(0, 8, 0, 0)
    apply_text_style(num, TOKENS.typography.caption)
    set_tone(num, Tone.MUTED)
    return num


class LockedPill(QWidget):
    """Read-only pill showing the original word at its index.

    Layout: ``[index]  [bordered read-only input]``. Only the input has the
    border. The index number floats outside as a left-aligned superscript.
    """

    def __init__(self, index: int, word: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        layout.addWidget(make_index_label(index, self), 0, Qt.AlignmentFlag.AlignTop)

        self.display = QLineEdit(self)
        self.display.setText(word)
        self.display.setReadOnly(True)
        self.display.setFixedHeight(39)
        self.display.setAlignment(Qt.AlignmentFlag.AlignLeft)
        self.display.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        apply_field(self.display, role=Role.RECOVERY_INPUT)
        # Locked words read as "you've already seen this" - fade them.
        self.display.setStyleSheet(
            self.display.styleSheet()
            + f" QLineEdit {{ color: {TOKENS.colors.text_muted.name()}; }}"
        )
        layout.addWidget(self.display, 1)


class InputPill(QWidget):
    """Editable pill where the user types a missing recovery word.

    Live-validates against the expected word via ``set_correct(True)``,
    which flips the input border to a success colour.
    """

    text_changed = Signal()

    def __init__(self, index: int, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._index = index

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        layout.addWidget(make_index_label(index, self), 0, Qt.AlignmentFlag.AlignTop)

        self.input = QLineEdit(self)
        self.input.setFixedHeight(39)
        self.input.setAlignment(Qt.AlignmentFlag.AlignLeft)
        apply_field(self.input, role=Role.RECOVERY_INPUT)
        self.input.textChanged.connect(self._on_changed)
        layout.addWidget(self.input, 1)

    def _on_changed(self, _text: str) -> None:
        self.text_changed.emit()

    def value(self) -> str:
        return self.input.text().strip().lower()

    def set_correct(self, correct: bool) -> None:
        if correct:
            success = TOKENS.colors.status_success_text
            r, g, b = success.red(), success.green(), success.blue()
            self.input.setStyleSheet(
                f"QLineEdit {{ border: 1px solid rgba({r}, {g}, {b}, 0.40); "
                f"background-color: rgba({r}, {g}, {b}, 0.10); "
                f"border-radius: {TOKENS.radius.sm}px; "
                f"padding: 0 8px; }}"
            )
            set_field_error(self.input, False)
        else:
            self.input.setStyleSheet("")
            apply_field(self.input, role=Role.RECOVERY_INPUT)

    def set_error(self, has_error: bool) -> None:
        set_field_error(self.input, has_error)
