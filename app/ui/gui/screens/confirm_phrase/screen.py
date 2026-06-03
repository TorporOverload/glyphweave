"""Confirm-phrase screen.

Shows the 24-word recovery phrase with 4 random positions blanked out. The user
must type the missing words to confirm they wrote the phrase down. The screen
emits ``continue_requested`` on a correct match and ``back_requested`` to return
to the recovery-phrase screen.

API mirrors ``RecoveryPhraseScreen`` so the parent flow can call
``set_words(words)`` once it has the freshly generated mnemonic.
"""

from __future__ import annotations

import random
from typing import Sequence

from PySide6.QtCore import (
    Property,
    QEasingCurve,
    QPoint,
    QPropertyAnimation,
    Qt,
    Signal,
)
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from app.ui.gui.setup import (
    TOKENS,
    ButtonVariant,
    Role,
    Tone,
    apply_button,
    apply_text_style,
    set_properties,
)

from .pills import InputPill as _InputPill
from .pills import LockedPill as _LockedPill


_BLANK_COUNT = 4


class ConfirmPhraseScreen(QWidget):
    """24-word grid with 4 random blanks the user must fill in."""

    continue_requested = Signal()
    back_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._words: list[str] = []
        self._blanks: list[int] = []
        self._inputs: dict[int, _InputPill] = {}
        self._build_ui()

        # Shake animation - animates `pos` of self.modal off-axis and back.
        self._shake_anim = QPropertyAnimation(self, b"_modal_offset")
        self._shake_anim.setDuration(360)
        self._shake_anim.setEasingCurve(QEasingCurve.Type.OutSine)

    def _build_ui(self) -> None:
        """Builds the UI for the confirm phrase screen."""
        set_properties(self, role=Role.RECOVERY_PHRASE)

        root = QVBoxLayout(self)
        root.setContentsMargins(48, 48, 48, 48)
        root.setSpacing(0)
        root.addStretch(1)

        self.modal = QFrame(self)
        set_properties(self.modal, role=Role.RECOVERY_MODAL)
        # Height tuned to actual content so the verify/back row sits close
        # to the grid instead of getting pushed to a far-bottom edge.
        self.modal.setFixedSize(920, 540)
        root.addWidget(self.modal, 0, Qt.AlignmentFlag.AlignHCenter)
        root.addStretch(1)

        layout = QVBoxLayout(self.modal)
        layout.setContentsMargins(28, 22, 28, 24)
        layout.setSpacing(12)

        title = QLabel("Confirm your recovery phrase", self.modal)
        apply_text_style(title, TOKENS.typography.page_title)
        title.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        layout.addWidget(title)

        layout.addSpacing(2)

        description = QLabel(
            "Enter the missing words to confirm you've written them down.",
            self.modal,
        )
        set_properties(description, role=Role.RECOVERY_MONO)
        apply_text_style(description, TOKENS.typography.mono)
        description.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        layout.addWidget(description)

        divider_top = QFrame(self.modal)
        set_properties(divider_top, role=Role.RECOVERY_DIVIDER)
        layout.addWidget(divider_top)

        self._pills_layout = QGridLayout()
        self._pills_layout.setContentsMargins(0, 8, 0, 0)
        self._pills_layout.setHorizontalSpacing(12)
        self._pills_layout.setVerticalSpacing(14)
        for row in range(4):
            self._pills_layout.setRowStretch(row, 1)
        layout.addLayout(self._pills_layout, 1)

        # Hint / error strip - toggles between info and error variants.
        self.hint_strip = QFrame(self.modal)
        set_properties(self.hint_strip, role=Role.ALERT, tone=Tone.INFO)
        self.hint_strip.setFixedHeight(36)
        hint_layout = QHBoxLayout(self.hint_strip)
        hint_layout.setContentsMargins(12, 6, 12, 6)
        hint_layout.setSpacing(10)
        self.hint_icon = QLabel("i", self.hint_strip)
        self.hint_icon.setObjectName("confirmPhraseHintBadge")
        self.hint_icon.setFixedSize(18, 18)
        self.hint_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._refresh_hint_icon_style("info")
        self.hint_label = QLabel(
            "We've blanked out 4 random words. Type each one to verify you "
            "have your phrase saved.",
            self.hint_strip,
        )
        apply_text_style(self.hint_label, TOKENS.typography.caption)
        hint_layout.addWidget(self.hint_icon, 0, Qt.AlignmentFlag.AlignVCenter)
        hint_layout.addWidget(self.hint_label, 1)
        layout.addWidget(self.hint_strip)

        # Buttons row
        buttons = QHBoxLayout()
        buttons.setContentsMargins(0, 4, 0, 0)
        buttons.setSpacing(10)

        self.continue_button = QPushButton("Confirm phrase", self.modal)
        apply_button(self.continue_button, ButtonVariant.PRIMARY, role=Role.RECOVERY)
        self.continue_button.setFixedHeight(36)
        self.continue_button.setEnabled(False)
        self.continue_button.clicked.connect(self._on_confirm_clicked)
        buttons.addWidget(self.continue_button, 1)

        self.back_button = QPushButton("Back to phrase", self.modal)
        apply_button(self.back_button, ButtonVariant.SECONDARY, role=Role.RECOVERY)
        self.back_button.setFixedHeight(36)
        self.back_button.clicked.connect(self.back_requested.emit)
        buttons.addWidget(self.back_button, 1)

        layout.addLayout(buttons)

        # Reseed link
        self.reseed_button = QPushButton("Pick different words", self.modal)
        self.reseed_button.setCursor(Qt.CursorShape.PointingHandCursor)
        set_properties(self.reseed_button, role=Role.UNLOCK_FORGOT)
        self.reseed_button.clicked.connect(self._reseed_blanks)
        layout.addWidget(self.reseed_button, 0, Qt.AlignmentFlag.AlignHCenter)
        
    def _get_modal_offset(self) -> int:
        return getattr(self, "_modal_offset_value", 0)

    def _set_modal_offset(self, value: int) -> None:
        self._modal_offset_value = value
        # Translate the modal sideways without affecting layout flow.
        if hasattr(self, "modal"):
            base = self.modal.property("_baseX")
            if base is None:
                base = self.modal.x()
                self.modal.setProperty("_baseX", base)
            self.modal.move(QPoint(int(base) + value, self.modal.y()))

    _modal_offset = Property(int, _get_modal_offset, _set_modal_offset)

    def _shake(self) -> None:
        self.modal.setProperty("_baseX", self.modal.x())
        anim = self._shake_anim
        anim.stop()
        anim.setStartValue(0)
        anim.setKeyValueAt(0.15, -10)
        anim.setKeyValueAt(0.30, 8)
        anim.setKeyValueAt(0.50, -6)
        anim.setKeyValueAt(0.70, 4)
        anim.setEndValue(0)
        anim.start()

    # Public API

    def set_words(self, words: Sequence[str]) -> None:
        self._words = [w.strip().lower() for w in words[:24]]
        self._reseed_blanks()

    def reset(self) -> None:
        for pill in self._inputs.values():
            pill.input.clear()
            pill.set_correct(False)
        self._set_hint_info(
            "We've blanked out 4 random words. Type each one to verify you "
            "have your phrase saved."
        )
        self.continue_button.setEnabled(False)

    # Internal helpers

    def _reseed_blanks(self) -> None:
        if len(self._words) < 24:
            return
        self._blanks = sorted(random.sample(range(24), _BLANK_COUNT))
        self._rebuild_grid()
        self.reset()

    def _rebuild_grid(self) -> None:
        # Tear down existing children
        while self._pills_layout.count():
            item = self._pills_layout.takeAt(0)
            if item is not None:
                widget = item.widget()
                if widget is not None:
                    widget.deleteLater()
        self._inputs.clear()

        blank_set = set(self._blanks)
        first_input: _InputPill | None = None
        for index in range(24):
            row, col = index // 6, index % 6
            if index in blank_set:
                pill = _InputPill(index + 1, self.modal)
                pill.text_changed.connect(self._on_input_changed)
                self._inputs[index] = pill
                self._pills_layout.addWidget(pill, row, col)
                if first_input is None:
                    first_input = pill
            else:
                pill = _LockedPill(index + 1, self._words[index], self.modal)
                self._pills_layout.addWidget(pill, row, col)

        if first_input is not None:
            first_input.input.setFocus()

    def _on_input_changed(self) -> None:
        # Live-correct visual state
        for index, pill in self._inputs.items():
            value = pill.value()
            if value == self._words[index]:
                pill.set_correct(True)
            else:
                pill.set_correct(False)
        all_filled = all(pill.value() for pill in self._inputs.values())
        self.continue_button.setEnabled(all_filled)
        # Clear any previous error styling now that the user is editing.
        if self.hint_strip.property("tone") == "error":
            self._set_hint_info(
                "We've blanked out 4 random words. Type each one to verify "
                "you have your phrase saved."
            )

    def _on_confirm_clicked(self) -> None:
        wrong = [
            index + 1
            for index, pill in self._inputs.items()
            if pill.value() != self._words[index]
        ]
        if not wrong:
            self.continue_requested.emit()
            return

        for index, pill in self._inputs.items():
            if pill.value() != self._words[index]:
                pill.set_error(True)

        if len(wrong) == 1:
            msg = f"Word {wrong[0]} doesn't match."
        else:
            joined = ", ".join(str(w) for w in wrong)
            msg = f"{len(wrong)} words don't match. Check positions {joined}."
        self._set_hint_error(msg)
        self._shake()

    def _set_hint_info(self, message: str) -> None:
        self.hint_strip.setProperty("tone", "info")
        self.hint_icon.setText("i")
        self._refresh_hint_icon_style("info")
        self.hint_label.setText(message)
        self.hint_strip.style().unpolish(self.hint_strip)
        self.hint_strip.style().polish(self.hint_strip)

    def _set_hint_error(self, message: str) -> None:
        self.hint_strip.setProperty("tone", "error")
        self.hint_icon.setText("!")
        self._refresh_hint_icon_style("error")
        self.hint_label.setText(message)
        self.hint_strip.style().unpolish(self.hint_strip)
        self.hint_strip.style().polish(self.hint_strip)

    def _refresh_hint_icon_style(self, tone: str) -> None:
        if tone == "error":
            bg = TOKENS.colors.status_error_text
            fg = TOKENS.colors.text_inverse
        else:
            bg = TOKENS.colors.text_secondary
            fg = TOKENS.colors.text_inverse
        self.hint_icon.setStyleSheet(
            f"background-color: {bg.name()}; color: {fg.name()}; "
            f"border-radius: 9px; font-size: 10px; font-weight: 700; "
            f"font-family: 'IBM Plex Sans';"
        )


__all__ = ["ConfirmPhraseScreen"]
