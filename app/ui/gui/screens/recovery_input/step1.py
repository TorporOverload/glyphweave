"""Step 1 of the vault-password recovery flow: enter the 24-word recovery key.

``RecoveryStep1Page`` renders a 6 × 4 grid of numbered ``QLineEdit`` fields,
one per recovery word, together with:

* A ``QProgressBar`` and ``0 / 24`` counter that update as the user types,
  giving live feedback on how many words have been entered.
* **Paste all** - splits the clipboard by whitespace and fills the first 24
  tokens into the grid in one action, covering the common case where the
  user has their phrase stored in a password manager.
* **Clear** - resets all fields and returns focus to word 1.
* An error strip (hidden by default) surfaced either by failed clipboard
  paste or by a backend rejection forwarded from ``RecoveryInputScreen``.

The "Verify recovery key" primary button is disabled until all 24 fields are
non-empty; clicking it emits ``verify_requested``, which ``RecoveryInputScreen``
handles by advancing to step 2.

Public API
----------
``words() -> list[str]``
    Returns the 24 words as a lowercased, stripped list.
``set_vault_info(name, path)``
    Populates the vault name/path labels in the header.
``set_loading(is_loading)``
    Disables all inputs and buttons while a background task is running.
``show_error(message)`` / ``clear_error()``
    Show/hide the error strip.
``reset()``
    Clears all fields and hides the error strip.
``focus_first_word()``
    Moves keyboard focus to word-input 1.
"""
from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QProgressBar,
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
    apply_field,
    apply_text_style,
    set_properties,
    set_tone,
)


class RecoveryStep1Page(QWidget):
    """Page 1 of the recovery flow: enter the 24-word recovery key.

    Emits ``verify_requested`` once the user has filled all 24 words and
    clicked the verify button - the parent screen advances to step 2 in
    response.
    """

    verify_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.word_inputs: list[QLineEdit] = []
        self._build_ui()

    # Public API

    def words(self) -> list[str]:
        """Return the 24 words as a list, lowercased and stripped."""
        return [inp.text().strip().lower() for inp in self.word_inputs]

    def set_vault_info(self, name: str, path: str) -> None:
        self._vault_name_label.setText(name)
        self._vault_path_label.setText(path)

    def set_loading(self, is_loading: bool) -> None:
        """Disable all step-1 inputs while a background task is running."""
        for inp in self.word_inputs:
            inp.setEnabled(not is_loading)
        self._verify_button.setEnabled(
            not is_loading and self._progress.value() == 24
        )
        self._paste_all_button.setEnabled(not is_loading)
        self._clear_button.setEnabled(not is_loading)

    def show_error(self, message: str) -> None:
        self._error_label.setText(f"x  {message}")
        self._error_strip.setVisible(True)

    def clear_error(self) -> None:
        self._error_strip.setVisible(False)

    def reset(self) -> None:
        for inp in self.word_inputs:
            inp.clear()
        self.clear_error()
        self._update_progress()

    def focus_first_word(self) -> None:
        if self.word_inputs:
            self.word_inputs[0].setFocus()

    def is_verify_enabled(self) -> bool:
        return self._verify_button.isEnabled()
    # Internal
 
    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        title = QLabel("Enter your recovery key", self)
        apply_text_style(title, TOKENS.typography.app_title)
        layout.addWidget(title)

        self._vault_name_label = QLabel("", self)
        apply_text_style(self._vault_name_label, TOKENS.typography.body)
        layout.addWidget(self._vault_name_label)

        self._vault_path_label = QLabel("", self)
        apply_text_style(self._vault_path_label, TOKENS.typography.mono)
        set_properties(self._vault_path_label, role=Role.UNLOCK_PATH)
        layout.addWidget(self._vault_path_label)

        layout.addSpacing(8)

        layout.addLayout(self._build_toolbar())
        layout.addLayout(self._build_grid(), 1)
        layout.addWidget(self._build_error_strip())

        layout.addSpacing(12)

        self._verify_button = QPushButton("Verify recovery key", self)
        self._verify_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self._verify_button.setFixedHeight(40)
        self._verify_button.setEnabled(False)
        apply_button(self._verify_button, ButtonVariant.PRIMARY)
        self._verify_button.clicked.connect(self._on_verify_clicked)
        layout.addWidget(self._verify_button)

        hint = QLabel(
            "Lost your recovery key? Your data cannot be recovered without it.",
            self,
        )
        apply_text_style(hint, TOKENS.typography.caption)
        set_tone(hint, Tone.MUTED)
        hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(hint)

    def _build_toolbar(self) -> QHBoxLayout:
        toolbar = QHBoxLayout()
        toolbar.setContentsMargins(0, 0, 0, 0)
        toolbar.setSpacing(10)

        self._progress = QProgressBar(self)
        self._progress.setRange(0, 24)
        self._progress.setValue(0)
        self._progress.setTextVisible(False)
        self._progress.setFixedHeight(6)
        self._progress.setObjectName("recoveryProgressBar")

        self._progress_count = QLabel("0 / 24", self)
        apply_text_style(self._progress_count, TOKENS.typography.caption)
        set_tone(self._progress_count, Tone.MUTED)
        self._progress_count.setFixedWidth(56)

        self._paste_all_button = QPushButton("Paste all", self)
        apply_button(self._paste_all_button, ButtonVariant.GHOST)
        self._paste_all_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self._paste_all_button.clicked.connect(self._on_paste_all)

        self._clear_button = QPushButton("Clear", self)
        apply_button(self._clear_button, ButtonVariant.GHOST)
        self._clear_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self._clear_button.clicked.connect(self._on_clear_clicked)

        toolbar.addWidget(self._progress, 1)
        toolbar.addWidget(self._progress_count)
        toolbar.addWidget(self._paste_all_button)
        toolbar.addWidget(self._clear_button)
        return toolbar

    def _build_grid(self) -> QGridLayout:
        grid = QGridLayout()
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(12)
        for row in range(4):
            grid.setRowStretch(row, 1)

        for i in range(24):
            cell = QWidget(self)
            cell_layout = QHBoxLayout(cell)
            cell_layout.setContentsMargins(0, 0, 0, 0)
            cell_layout.setSpacing(8)

            num = QLabel(str(i + 1), cell)
            num.setFixedWidth(20)
            num.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignRight)
            num.setContentsMargins(0, 8, 0, 0)
            apply_text_style(num, TOKENS.typography.caption)
            set_tone(num, Tone.MUTED)

            inp = QLineEdit(cell)
            inp.setFixedHeight(39)
            inp.setAlignment(Qt.AlignmentFlag.AlignLeft)
            inp.textChanged.connect(self._update_progress)
            apply_field(inp, role=Role.RECOVERY_INPUT)

            cell_layout.addWidget(num, 0, Qt.AlignmentFlag.AlignTop)
            cell_layout.addWidget(inp, 1)
            self.word_inputs.append(inp)
            grid.addWidget(cell, i // 6, i % 6)

        return grid

    def _build_error_strip(self) -> QFrame:
        self._error_strip = QFrame(self)
        set_properties(self._error_strip, role=Role.ALERT, tone=Tone.ERROR)
        self._error_strip.setFixedHeight(28)
        self._error_strip.setVisible(False)
        err_layout = QHBoxLayout(self._error_strip)
        err_layout.setContentsMargins(11, 5, 11, 5)
        err_layout.setSpacing(0)
        self._error_label = QLabel("", self._error_strip)
        apply_text_style(self._error_label, TOKENS.typography.caption)
        set_properties(self._error_label, role=Role.ERROR_TEXT)
        err_layout.addWidget(self._error_label)
        return self._error_strip

    def _update_progress(self) -> None:
        filled = sum(1 for inp in self.word_inputs if inp.text().strip())
        self._progress.setValue(filled)
        self._progress_count.setText(f"{filled} / 24")
        self._verify_button.setEnabled(filled == 24)
        if self._error_strip.isVisible():
            self.clear_error()

    def _on_paste_all(self) -> None:
        clipboard = QGuiApplication.clipboard()
        text = clipboard.text() if clipboard else ""
        tokens = [t for t in text.split() if t]
        if not tokens:
            self.show_error("Nothing on the clipboard to paste.")
            return
        for i, token in enumerate(tokens[:24]):
            self.word_inputs[i].setText(token.lower())
        self._update_progress()

    def _on_clear_clicked(self) -> None:
        self.reset()
        self.focus_first_word()

    def _on_verify_clicked(self) -> None:
        words = self.words()
        if not all(words):
            self.show_error("All 24 recovery words are required.")
            return
        self.verify_requested.emit()


__all__ = ["RecoveryStep1Page"]
