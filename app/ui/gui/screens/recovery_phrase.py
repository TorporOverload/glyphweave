from __future__ import annotations

from typing import Sequence

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from app.ui.gui.setup import (
    load_icon,
    apply_button,
    apply_text_style,
    set_properties,
    TOKENS,
    ButtonVariant,
    Role,
)

# 24 empty placeholders. the real phrase is supplied via ``set_words(...)``
# after vault creation. 
# 
_PLACEHOLDER_WORDS = [""] * 24

# Seconds to leave the recovery mnemonic on the system clipboard before
# auto-clearing. Long enough for the user to paste it into their password
# manager once, short enough to avoid stale-clipboard leaks.
_CLIPBOARD_CLEAR_DELAY_MS = 30_000


class RecoveryWordPill(QFrame):
    def __init__(
        self,
        index: int,
        word: str,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        set_properties(self, role=Role.RECOVERY_PILL)
        self.setFixedSize(122, 52)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 6, 8, 8)
        layout.setSpacing(1)

        number = QLabel(str(index), self)
        set_properties(number, role=Role.RECOVERY_NUMBER)
        apply_text_style(number, TOKENS.typography.caption)
        layout.addWidget(number, 0, Qt.AlignmentFlag.AlignLeft)

        value = QLabel(word, self)
        apply_text_style(value, TOKENS.typography.body_secondary)
        layout.addWidget(value, 0, Qt.AlignmentFlag.AlignLeft)
        layout.addStretch(1)


class RecoveryPhraseScreen(QWidget):
    continue_requested = Signal()
    copied_to_clipboard = Signal()
    dismissed = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._view_mode = False
        self._clipboard_clear_timer: QTimer | None = None
        self._build_ui()
        self.set_words(_PLACEHOLDER_WORDS)

    def _build_ui(self) -> None:
        set_properties(self, role=Role.RECOVERY_PHRASE)

        root = QVBoxLayout(self)
        root.setContentsMargins(48, 48, 48, 48)
        root.setSpacing(0)
        root.addStretch(1)

        self.modal = QFrame(self)
        set_properties(self.modal, role=Role.RECOVERY_MODAL)
        self.modal.setFixedSize(880, 576)
        root.addWidget(self.modal, 0, Qt.AlignmentFlag.AlignHCenter)
        root.addStretch(1)

        layout = QVBoxLayout(self.modal)
        layout.setContentsMargins(24, 18, 24, 24)
        layout.setSpacing(10)

        self._title_label = QLabel("This is your Recovery Phrase", self.modal)
        apply_text_style(self._title_label, TOKENS.typography.page_title)
        self._title_label.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        layout.addWidget(self._title_label)

        layout.addSpacing(2)

        self._description_label = QLabel(
            "Write it down in order and keep it somewhere safe. You will need "
            "these 24 words to recover your vault.",
            self.modal,
        )
        set_properties(self._description_label, role=Role.RECOVERY_MONO)
        apply_text_style(self._description_label, TOKENS.typography.mono)
        self._description_label.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        layout.addWidget(self._description_label)

        divider_top = QFrame(self.modal)
        set_properties(divider_top, role=Role.RECOVERY_DIVIDER)
        layout.addWidget(divider_top)

        pills = QGridLayout()
        pills.setContentsMargins(10, 10, 10, 0)
        pills.setHorizontalSpacing(10)
        pills.setVerticalSpacing(18)
        self._pills_layout = pills
        layout.addLayout(pills)

        warning_row = QHBoxLayout()
        warning_row.setContentsMargins(12, 0, 12, 0)
        warning_row.setSpacing(6)

        warning_icon = QLabel(self.modal)
        warning_icon.setPixmap(load_icon("warning.svg").pixmap(18, 17))
        warning_row.addWidget(warning_icon, 0, Qt.AlignmentFlag.AlignVCenter)

        warning_text = QLabel(
            "These 24 are your recovery key. "
            "Write them down in order before continuing.",
            self.modal,
        )
        set_properties(warning_text, role=Role.RECOVERY_WARNING)
        apply_text_style(warning_text, TOKENS.typography.caption)
        warning_row.addWidget(warning_text, 1)
        layout.addLayout(warning_row)

        self.confirm_checkbox = QCheckBox(
            "I have written down all 24 words in order and stored them safely",
            self.modal,
        )
        set_properties(self.confirm_checkbox, role=Role.RECOVERY_CHECK)
        self.confirm_checkbox.toggled.connect(self._sync_continue_state)
        layout.addWidget(self.confirm_checkbox)

        divider_middle = QFrame(self.modal)
        set_properties(divider_middle, role=Role.RECOVERY_DIVIDER)
        layout.addWidget(divider_middle)

        hint_row = QHBoxLayout()
        hint_row.setContentsMargins(0, 0, 0, 0)
        hint_row.setSpacing(8)

        left_hint = QFrame(self.modal)
        set_properties(left_hint, role=Role.RECOVERY_SHORT_DIVIDER)
        self._left_hint = left_hint
        hint_row.addWidget(left_hint)

        hint = QLabel("Continue is disabled until confirmed", self.modal)
        set_properties(hint, role=Role.RECOVERY_HINT)
        apply_text_style(hint, TOKENS.typography.mono)
        self._hint_label = hint
        hint_row.addWidget(hint, 0, Qt.AlignmentFlag.AlignCenter)

        right_hint = QFrame(self.modal)
        set_properties(right_hint, role=Role.RECOVERY_SHORT_DIVIDER)
        self._right_hint = right_hint
        hint_row.addWidget(right_hint)

        hint_row.addStretch(1)
        layout.addLayout(hint_row)

        buttons = QHBoxLayout()
        buttons.setContentsMargins(0, 2, 0, 0)
        buttons.setSpacing(10)

        self.continue_button = QPushButton("Continue", self.modal)
        apply_button(self.continue_button, ButtonVariant.PRIMARY, role=Role.RECOVERY)
        self.continue_button.setEnabled(False)
        self.continue_button.setFixedHeight(36)
        self.continue_button.clicked.connect(self.continue_requested.emit)
        buttons.addWidget(self.continue_button, 1)

        self.copy_button = QPushButton("Copy to clipboard", self.modal)
        apply_button(self.copy_button, ButtonVariant.SECONDARY, role=Role.RECOVERY)
        self.copy_button.setFixedHeight(36)
        self.copy_button.clicked.connect(self.copy_words_to_clipboard)
        buttons.addWidget(self.copy_button, 1)

        self.close_button = QPushButton("Close", self.modal)
        apply_button(self.close_button, ButtonVariant.SECONDARY, role=Role.RECOVERY)
        self.close_button.setFixedHeight(36)
        self.close_button.clicked.connect(self.dismissed.emit)
        self.close_button.setVisible(False)
        buttons.addWidget(self.close_button, 1)

        layout.addLayout(buttons)

    def set_words(self, words: Sequence[str]) -> None:
        while self._pills_layout.count():
            item = self._pills_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

        for index, word in enumerate(words[:24], start=1):
            row = (index - 1) // 6
            column = (index - 1) % 6
            self._pills_layout.addWidget(
                RecoveryWordPill(index, word, self.modal), row, column
            )

    def copy_words_to_clipboard(self) -> None:
        words: list[str] = []
        for i in range(self._pills_layout.count()):
            item = self._pills_layout.itemAt(i)
            widget = item.widget()
            if widget is None:
                continue
            labels = widget.findChildren(QLabel)
            if len(labels) >= 2:
                words.append(labels[1].text())
        phrase = " ".join(words)
        if not phrase.strip():
            return
        clipboard = QApplication.clipboard()
        clipboard.setText(phrase)
        self.copied_to_clipboard.emit()
        self._schedule_clipboard_clear(phrase)

    def _schedule_clipboard_clear(self, expected: str) -> None:
        """Clear the clipboard after ``_CLIPBOARD_CLEAR_DELAY_MS`` if it still
        holds the recovery phrase. Guards against wiping unrelated content the
        user may have copied in the meantime."""
        if self._clipboard_clear_timer is not None:
            self._clipboard_clear_timer.stop()
        timer = QTimer(self)
        timer.setSingleShot(True)
        timer.timeout.connect(lambda: self._clear_clipboard_if_match(expected))
        timer.start(_CLIPBOARD_CLEAR_DELAY_MS)
        self._clipboard_clear_timer = timer

    def _clear_clipboard_if_match(self, expected: str) -> None:
        clipboard = QApplication.clipboard()
        if clipboard.text() == expected:
            clipboard.clear()
        self._clipboard_clear_timer = None

    def reset(self) -> None:
        self.confirm_checkbox.setChecked(False)
        self._sync_continue_state()

    def clear_words(self) -> None:
        """Drop the displayed mnemonic. Call this after the confirm-phrase
        step succeeds so the words don't linger as widget text on the dead
        screen for the rest of the session."""
        self.set_words(_PLACEHOLDER_WORDS)
        if self._clipboard_clear_timer is not None:
            self._clipboard_clear_timer.stop()
            self._clipboard_clear_timer = None

    def _sync_continue_state(self) -> None:
        self.continue_button.setEnabled(self.confirm_checkbox.isChecked())

    def set_view_mode(self, view_mode: bool) -> None:
        self._view_mode = view_mode
        self.continue_button.setVisible(not view_mode)
        self.confirm_checkbox.setVisible(not view_mode)
        self.copy_button.setVisible(not view_mode)
        self.close_button.setVisible(view_mode)
        self._hint_label.setVisible(not view_mode)
        self._left_hint.setVisible(not view_mode)
        self._right_hint.setVisible(not view_mode)
        if view_mode:
            title = "Your Recovery Phrase"
            description = (
                "Keep this phrase safe. You will need it to recover your vault "
                "if you lose access to your account."
            )
        else:
            title = "This is your Recovery Phrase"
            description = (
                "Write it down in order and keep it somewhere safe. You will need "
                "these 24 words to recover your vault."
            )
        self._title_label.setText(title)
        self._description_label.setText(description)
