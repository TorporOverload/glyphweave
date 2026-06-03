"""Top-level screen widget for the two-step vault-password recovery flow.

``RecoveryInputScreen`` wraps both step pages in a centred modal card and
manages navigation between them.  It is designed to be swapped into the main
window's screen stack in place of the normal unlock screen when the user
chooses "Forgot password".

Layout
------
The screen has a full-window background (``Role.UNLOCK_VAULT``) with a
centred ``QFrame`` modal card whose fixed size changes per step:

* **Step 1** (920 × 540) - wide enough to fit the 6 × 4 word grid in
  ``RecoveryStep1Page``.
* **Step 2** (520 × 520) - narrower, matching the standard lock-screen
  proportions used by ``RecoveryStep2Page``.

A persistent "< Back" button is floated over the top-left corner via
``resizeEvent``; it navigates back to step 1 when on step 2, or emits
``back_requested`` when on step 1.

A two-dot step indicator bar (``_build_step_indicator``) sits above the
``QStackedWidget`` that hosts both pages and updates its dot states
(``active`` / ``done`` / ``pending``) on every transition.

Signals
-------
``back_requested``
    Emitted when the user clicks Back on step 1 (i.e. wants to leave the
    recovery flow entirely).
``recovery_succeeded(new_password, passphrase)``
    Emitted after step 2 is submitted with the validated new password and
    the space-joined 24-word passphrase from step 1.  The caller is
    responsible for driving the backend re-encryption and calling
    ``show_error`` or closing the screen on completion.

Public API
----------
``set_vault_info(name, path)``
    Populates the vault name/path labels on step 1.
``set_loading(is_loading)``
    Disables/re-enables all inputs and the Back button during async work.
``show_error(message)``
    Returns the user to step 1 and shows an error strip (used when the
    backend rejects the recovery words).
``reset()``
    Clears both pages and returns to step 1 (e.g. when the screen is
    re-shown for a different vault).
"""
from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QResizeEvent
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from app.ui.gui.setup import (
    TOKENS,
    Role,
    apply_text_style,
    set_properties,
)

from .step1 import RecoveryStep1Page
from .step2 import RecoveryStep2Page


class RecoveryInputScreen(QWidget):
    """Two-step recovery flow:

    Step 1 - enter 24-word recovery key (paste-all, clear, progress bar).
    Step 2 - set a new password and confirm.
    """

    back_requested = Signal()
    recovery_succeeded = Signal(str, str)  # (new_password, passphrase)

    # Modal dimensions per step. Step 1's 6×4 word grid wants width and
    # enough height to feel proportional next to ConfirmPhraseScreen
    # (920×540). Step 2's password form is narrow (LockScreen-style) but
    # needs more height for the subtitle, confirm field, and warning.
    _STEP1_SIZE = (920, 540)
    _STEP2_SIZE = (520, 520)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._vault_name: str = ""
        self._vault_path: str = ""
        self._build_ui()

    # Build

    def _build_ui(self) -> None:
        set_properties(self, role=Role.UNLOCK_VAULT)

        root = QVBoxLayout(self)
        root.setContentsMargins(20, 16, 20, 16)
        root.setSpacing(0)
        root.addStretch(1)

        # Modal card - sized dynamically per step (see _goto_step).
        self.modal = QFrame(self)
        set_properties(self.modal, role=Role.UNLOCK_MODAL)
        root.addWidget(self.modal, 0, Qt.AlignmentFlag.AlignHCenter)

        # Back button (always visible). Step 1 → onBack; Step 2 → step 1.
        # Floated over the screen by ``_position_back_button`` from
        # ``resizeEvent`` so it does not consume layout height.
        self.back_button = QPushButton("< Back", self)
        self.back_button.setCursor(Qt.CursorShape.PointingHandCursor)
        set_properties(self.back_button, role=Role.UNLOCK_BACK)
        self.back_button.clicked.connect(self._on_back_clicked)
        self.back_button.adjustSize()

        modal_layout = QVBoxLayout(self.modal)
        modal_layout.setContentsMargins(28, 24, 28, 24)
        modal_layout.setSpacing(12)

        self.step_indicator = self._build_step_indicator(self.modal)
        modal_layout.addWidget(self.step_indicator)

        self._stack = QStackedWidget(self.modal)

        self._step1 = RecoveryStep1Page(self._stack)
        self._step1.verify_requested.connect(lambda: self._goto_step(2))
        self._stack.addWidget(self._step1)

        self._step2 = RecoveryStep2Page(self._stack)
        self._step2.submit_requested.connect(self._on_step2_submit)
        self._stack.addWidget(self._step2)

        modal_layout.addWidget(self._stack, 1)

        root.addStretch(1)

        self._goto_step(1)
        self._position_back_button()

    def resizeEvent(self, event: QResizeEvent) -> None:  # type: ignore[override]
        super().resizeEvent(event)
        self._position_back_button()

    def _position_back_button(self) -> None:
        if hasattr(self, "back_button"):
            self.back_button.move(20, 16)

    def _build_step_indicator(self, parent: QWidget) -> QWidget:
        bar = QWidget(parent)
        bar.setObjectName("recoveryStepIndicator")
        h = QHBoxLayout(bar)
        h.setContentsMargins(0, 0, 0, 4)
        h.setSpacing(8)

        def make_step(num: int, label: str) -> tuple[QLabel, QLabel]:
            dot = QLabel(str(num), bar)
            dot.setObjectName(f"recoveryStepDot{num}")
            dot.setFixedSize(22, 22)
            dot.setAlignment(Qt.AlignmentFlag.AlignCenter)
            text = QLabel(label, bar)
            text.setObjectName(f"recoveryStepLabel{num}")
            apply_text_style(text, TOKENS.typography.caption)
            return dot, text

        self._step1_dot, self._step1_label = make_step(1, "Recovery key")
        self._step2_dot, self._step2_label = make_step(2, "New password")

        rule = QFrame(bar)
        rule.setObjectName("recoveryStepRule")
        rule.setFixedHeight(1)
        rule.setMinimumWidth(40)

        h.addWidget(self._step1_dot)
        h.addWidget(self._step1_label)
        h.addWidget(rule, 1)
        h.addWidget(self._step2_dot)
        h.addWidget(self._step2_label)
        return bar
   
    # Step navigation

    def _goto_step(self, step: int) -> None:
        size = self._STEP1_SIZE if step == 1 else self._STEP2_SIZE
        self.modal.setFixedSize(*size)
        self._stack.setCurrentIndex(step - 1)
        self._update_step_indicator(step)
        if step == 1:
            self._step1.focus_first_word()
        else:
            self._step2.focus_password()

    def _update_step_indicator(self, active: int) -> None:
        for num, dot, label in (
            (1, self._step1_dot, self._step1_label),
            (2, self._step2_dot, self._step2_label),
        ):
            state = (
                "active"
                if num == active
                else ("done" if num < active else "pending")
            )
            dot.setProperty("state", state)
            label.setProperty("state", state)
            for w in (dot, label):
                w.style().unpolish(w)
                w.style().polish(w)

    def _on_back_clicked(self) -> None:
        if self._stack.currentIndex() == 1:
            self._goto_step(1)
            return
        self.back_requested.emit()

    def _on_step2_submit(self, new_password: str) -> None:
        self.set_loading(True)
        words = " ".join(self._step1.words())
        self.recovery_succeeded.emit(new_password, words)

    # Public API
    
    def set_vault_info(self, name: str, path: str) -> None:
        self._vault_name = name
        self._vault_path = path
        self._step1.set_vault_info(name, path)

    def set_loading(self, is_loading: bool) -> None:
        # Disable inputs/buttons across both steps + the global back button.
        self._step1.set_loading(is_loading)
        self._step2.set_loading(is_loading)
        self.back_button.setEnabled(not is_loading)

    def show_error(self, message: str) -> None:
        """Surface a backend-side recovery error. Returns the user to step
        1 if they're on step 2 (a backend rejection means the recovery
        words were wrong)."""
        self.set_loading(False)
        self._goto_step(1)
        self._step1.show_error(message)

    def clear_error(self) -> None:
        self._step1.clear_error()
        self._step2.clear_error()

    def reset(self) -> None:
        self._step1.reset()
        self._step2.reset()
        self._goto_step(1)


__all__ = ["RecoveryInputScreen"]
