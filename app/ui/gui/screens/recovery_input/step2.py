"""Step 2 of the vault-password recovery flow: set a new vault password.

``RecoveryStep2Page`` presents a standard new-password / confirm-password
form.  It validates locally (minimum 8 characters, fields must match) before
emitting ``submit_requested`` with the validated password string - the actual
re-encryption is performed by the caller (``RecoveryInputScreen``).

Layout
------
* Title + subtitle explaining that re-encryption will occur.
* New-password field with an adjacent "Show / Hide" toggle button.
* Confirm-password field (``returnPressed`` triggers submission).
* A yellow warning row noting that re-encryption invalidates other signed-in
  devices.
* A hidden error strip revealed on validation failure or backend rejection.
* Primary "Reset password && unlock" button (text changes to
  "Re-encrypting…" while loading).

Signals
-------
``submit_requested(new_password: str)``
    Emitted with the validated new password after the user clicks the
    primary button or presses Enter in the confirm field.

Public API
----------
``set_loading(is_loading)``
    Disables all inputs and updates the button label.
``reset()``
    Clears both fields, resets the show-password toggle, and hides errors.
``focus_password()``
    Moves keyboard focus to the new-password field.
``show_error(message)`` / ``clear_error()``
    Show/hide the error strip and field-error styling.
"""
from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
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
    set_field_error,
    set_properties,
)


class RecoveryStep2Page(QWidget):
    """Page 2 of the recovery flow: set a new vault password."""

    submit_requested = Signal(str)  # new_password (validated)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._build_ui()

    # Public API
    
    def set_loading(self, is_loading: bool) -> None:
        self._password_input.setEnabled(not is_loading)
        self._confirm_input.setEnabled(not is_loading)
        self._show_pwd_button.setEnabled(not is_loading)
        self._reset_button.setEnabled(not is_loading)
        # Qt eats the lone `&`, so escape it as `&&`.
        self._reset_button.setText(
            "Re-encrypting…" if is_loading else "Reset password && unlock"
        )

    def reset(self) -> None:
        self._password_input.clear()
        self._confirm_input.clear()
        self._show_pwd_button.setChecked(False)
        self._toggle_password_visibility(False)
        self.clear_error()

    def focus_password(self) -> None:
        self._password_input.setFocus()

    def show_error(self, message: str) -> None:
        set_field_error(self._password_input, True)
        set_field_error(self._confirm_input, True)
        self._error_label.setText(f"x  {message}")
        self._error_strip.setVisible(True)

    def clear_error(self) -> None:
        set_field_error(self._password_input, False)
        set_field_error(self._confirm_input, False)
        self._error_strip.setVisible(False)

    # Internal

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        title = QLabel("Set a new password", self)
        apply_text_style(title, TOKENS.typography.app_title)
        layout.addWidget(title)

        sub = QLabel(
            "Choose a new password for this vault. Your files will be re-encrypted "
            "with this password.",
            self,
        )
        apply_text_style(sub, TOKENS.typography.body)
        sub.setWordWrap(True)
        layout.addWidget(sub)

        layout.addSpacing(6)

        new_label = QLabel("New password", self)
        apply_text_style(new_label, TOKENS.typography.body)
        layout.addWidget(new_label)

        pwd_row = QHBoxLayout()
        pwd_row.setSpacing(8)
        self._password_input = QLineEdit(self)
        self._password_input.setFixedHeight(40)
        self._password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self._password_input.setPlaceholderText("********")
        apply_field(self._password_input, role=Role.PASSWORD)

        self._show_pwd_button = QPushButton("Show", self)
        self._show_pwd_button.setCheckable(True)
        self._show_pwd_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self._show_pwd_button.setFixedHeight(40)
        apply_button(self._show_pwd_button, ButtonVariant.GHOST)
        self._show_pwd_button.toggled.connect(self._toggle_password_visibility)

        pwd_row.addWidget(self._password_input, 1)
        pwd_row.addWidget(self._show_pwd_button)
        layout.addLayout(pwd_row)

        conf_label = QLabel("Confirm new password", self)
        apply_text_style(conf_label, TOKENS.typography.body)
        layout.addWidget(conf_label)

        self._confirm_input = QLineEdit(self)
        self._confirm_input.setFixedHeight(40)
        self._confirm_input.setEchoMode(QLineEdit.EchoMode.Password)
        self._confirm_input.setPlaceholderText("********")
        self._confirm_input.returnPressed.connect(self._on_reset_clicked)
        apply_field(self._confirm_input, role=Role.PASSWORD)
        layout.addWidget(self._confirm_input)

        layout.addWidget(self._build_warning())
        layout.addWidget(self._build_error_strip())

        layout.addStretch(1)

        self._reset_button = QPushButton("Reset password && unlock", self)
        self._reset_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self._reset_button.setFixedHeight(40)
        apply_button(self._reset_button, ButtonVariant.PRIMARY)
        self._reset_button.clicked.connect(self._on_reset_clicked)
        layout.addWidget(self._reset_button)

    def _build_warning(self) -> QFrame:
        warn = QFrame(self)
        warn.setObjectName("recoveryWarnRow")
        warn_layout = QHBoxLayout(warn)
        warn_layout.setContentsMargins(11, 8, 11, 8)
        warn_layout.setSpacing(8)
        warn_icon = QLabel("!", warn)
        warn_icon.setFixedSize(18, 18)
        warn_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        warn_icon.setObjectName("recoveryWarnIcon")
        warn_icon.setStyleSheet(
            f"background-color: {TOKENS.colors.status_warning_text.name()}; "
            f"color: {TOKENS.colors.text_inverse.name()}; "
            f"border-radius: 9px; font-size: 10px; font-weight: 700; "
            f"font-family: 'IBM Plex Sans';"
        )
        warn_text = QLabel(
            "Re-encrypting will invalidate any other devices currently signed in "
            "to this vault.",
            warn,
        )
        warn_text.setWordWrap(True)
        apply_text_style(warn_text, TOKENS.typography.caption)
        warn_layout.addWidget(warn_icon, 0, Qt.AlignmentFlag.AlignTop)
        warn_layout.addWidget(warn_text, 1)
        return warn

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

    def _toggle_password_visibility(self, show: bool) -> None:
        mode = QLineEdit.EchoMode.Normal if show else QLineEdit.EchoMode.Password
        self._password_input.setEchoMode(mode)
        self._confirm_input.setEchoMode(mode)
        self._show_pwd_button.setText("Hide" if show else "Show")

    def _on_reset_clicked(self) -> None:
        password = self._password_input.text()
        confirm = self._confirm_input.text()
        if len(password) < 8:
            self.show_error("Password must be at least 8 characters.")
            return
        if password != confirm:
            self.show_error("Passwords do not match.")
            return
        self.clear_error()
        self.submit_requested.emit(password)


__all__ = ["RecoveryStep2Page"]
