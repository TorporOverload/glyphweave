from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QFrame,
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


class LockScreen(QWidget):
    unlock_requested = Signal(str)
    recovery_requested = Signal()
    switch_vault_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self) -> None:
        set_properties(self, role=Role.UNLOCK_VAULT)

        root = QVBoxLayout(self)
        root.setContentsMargins(20, 16, 20, 16)
        root.setSpacing(0)

        intro = QLabel("log in to vault", self)
        apply_text_style(intro, TOKENS.typography.caption)
        set_properties(intro, role=Role.UNLOCK_INTRO)
        root.addWidget(intro, 0, Qt.AlignmentFlag.AlignLeft)

        root.addStretch(1)

        self.modal = QFrame(self)
        set_properties(self.modal, role=Role.UNLOCK_MODAL)
        self.modal.setFixedWidth(440)
        root.addWidget(self.modal, 0, Qt.AlignmentFlag.AlignHCenter)

        layout = QVBoxLayout(self.modal)
        layout.setContentsMargins(24, 19, 24, 22)
        layout.setSpacing(0)

        self.back_button = QPushButton("< Back to vault list", self.modal)
        self.back_button.setCursor(Qt.CursorShape.PointingHandCursor)
        set_properties(self.back_button, role=Role.UNLOCK_BACK)
        self.back_button.clicked.connect(self.switch_vault_requested.emit)
        layout.addWidget(self.back_button, 0, Qt.AlignmentFlag.AlignLeft)

        layout.addSpacing(20)

        # Vault name + path live inside a properties frame so long values can
        # wrap onto multiple lines without forcing horizontal scroll.
        self.properties_frame = QFrame(self.modal)
        self.properties_frame.setObjectName("unlockProperties")
        self.properties_frame.setStyleSheet(
            "#unlockProperties { background-color: #eceff4; "
            "border: 1px solid #c0c9d6; "
            f"border-radius: {TOKENS.radius.md}px; }}"
        )
        properties_layout = QVBoxLayout(self.properties_frame)
        properties_layout.setContentsMargins(14, 12, 14, 12)
        properties_layout.setSpacing(4)

        self.vault_title = QLabel("", self.properties_frame)
        self.vault_title.setAlignment(Qt.AlignmentFlag.AlignLeft)
        self.vault_title.setWordWrap(True)
        self.vault_title.setFont(QFont(TOKENS.typography.family_ui, 22))
        self.vault_title.setStyleSheet(
            "font-weight: 700; "
            f"color: {TOKENS.colors.text_primary.name()}; "
            "letter-spacing: -0.01em; "
            "background: transparent; border: none;"
        )
        properties_layout.addWidget(self.vault_title)

        self.vault_path = QLabel("", self.properties_frame)
        self.vault_path.setAlignment(Qt.AlignmentFlag.AlignLeft)
        self.vault_path.setWordWrap(True)
        apply_text_style(self.vault_path, TOKENS.typography.mono)
        set_properties(self.vault_path, role=Role.UNLOCK_PATH)
        self.vault_path.setStyleSheet(
            (self.vault_path.styleSheet() or "")
            + " QLabel { background: transparent; border: none; }"
        )
        properties_layout.addWidget(self.vault_path)

        layout.addWidget(self.properties_frame)

        layout.addSpacing(20)

        field_label = QLabel("Password", self.modal)
        apply_text_style(field_label, TOKENS.typography.body)
        layout.addWidget(field_label)

        layout.addSpacing(6)

        self.passphrase_input = QLineEdit(self.modal)
        self.passphrase_input.setFixedHeight(40)
        self.passphrase_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.passphrase_input.setPlaceholderText("********")
        self.passphrase_input.returnPressed.connect(self.request_unlock)
        apply_field(self.passphrase_input, role=Role.PASSWORD)
        layout.addWidget(self.passphrase_input)

        layout.addSpacing(16)

        self.unlock_button = QPushButton("unlock", self.modal)
        self.unlock_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.unlock_button.setFixedHeight(40)
        apply_button(self.unlock_button, ButtonVariant.PRIMARY, role=Role.UNLOCK)
        self.unlock_button.clicked.connect(self.request_unlock)
        layout.addWidget(self.unlock_button)

        layout.addSpacing(8)

        self.error_strip = QFrame(self.modal)
        set_properties(self.error_strip, role=Role.ALERT, tone=Tone.ERROR)
        self.error_strip.setFixedHeight(28)
        self.error_strip.setVisible(False)
        error_layout = QVBoxLayout(self.error_strip)
        error_layout.setContentsMargins(11, 5, 11, 5)
        error_layout.setSpacing(0)

        self.error_label = QLabel(
            "x  Incorrect password. Please try again.", self.error_strip
        )
        apply_text_style(self.error_label, TOKENS.typography.caption)
        set_properties(self.error_label, role=Role.ERROR_TEXT)
        error_layout.addWidget(self.error_label)
        layout.addWidget(self.error_strip)

        layout.addSpacing(10)

        self.recovery_button = QPushButton("forgot password", self.modal)
        self.recovery_button.setCursor(Qt.CursorShape.PointingHandCursor)
        set_properties(self.recovery_button, role=Role.UNLOCK_FORGOT)
        self.recovery_button.clicked.connect(self.recovery_requested.emit)
        layout.addWidget(self.recovery_button, 0, Qt.AlignmentFlag.AlignHCenter)

        root.addStretch(1)

    def set_vault_details(self, name: str, path: str) -> None:
        self.vault_title.setText(name)
        self.vault_path.setText(path)

    def set_vault_name(self, name: str) -> None:
        self.vault_title.setText(name)

    def request_unlock(self) -> None:
        passphrase = self.passphrase_input.text().strip()
        if not passphrase:
            self.show_error("Incorrect password. Please try again.")
            return

        self.clear_error()
        self.set_loading(True)
        self.unlock_requested.emit(passphrase)

    def set_loading(self, is_loading: bool) -> None:
        self.unlock_button.setEnabled(not is_loading)
        self.back_button.setEnabled(not is_loading)
        self.recovery_button.setEnabled(not is_loading)
        self.passphrase_input.setEnabled(not is_loading)
        self.unlock_button.setText("unlocking" if is_loading else "unlock")

    def show_error(self, message: str) -> None:
        self.set_loading(False)
        set_field_error(self.passphrase_input, True)
        self.error_label.setText(f"x  {message}")
        self.error_strip.setVisible(True)
        self.passphrase_input.setFocus()

    def clear_error(self) -> None:
        set_field_error(self.passphrase_input, False)
        self.error_strip.setVisible(False)


__all__ = ["LockScreen"]
