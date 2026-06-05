from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QStackedLayout,
    QVBoxLayout,
    QWidget,
)

from app.ui.gui.setup import (
    TOKENS,
    ButtonVariant,
    Role,
    apply_button,
    apply_text_style,
    set_properties,
)
from app.ui.gui.setup.icons import tinted_icon


def _font(
    *,
    family: str,
    size_px: int,
    weight: QFont.Weight,
) -> QFont:
    font = QFont(family)
    font.setPixelSize(size_px)
    font.setWeight(weight)
    return font


class EmptyVaultBackground(QWidget):
    continue_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self) -> None:
        set_properties(self, role=Role.EMPTY_VAULT)

        root = QVBoxLayout(self)
        root.setContentsMargins(48, 64, 48, 40)
        root.setSpacing(0)

        root.addStretch(1)

        # Wordmark: glyph<accent>weave</accent> - thin weight, 64px
        accent_hex = TOKENS.colors.focus_ring.name()
        self.title_label = QLabel(self)
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        self.title_label.setTextFormat(Qt.TextFormat.RichText)
        self.title_label.setText(
            f"""<span style=\"font-family:'IBM Plex Sans'; font-size:64px;
            font-weight:100; color:#2e3440;\">"""
            f'glyph<span style="color:{accent_hex};">weave</span>'
            f"</span>"
        )  
        root.addWidget(self.title_label)

        root.addSpacing(10)

        self.subtitle_label = QLabel("where your files stay yours", self)
        self.subtitle_label.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        self.subtitle_label.setFont(
            _font(
                family=TOKENS.typography.family_mono,
                size_px=12,
                weight=QFont.Weight.Normal,
            )
        )
        set_properties(self.subtitle_label, role=Role.SPLASH_COPY)
        root.addWidget(self.subtitle_label)

        root.addSpacing(48)

        # Dashed note card with pulsing dot
        note_frame = QFrame(self)
        note_frame.setObjectName("WelcomeNote")
        accent_border = TOKENS.colors.border_default.name()
        bg = TOKENS.colors.bg_elevated.name()
        note_frame.setStyleSheet(
            f"QFrame#WelcomeNote {{"
            f"  background-color: {bg};"
            f"  border: 1px dashed {accent_border};"
            f"  border-radius: 6px;"
            f"}}"
        )
        note_layout = QHBoxLayout(note_frame)
        note_layout.setContentsMargins(16, 12, 16, 12)
        note_layout.setSpacing(10)

        copy_label = QLabel(
            "No vaults detected on this device. Continue to create your first vault.",
            note_frame,
        )
        copy_label.setFont(
            _font(
                family=TOKENS.typography.family_mono,
                size_px=11,
                weight=QFont.Weight.Normal,
            )
        )
        copy_label.setWordWrap(True)
        set_properties(copy_label, role=Role.SPLASH_COPY)
        note_layout.addWidget(copy_label, 1)

        _note_row = QHBoxLayout()
        _note_row.setContentsMargins(0, 0, 0, 0)
        _note_row.addStretch()
        _note_row.addWidget(note_frame)
        _note_row.addStretch()
        root.addLayout(_note_row)
        note_frame.setMaximumWidth(560)

        root.addSpacing(20)

        self.continue_button = QPushButton("Continue", self)
        apply_button(
            self.continue_button, ButtonVariant.PRIMARY, role=Role.CREATE_VAULT
        )
        self.continue_button.setFixedSize(120, 44)
        self.continue_button.clicked.connect(self.continue_requested.emit)
        root.addWidget(self.continue_button, 0, Qt.AlignmentFlag.AlignHCenter)

        root.addStretch(1)

    def focus_continue(self) -> None:
        self.continue_button.setFocus()


class NewVaultFrame(QWidget):
    vault_created = Signal(str)
    import_existing_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self) -> None:
        set_properties(self, role=Role.EMPTY_VAULT)

        root = QVBoxLayout(self)
        root.setContentsMargins(48, 48, 48, 48)
        root.setSpacing(0)
        root.addStretch(1)

        self.modal = QFrame(self)
        set_properties(self.modal, role=Role.CREATE_VAULT_MODAL)
        self.modal.setFixedSize(420, 516)
        root.addWidget(self.modal, 0, Qt.AlignmentFlag.AlignHCenter)
        root.addStretch(1)

        layout = QVBoxLayout(self.modal)
        layout.setContentsMargins(20, 32, 20, 20)
        layout.setSpacing(8)

        self.title_label = QLabel("Create a new Vault", self.modal)
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        self.title_label.setFont(
            _font(
                family=TOKENS.typography.family_ui,
                size_px=20,
                weight=QFont.Weight.DemiBold,
            )
        )
        layout.addWidget(self.title_label)

        layout.addSpacing(10)

        self.name_label = self._make_field_label("Vault name")
        layout.addWidget(self.name_label)

        self.name_input = self._make_field(placeholder="my-vault")
        layout.addWidget(self.name_input)

        layout.addSpacing(4)

        self.location_label = self._make_field_label("Storage Location")
        layout.addWidget(self.location_label)

        location_row = QHBoxLayout()
        location_row.setContentsMargins(0, 0, 0, 0)
        location_row.setSpacing(8)

        self.location_input = self._make_field(
            placeholder="C:\\Users\\...\\Vaults\\",
            mono=True,
        )
        location_row.addWidget(self.location_input, 1)

        self.location_button = QPushButton(self.modal)
        apply_button(self.location_button, ButtonVariant.ICON, role=Role.CREATE_VAULT)
        self.location_button.setFixedSize(36, 36)
        self.location_button.setIcon(
            tinted_icon("folder-open", size=16, color=TOKENS.colors.text_primary)
        )
        self.location_button.setIconSize(QSize(16, 16))
        self.location_button.setToolTip("Browse for vault location")
        self.location_button.clicked.connect(self._select_storage_location)
        location_row.addWidget(self.location_button)

        layout.addLayout(location_row)

        layout.addSpacing(4)

        self.password_label = self._make_field_label("Password")
        layout.addWidget(self.password_label)

        self.password_input = self._make_field(placeholder="********", mono=True)
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.password_input)

        layout.addSpacing(4)

        self.confirm_label = self._make_field_label("Confirm Password")
        layout.addWidget(self.confirm_label)

        self.confirm_input = self._make_field(placeholder="**********", mono=True)
        self.confirm_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.confirm_input)

        layout.addSpacing(12)

        self.create_button = QPushButton("Create Vault", self.modal)
        apply_button(self.create_button, ButtonVariant.PRIMARY, role=Role.CREATE_VAULT)
        self.create_button.setFixedHeight(36)
        self.create_button.clicked.connect(self._emit_created)
        layout.addWidget(self.create_button)

        layout.addSpacing(6)

        divider = QHBoxLayout()
        divider.setContentsMargins(0, 0, 0, 0)
        divider.setSpacing(8)

        left_divider = QFrame(self.modal)
        set_properties(left_divider, role=Role.CREATE_VAULT_DIVIDER)
        divider.addWidget(left_divider, 1)

        self.existing_label = QLabel("Already have a vault?", self.modal)
        self.existing_label.setFont(
            _font(
                family=TOKENS.typography.family_mono,
                size_px=12,
                weight=QFont.Weight.Normal,
            )
        )
        set_properties(self.existing_label, role=Role.CREATE_VAULT_CAPTION)
        divider.addWidget(self.existing_label, 0, Qt.AlignmentFlag.AlignCenter)

        right_divider = QFrame(self.modal)
        set_properties(right_divider, role=Role.CREATE_VAULT_DIVIDER)
        divider.addWidget(right_divider, 1)

        layout.addLayout(divider)

        layout.addSpacing(6)

        self.import_button = QPushButton("Import an existing vault", self.modal)
        apply_button(
            self.import_button, ButtonVariant.SECONDARY, role=Role.CREATE_VAULT
        )
        self.import_button.setFixedHeight(36)
        self.import_button.clicked.connect(self.import_existing_requested.emit)
        layout.addWidget(self.import_button)

    def _make_field_label(self, text: str) -> QLabel:
        label = QLabel(text, self.modal)
        apply_text_style(label, TOKENS.typography.body)
        return label

    def _make_field(self, *, placeholder: str, mono: bool = False) -> QLineEdit:
        field = QLineEdit(self.modal)
        set_properties(field, role=Role.CREATE_VAULT_FIELD)
        field.setFixedHeight(36)
        field.setPlaceholderText(placeholder)
        if mono:
            field.setFont(
                _font(
                    family=TOKENS.typography.family_mono,
                    size_px=11,
                    weight=QFont.Weight.Normal,
                )
            )
        else:
            apply_text_style(field, TOKENS.typography.body)
        return field

    def _select_storage_location(self) -> None:
        start_dir = self.location_input.text().strip()
        if not start_dir:
            start_dir = str(Path.home() / "Vaults")

        selected = QFileDialog.getExistingDirectory(
            self,
            "Choose Vault Location",
            start_dir,
        )
        if selected:
            self.location_input.setText(selected)

    def _emit_created(self) -> None:
        vault_name = self.name_input.text().strip() or self.name_input.placeholderText()
        self.vault_created.emit(vault_name)

    def focus_name_input(self) -> None:
        self.name_input.setFocus()

    def reset(self) -> None:
        self.name_input.clear()
        self.location_input.clear()
        self.password_input.clear()
        self.confirm_input.clear()


class CreateVaultScreen(QWidget):
    vault_created = Signal(str)
    import_existing_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self) -> None:
        stack = QStackedLayout(self)
        self._stack = stack

        self.background = EmptyVaultBackground(self)
        self.background.continue_requested.connect(self.show_form)
        stack.addWidget(self.background)

        self.new_vault_frame = NewVaultFrame(self)
        self.new_vault_frame.vault_created.connect(self.vault_created.emit)
        self.new_vault_frame.import_existing_requested.connect(
            self.import_existing_requested.emit
        )
        stack.addWidget(self.new_vault_frame)

        self.show_background()

    def show_background(self) -> None:
        self.new_vault_frame.reset()
        self._stack.setCurrentWidget(self.background)
        self.background.focus_continue()

    def show_form(self) -> None:
        self._stack.setCurrentWidget(self.new_vault_frame)
        self.new_vault_frame.focus_name_input()
