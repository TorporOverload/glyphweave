from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from app.ui.gui.setup.theme import (
    apply_alert_variant,
    apply_badge_variant,
    apply_button,
    apply_card_style,
    apply_text_style,
)
from app.ui.gui.setup.tokens import (
    TOKENS,
    AlertVariant,
    BadgeVariant,
    ButtonVariant,
    StatusKey,
)


class CardFrame(QFrame):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        apply_card_style(self)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(
            TOKENS.spacing.xl,
            TOKENS.spacing.xl,
            TOKENS.spacing.xl,
            TOKENS.spacing.xl,
        )
        layout.setSpacing(TOKENS.spacing.lg)


class BadgeLabel(QLabel):
    def __init__(
        self,
        text: str = "",
        variant: BadgeVariant = BadgeVariant.NEUTRAL,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(text, parent)
        apply_text_style(self, TOKENS.typography.badge)
        apply_badge_variant(self, variant)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)

    def set_variant(self, variant: BadgeVariant) -> None:
        apply_badge_variant(self, variant)


class StatusBadge(BadgeLabel):
    def __init__(
        self,
        status: StatusKey,
        parent: QWidget | None = None,
    ) -> None:
        self._status = status
        spec = TOKENS.statuses[status]
        super().__init__(spec.label, spec.badge_variant, parent)

    def set_status(self, status: StatusKey) -> None:
        self._status = status
        spec = TOKENS.statuses[status]
        self.setText(spec.label)
        self.set_variant(spec.badge_variant)

    @property
    def status(self) -> StatusKey:
        return self._status


class AlertBanner(QFrame):
    def __init__(
        self,
        variant: AlertVariant = AlertVariant.INFO,
        *,
        title: str = "",
        body: str = "",
        action_text: str | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._variant = variant
        apply_alert_variant(self, variant)

        outer = QHBoxLayout(self)
        outer.setContentsMargins(
            TOKENS.spacing.lg,
            TOKENS.spacing.lg,
            TOKENS.spacing.lg,
            TOKENS.spacing.lg,
        )
        outer.setSpacing(TOKENS.spacing.md)

        self.icon_label = QLabel(self._icon_for_variant(variant), self)
        apply_text_style(self.icon_label, TOKENS.typography.section_title)
        self.icon_label.setAlignment(Qt.AlignmentFlag.AlignTop)
        outer.addWidget(self.icon_label)

        content = QVBoxLayout()
        content.setContentsMargins(0, 0, 0, 0)
        content.setSpacing(TOKENS.spacing.sm)

        self.title_label = QLabel(title, self)
        apply_text_style(self.title_label, TOKENS.typography.card_title)
        self.title_label.setWordWrap(True)
        content.addWidget(self.title_label)

        self.body_label = QLabel(body, self)
        apply_text_style(self.body_label, TOKENS.typography.body)
        self.body_label.setWordWrap(True)
        content.addWidget(self.body_label)

        self.action_button = QPushButton(self)
        apply_button(self.action_button, ButtonVariant.GHOST, size="sm")
        self.action_button.setVisible(False)
        content.addWidget(self.action_button, 0, Qt.AlignmentFlag.AlignLeft)

        outer.addLayout(content, 1)

        self.set_message(title=title, body=body, action_text=action_text)

    def set_variant(self, variant: AlertVariant) -> None:
        self._variant = variant
        apply_alert_variant(self, variant)
        self.icon_label.setText(self._icon_for_variant(variant))

    def set_message(
        self,
        *,
        title: str,
        body: str,
        action_text: str | None = None,
    ) -> None:
        self.title_label.setText(title)
        self.body_label.setText(body)
        if action_text:
            self.action_button.setText(action_text)
            self.action_button.setVisible(True)
        else:
            self.action_button.setVisible(False)

    @staticmethod
    def _icon_for_variant(variant: AlertVariant) -> str:
        icons = {
            AlertVariant.INFO: "[i]",
            AlertVariant.SUCCESS: "[ok]",
            AlertVariant.WARNING: "[!]",
            AlertVariant.WARNING_STRONG: "[!]",
            AlertVariant.ERROR: "[x]",
            AlertVariant.CONFLICT: "[<>]",
        }
        return icons[variant]
