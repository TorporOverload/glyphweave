from __future__ import annotations

from typing import Callable
from functools import partial

from PySide6.QtCore import (
    QEvent,
    QObject,
    QPropertyAnimation,
    Qt,
    QTimer,
    Signal,
)
from PySide6.QtWidgets import (
    QFrame,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QLabel,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from app.ui.gui.setup import TOKENS, Tone, apply_text_style, set_tone

AUTO_DISMISS_MS = 4500
FADE_OUT_MS = 200
STACK_MARGIN = 16
# Bottom margin is larger so the stack clears the 36px status footer at the
# bottom of AppShell (otherwise the lowest toast gets visually cut off).
STACK_BOTTOM_MARGIN = 56
STACK_SPACING = 14
MAX_VISIBLE = 5
TOAST_WIDTH = 340  # fixed so the wrapped label can compute its own height


class Toast(QFrame):
    """A single non-blocking notification card."""

    clicked = Signal()
    closed = Signal()

    def __init__(
        self,
        kind: str,
        text: str,
        *,
        has_action: bool,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("toast")
        self.setProperty("kind", kind or "info")
        self.setCursor(
            Qt.CursorShape.PointingHandCursor
            if has_action
            else Qt.CursorShape.ArrowCursor
        )
        # Fixed width - the QLabel inside uses setWordWrap(True), and its
        # heightForWidth() needs a known width before it can report the
        # correct multi-line height. Without this each toast was getting
        # vertically clipped when stacked because their sizeHint() was
        # computed against the wrong width.
        self.setFixedWidth(TOAST_WIDTH)
        # Height grows with content.
        self.setSizePolicy(
            QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Minimum
        )
        self._is_closing = False
        self._build_ui(kind, text, has_action)

    def _build_ui(self, kind: str, text: str, has_action: bool) -> None:
        # Background + border via inline QSS so we don't depend on the global
        # stylesheet picking up our object name. Colors come from tokens.
        bg = TOKENS.colors.bg_elevated
        border = TOKENS.colors.border_default
        if kind == "success":
            bg = TOKENS.colors.status_success_bg
            border = TOKENS.colors.status_success_text
        elif kind == "warn":
            bg = TOKENS.colors.status_warning_bg
            border = TOKENS.colors.status_warning_text
        elif kind == "error":
            bg = TOKENS.colors.status_error_bg
            border = TOKENS.colors.status_error_text

        from app.ui.gui.setup.tokens import to_css_color

        self.setStyleSheet(f"""
            QFrame#toast {{
                background-color: {to_css_color(bg)};
                border: 1px solid {to_css_color(border)};
                border-radius: {TOKENS.radius.sm}px;
            }}
        """)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(8)

        # Warn / error toasts get a small inline marker so they read as
        # alerts even when the user hasn't focused the message text.
        if kind in ("warn", "error"):
            marker = QLabel("!", self)
            marker.setFixedSize(14, 14)
            marker.setAlignment(Qt.AlignmentFlag.AlignCenter)
            marker.setStyleSheet(
                f"background-color: {to_css_color(TOKENS.colors.text_secondary)}; "
                f"color: {to_css_color(TOKENS.colors.text_inverse)}; "
                f"border-radius: 7px; font-size: 9px; font-weight: 700;"
            )
            layout.addWidget(marker)

        body = QLabel(text, self)
        apply_text_style(body, TOKENS.typography.caption)
        body.setWordWrap(True)
        body.setAlignment(
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
        )
        body_sp = QSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum
        )
        body_sp.setHeightForWidth(True)
        body.setSizePolicy(body_sp)
        layout.addWidget(body, 1)

        action_label_w = 0
        if has_action:
            action_hint = QLabel("resolve", self)
            apply_text_style(action_hint, TOKENS.typography.caption)
            set_tone(action_hint, Tone.MUTED)
            action_hint.setStyleSheet(
                action_hint.styleSheet() + " text-decoration: underline;"
            )
            layout.addWidget(action_hint)
            action_label_w = action_hint.sizeHint().width() + 8

        # Compute the body label's wrapped height explicitly, then set a
        # minimum height on the toast frame. Qt's QHBoxLayout doesn't reliably
        # propagate heightForWidth from a wrapping QLabel up to the parent
        # QFrame, so without this the toast collapses to a single line.
        marker_w = (14 + 8) if kind in ("warn", "error") else 0
        h_margins = 12 + 12
        text_w = max(40, TOAST_WIDTH - h_margins - marker_w - action_label_w)
        metrics = body.fontMetrics()
        text_h = metrics.boundingRect(
            0, 0, text_w, 4096, Qt.TextFlag.TextWordWrap, text
        ).height()
        v_margins = 8 + 8
        self.setMinimumHeight(max(36, text_h + v_margins))

    def mousePressEvent(self, event):  # type: ignore[override]
        self.clicked.emit()
        super().mousePressEvent(event)

    def begin_fade_out(self) -> None:
        """Animate fade-to-zero, then emit ``closed``."""
        if self._is_closing:
            return
        self._is_closing = True
        effect = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(effect)
        anim = QPropertyAnimation(effect, b"opacity", self)
        anim.setDuration(FADE_OUT_MS)
        anim.setStartValue(1.0)
        anim.setEndValue(0.0)
        anim.finished.connect(self.closed.emit)
        # Hold a reference so the animation isn't garbage-collected mid-flight.
        self._fade_anim = anim
        anim.start()


class ToastStack(QWidget):
    """Bottom-right overlay that stacks ``Toast`` widgets vertically.

    The stack is mouse-transparent so it never blocks the underlying UI; only
    the individual toast cards inside it accept mouse events.
    """

    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent)
        self.setObjectName("toastStack")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self.setStyleSheet("background: transparent;")
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(STACK_SPACING)
        self._layout.insertStretch(0, 1)
        self._toasts: list[Toast] = []
        self._resize_filter: _ToastResizeFilter | None = None

    # Public API

    def add(
        self,
        kind: str,
        text: str,
        action: Callable[[], None] | None = None,
    ) -> Toast:
        toast = Toast(kind, text, has_action=action is not None, parent=self)
        # Toast cards opt back into mouse events even though the stack itself
        # is transparent - see WA_TransparentForMouseEvents on the stack.
        toast.setAttribute(
            Qt.WidgetAttribute.WA_TransparentForMouseEvents, False
        )
        if action is not None:
            toast.clicked.connect(action)
            toast.clicked.connect(partial(self._dismiss, toast))
        toast.closed.connect(partial(self._remove, toast))

        # Insert after the leading stretch so toasts stack from the bottom.
        self._layout.insertWidget(1, toast)
        self._toasts.append(toast)

        # Cap visible toasts so the stack doesn't grow unbounded. Snap-remove
        # rather than fade so we don't depend on the event loop to release
        # over-cap toasts
        while len(self._toasts) > MAX_VISIBLE:
            self._remove(self._toasts[0])

        QTimer.singleShot(AUTO_DISMISS_MS, partial(self._dismiss, toast))
        self.reposition()
        self.raise_()
        return toast

    def reposition(self) -> None:
        if not self._toasts:
            self.hide()
            return
        self.show()
        toplevel = self.parentWidget()
        if toplevel is None:
            return
        self.setFixedWidth(TOAST_WIDTH)
        total_height = sum(t.sizeHint().height() + STACK_SPACING for t in self._toasts)
        if total_height > 0:
            total_height -= STACK_SPACING
        self.setFixedHeight(total_height)
        self.updateGeometry()
        x = toplevel.width() - self.width() - STACK_MARGIN
        y = toplevel.height() - total_height - STACK_BOTTOM_MARGIN
        self.move(x, y)
        self.raise_()

    # Internal

    def _dismiss(self, toast: Toast) -> None:
        if toast not in self._toasts:
            return
        toast.begin_fade_out()

    def _remove(self, toast: Toast) -> None:
        if toast in self._toasts:
            self._toasts.remove(toast)
        toast.hide()
        toast.deleteLater()
        self.reposition()


class _ToastResizeFilter(QObject):
    """Event filter that calls ``stack.reposition()`` when the host window is
    resized. Installed by ``install_on(window, stack)``."""

    def __init__(self, stack: ToastStack) -> None:
        super().__init__(stack)
        self._stack = stack

    def eventFilter(self, _watched: QObject, event: QEvent) -> bool:
        if event.type() in (
            QEvent.Type.Resize,
            QEvent.Type.Show,
            QEvent.Type.ChildAdded,
        ):
            self._stack.reposition()
            self._stack.raise_()
        return False


def install_on(host: QWidget) -> ToastStack:
    """Create a ``ToastStack`` parented to ``host`` and wire up auto-resize."""
    stack = ToastStack(host)
    filt = _ToastResizeFilter(stack)
    host.installEventFilter(filt)
    stack._resize_filter = filt
    stack.reposition()
    stack.show()
    stack.raise_()
    return stack
