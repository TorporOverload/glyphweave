"""Main application window for the GlyphWeave GUI."""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QMessageBox,
    QStackedWidget,
)

from app.common.logging import logger
from app.services.vault_service import VaultService
from app.ui.gui.setup.resources import load_app_icon

from .gui_utils import TaskThread
from .screens import (
    ConfirmPhraseScreen,
    CreateVaultScreen,
    FileViewScreen,
    LockScreen,
    RecoveryInputScreen,
    RecoveryPhraseScreen,
    VaultListScreen,
)
from .widgets.about_modal import AboutModal
from .widgets.shell import AppShell, MenuBar, VaultTreePanel
from .widgets.toast import ToastStack
from .widgets.toast import install_on as install_toast_stack
from .window import actions as actions
from .window import menu as menu
from .window import routing as routing
from .window import startup as init


class GlypheaveGUI(QMainWindow):
    _task_progress = Signal(int, int, str)  # current, total, label
    _sync_progress = Signal(int, int, str)  # current, total, label
    # Emitted by long-running import tasks every N files so the file view
    # can refresh without waiting for the whole batch to finish. Payload is
    # a `FileViewPayload` built by `_meta.build_file_view_payload`.
    _task_intermediate_refresh = Signal(object)

    def __init__(self, app_data_dir: Path | None = None) -> None:
        super().__init__()
        self._center_on_show = True
        self._shutdown_started = False
        self.setWindowTitle("glyphweave: secure file vault")
        self.setWindowIcon(load_app_icon())
        self.resize(1440, 920)
        # Track every in-flight TaskThread so we can wait on them during
        # closeEvent rather than letting workers outlive the QApplication
        # and write to a torn-down vault.
        self._active_tasks: set[TaskThread] = set()
        self._selected_vault_id: str | None = None

        stack = QStackedWidget(self)
        self.setCentralWidget(stack)
        self.stack = stack

        # Application menu bar (window-level so it is visible on every stage).
        self.menu_bar = MenuBar(self)
        self.setMenuBar(self.menu_bar)
        menu.wire_menu_bar(self)

        self._about_modal: AboutModal | None = None
        self._toasts: ToastStack = install_toast_stack(self)

        # Child screens.
        self.vault_list_screen = VaultListScreen(self)
        self.create_vault_screen = CreateVaultScreen(self)
        self.recovery_phrase_screen = RecoveryPhraseScreen(self)
        self.confirm_phrase_screen = ConfirmPhraseScreen(self)
        self.lock_screen = LockScreen(self)
        self.file_view = FileViewScreen(self)
        self.recovery_input_screen = RecoveryInputScreen(self)

        self.service = VaultService(app_data_dir=app_data_dir)

        # AppShell hosts the post-unlock layout. file_view is owned by the
        # main window and passed in so signal connections on self.file_view
        # remain valid when it gets reparented.
        self.app_shell = AppShell(self.file_view, parent=self)
        self.app_shell.inject_service(self.service)

        self.vault_tree_panel = VaultTreePanel(self.file_view.tree_widget(), self)
        # Vault switch and lock are reachable via the menu bar and the
        # status footer button; the tree panel only owns "home" (jump to
        # vault root) which AppShell wires up in set_tree_panel.
        self.app_shell.set_tree_panel(self.vault_tree_panel)

        init.wire_screen_signals(self)
        self._task_progress.connect(self._on_import_progress)
        self._sync_progress.connect(self._on_sync_progress)
        self._task_intermediate_refresh.connect(
            self._on_intermediate_refresh
        )

        for screen in (
            self.vault_list_screen,
            self.create_vault_screen,
            self.recovery_phrase_screen,
            self.confirm_phrase_screen,
            self.lock_screen,
            self.app_shell,
            self.recovery_input_screen,
        ):
            stack.addWidget(screen)

        self.show_initial_screen()

    def showEvent(self, event) -> None:  # type: ignore[override]
        super().showEvent(event)
        if not self._center_on_show:
            return
        self._center_on_show = False
        screen = (
            self.windowHandle().screen()
            if self.windowHandle() is not None
            else QApplication.primaryScreen()
        )
        if screen is None:
            return
        frame = self.frameGeometry()
        frame.moveCenter(screen.availableGeometry().center())
        self.move(frame.topLeft())

    def closeEvent(self, event) -> None:  # type: ignore[override]
        # Block close-during-import: tearing the service down mid-task
        # would leave the worker writing to a half-cleaned-up vault.
        # Surface a blocking modal and refuse the close - the user can
        # quit again once the import completes.
        if not self._shutdown_started and self._is_importing():
            QMessageBox.warning(
                self,
                "Import in progress",
                "An import is currently running. Please wait for it to "
                "finish before closing GlyphWeave.",
            )
            event.ignore()
            return

        if not self._shutdown_started and self._is_syncing():
            QMessageBox.warning(
                self,
                "Sync in progress",
                "A sync is currently running. Please wait for it to "
                "finish before closing GlyphWeave.",
            )
            event.ignore()
            return

        # If files are still unlocked (FUSE-mounted), warn the user before
        # tearing the app down - closing without locking would silently
        # discard any unsaved edits to those files.
        if not self._shutdown_started and self._has_unlocked_files_open():
            box = QMessageBox(self)
            box.setIcon(QMessageBox.Icon.Warning)
            box.setWindowTitle("Quit GlyphWeave")
            box.setText(
                "You have files still unlocked. Quitting will lock and "
                "unmount them. Continue?"
            )
            proceed = box.addButton(
                "Lock and quit", QMessageBox.ButtonRole.AcceptRole
            )
            cancel = box.addButton(
                "Cancel", QMessageBox.ButtonRole.RejectRole
            )
            box.setDefaultButton(cancel)
            box.exec()
            if box.clickedButton() is not proceed:
                event.ignore()
                return
            try:
                self.app_shell.lock_all_unlocked()
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Lock-on-quit failed: %s", exc, exc_info=True
                )

        if not self._shutdown_started:
            self._shutdown_started = True
            self._join_active_tasks()
            try:
                self.service.cleanup()
            except Exception as exc:
                logger.warning("GUI shutdown cleanup failed: %s", exc, exc_info=True)
        super().closeEvent(event)

    def _join_active_tasks(self, timeout_ms: int = 5000) -> None:
        """Ask each running worker to quit and wait briefly for it to exit.

        Called from ``closeEvent`` so background tasks cannot race the
        service teardown. The wait is capped so a wedged worker can't
        prevent the app from closing - at worst the QThread is leaked.
        """
        for thread in list(self._active_tasks):
            try:
                if thread.isRunning():
                    thread.quit()
                    thread.wait(timeout_ms)
            except RuntimeError:
                # Underlying QThread was already deleted by Qt.
                pass
        self._active_tasks.clear()

    def _has_unlocked_files_open(self) -> bool:
        shell = getattr(self, "app_shell", None)
        if shell is None:
            return False
        try:
            return bool(shell.has_unlocked_files())
        except Exception:  # noqa: BLE001
            return False

    def _is_importing(self) -> bool:
        shell = getattr(self, "app_shell", None)
        if shell is None:
            return False
        try:
            return bool(shell.is_importing())
        except Exception:  # noqa: BLE001
            return False

    def _is_syncing(self) -> bool:
        shell = getattr(self, "app_shell", None)
        if shell is None:
            return False
        try:
            return bool(shell.is_syncing())
        except Exception:  # noqa: BLE001
            return False

    def _run_task(
        self,
        task_fn: Callable[[], object],
        *,
        on_success: Callable[[object], None] | None = None,
        on_error: Callable[[str], None] | None = None,
        error_title: str = "Operation failed",
        before: Callable[[], None] | None = None,
        after: Callable[[], None] | None = None,
        block_ui: bool = True,
    ) -> None:
        if before:
            before()
        if block_ui:
            self._set_busy(True)

        thread = TaskThread(task_fn, parent=self)

        def _on_finished() -> None:
            self._active_tasks.discard(thread)
            thread.deleteLater()

        def handle_success(result: object) -> None:
            if after:
                after()
            if on_success:
                on_success(result)
            if block_ui:
                self._set_busy(False)

        def handle_failure(error: str) -> None:
            if block_ui:
                self._set_busy(False)
            if on_error:
                on_error(error)
            else:
                self._show_task_failure_dialog(error_title, error)

        thread.succeeded.connect(handle_success)
        thread.failed.connect(handle_failure)
        thread.finished.connect(_on_finished)
        if hasattr(thread, "progress"):
            thread.progress.connect(self._task_progress.emit)
        self._active_tasks.add(thread)
        thread.start()

    def _show_task_failure_dialog(self, title: str, error: str) -> None:
        """Surface a task error without dumping raw backend details into
        the visible message text. The user sees a generic message; the
        full exception string (which can contain vault paths, ids, or
        SQLCipher diagnostics) goes behind 'Show Details'."""
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle(title)
        box.setText(f"{title}.")
        box.setInformativeText(
            "Click 'Show Details' for the underlying error message."
        )
        box.setDetailedText(error)
        box.setStandardButtons(QMessageBox.StandardButton.Ok)
        box.exec()

    def _set_busy(self, busy: bool) -> None:
        central = self.centralWidget()
        if central is not None:
            central.setEnabled(not busy)
        if busy:
            QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
            return
        QApplication.restoreOverrideCursor()

    def add_toast(
        self, kind: str, text: str, action: Callable[[], None] | None = None
    ) -> None:
        """Public API for non-blocking notifications. ``kind`` is one of
        ``"success"``, ``"info"``, ``"warn"``, ``"error"``. ``action`` is an
        optional zero-arg callable invoked when the user clicks the toast."""
        self._toasts.add(kind, text, action=action)

    def _on_import_progress(self, current: int, total: int, label: str) -> None:
        # ``label`` is the current source filename (or "" on completion).
        # Empty label + total == 0 means the worker is signalling the end
        # of the batch; everything else is a per-file progress tick that
        # drives the import progress pill's fill width.
        if label or total > 0:
            self.app_shell.update_importing_status(current, total, label)
        else:
            self.app_shell.hide_importing_status()

    def _on_sync_progress(self, current: int, total: int, label: str) -> None:
        if label or total > 0:
            self.app_shell.update_syncing_status(current, total, label)
        else:
            self.app_shell.hide_syncing_status()

    def _on_intermediate_refresh(self, payload: object) -> None:
        """UI-thread slot for intermediate refresh signals from a worker.

        Skips errors silently - the final post-task refresh is the
        authoritative one; this just keeps the table feeling alive during
        long batch imports.
        """
        try:
            self._handle_file_view_loaded(payload, show_screen=False)
        except Exception as exc:  # noqa: BLE001
            logger.debug(
                "Intermediate refresh failed: %s", exc, exc_info=True
            )

    def _show_about_modal(self) -> None:
        if self._about_modal is None:
            self._about_modal = AboutModal(self)
        self._about_modal.exec()

    def _set_vault_unlocked_in_menu(self, unlocked: bool) -> None:
        self.menu_bar.set_vault_unlocked(unlocked)

    def _show_error(self, title: str, message: str) -> None:
        QMessageBox.critical(self, title, message)

    def _show_warning(self, title: str, message: str) -> None:
        QMessageBox.warning(self, title, message)

    def show_initial_screen(self) -> None:
        routing.show_initial_screen(self)

    def show_vault_list_screen(self) -> None:
        routing.show_vault_list_screen(self)

    def show_create_vault_screen(self) -> None:
        routing.show_create_vault_screen(self)

    def show_create_vault_form(self) -> None:
        routing.show_create_vault_form(self)

    def show_recovery_input_screen(self) -> None:
        routing.show_recovery_input_screen(self)

    def show_lock_screen(self) -> None:
        routing.show_lock_screen(self)

    def show_lock_screen_for_vault(self, vault_id: str) -> None:
        routing.show_lock_screen_for_vault(self, vault_id)

    def handle_delete_vault(self, vault_id: str) -> None:
        routing.handle_delete_vault(self, vault_id)

    def show_file_view(self) -> None:
        routing.show_file_view(self)

    def refresh_file_view(self) -> None:
        routing.refresh_file_view(self)

    def handle_create_vault(self, vault_name: str) -> None:
        routing.handle_create_vault(self, vault_name)

    def handle_unlock(self, passphrase: str) -> None:
        routing.handle_unlock(self, passphrase)

    def handle_vault_created(self) -> None:
        # The user just confirmed the recovery phrase - drop the cached
        # words and clear the displayed mnemonic so they don't linger as
        # widget text / window state for the rest of the session.
        routing.clear_pending_recovery_words(self)
        self.recovery_phrase_screen.clear_words()
        # Loads payload then routes through _show_app_shell_with_payload.
        self.show_file_view()

    def _handle_file_view_loaded(self, result: object, *, show_screen: bool) -> None:
        routing.handle_file_view_loaded(self, result, show_screen=show_screen)

    def _handle_prepared_vault(self, result: object) -> None:
        routing.handle_prepared_vault(self, result)

    def _handle_lock_request(self) -> None:
        routing.handle_lock_request(self)

    def open_file_from_view(self, file_ref_id: int) -> None:
        actions.open_file_from_view(self, file_ref_id)

    def reopen_unlocked_file(self, file_ref_id: int) -> None:
        actions.reopen_unlocked_file(self, file_ref_id)

    def lock_unlocked_file(self, file_ref_id: int) -> None:
        actions.lock_unlocked_file(self, file_ref_id)

    def import_into_vault(
        self, paths: object, destination_folder_virtual_path: str
    ) -> None:
        actions.import_into_vault(self, paths, destination_folder_virtual_path)

    def delete_selected_entries(self, paths: object) -> None:
        actions.delete_selected_entries(self, paths)

    def create_folder_in_vault(
        self, folder_name: str, parent_virtual_path: str
    ) -> None:
        actions.create_folder_in_vault(self, folder_name, parent_virtual_path)

    def export_selected_entries(self, paths: object) -> None:
        actions.export_selected_entries(self, paths)

    def rename_entry(self, virtual_path: str, new_name: str) -> None:
        actions.rename_entry(self, virtual_path, new_name)

    def move_entries(self, payload: tuple[list[str], str]) -> None:
        actions.move_entries(self, payload)

    def import_existing_vault(self) -> None:
        actions.import_existing_vault(self)


gui_main = init.main
