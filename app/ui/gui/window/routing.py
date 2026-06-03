from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QMessageBox

from app.common.logging import logger

from . import tasks as _tasks
from ..gui_utils import (
    CreatedVaultResult,
    FileViewPayload,
    PreparedVaultResult,
)
from ..screens import VaultListEntry

if TYPE_CHECKING:
    from ..glyphweave_ui import GlypheaveGUI


def show_initial_screen(window: "GlypheaveGUI") -> None:
    show_create_vault_screen(window)
    window._run_task(
        lambda: _tasks.load_vault_entries(window),
        on_success=lambda r: handle_initial_entries_loaded(window, r),
        error_title="Failed to load vault list",
    )


def show_vault_list_screen(window: "GlypheaveGUI") -> None:
    window._run_task(
        lambda: _tasks.load_vault_entries(window),
        on_success=lambda r: handle_vault_list_loaded(window, r),
        error_title="Failed to load vault list",
    )


def show_create_vault_screen(window: "GlypheaveGUI") -> None:
    """Initial / no-vaults entry: show the welcome splash. The user clicks
    the splash's Continue button to reveal the form."""
    window.create_vault_screen.show_background()
    window.stack.setCurrentWidget(window.create_vault_screen)


def show_create_vault_form(window: "GlypheaveGUI") -> None:
    """Direct path to the form (used when the user explicitly clicks
    '+ Create a new vault' from the vault list or 'New Vault…' from the
    menubar) - skips the welcome splash."""
    window.create_vault_screen.show_form()
    window.stack.setCurrentWidget(window.create_vault_screen)


def show_recovery_input_screen(window: "GlypheaveGUI") -> None:
    if window._selected_vault_id:
        entry = window.vault_list_screen.entry_for_id(window._selected_vault_id)
        if entry:
            window.recovery_input_screen.set_vault_info(entry.name, entry.path)
    window.stack.setCurrentWidget(window.recovery_input_screen)
    window.recovery_input_screen.reset()


def show_lock_screen(window: "GlypheaveGUI") -> None:
    window.lock_screen.set_loading(False)
    window.lock_screen.passphrase_input.clear()
    window.lock_screen.clear_error()
    window.stack.setCurrentWidget(window.lock_screen)
    window.lock_screen.passphrase_input.setFocus()


def show_lock_screen_for_vault(
    window: "GlypheaveGUI", vault_id: str
) -> None:
    entry = window.vault_list_screen.entry_for_id(vault_id)
    if entry is None:
        window._show_error(
            "Vault not found",
            "The selected vault is no longer available in the local registry.",
        )
        show_vault_list_screen(window)
        return
    window._run_task(
        lambda: _tasks.prepare_vault(window, entry),
        on_success=lambda r: handle_prepared_vault(window, r),
        error_title="Failed to prepare vault",
    )


def show_file_view(window: "GlypheaveGUI") -> None:
    window._run_task(
        lambda: _tasks.load_file_view_payload(window),
        on_success=lambda payload: handle_file_view_loaded(
            window, payload, show_screen=True
        ),
        error_title="Failed to load vault",
    )


def refresh_file_view(window: "GlypheaveGUI") -> None:
    window._run_task(
        lambda: _tasks.load_file_view_payload(window),
        on_success=lambda payload: handle_file_view_loaded(
            window, payload, show_screen=False
        ),
        error_title="Failed to refresh vault view",
    )


def handle_create_vault(
    window: "GlypheaveGUI", _vault_name: str
) -> None:
    frame = window.create_vault_screen.new_vault_frame
    vault_name = frame.name_input.text().strip()
    location_text = frame.location_input.text().strip()
    password = frame.password_input.text()
    confirm = frame.confirm_input.text()

    if not vault_name:
        window._show_warning(
            "Vault name required",
            "Enter a vault name before creating the vault.",
        )
        return
    if not password:
        window._show_warning(
            "Password required", "Enter a password to create the vault."
        )
        return
    if password != confirm:
        window._show_warning(
            "Password mismatch", "Password and confirmation do not match."
        )
        return

    parent_dir = (
        Path(location_text).expanduser()
        if location_text
        else Path.home() / "Vaults"
    )
    vault_path = parent_dir / vault_name
    window._run_task(
        lambda: _tasks.create_vault(window, vault_path, vault_name, password),
        on_success=lambda r: handle_created_vault(window, r),
        error_title="Vault creation failed",
    )


def handle_unlock(window: "GlypheaveGUI", passphrase: str) -> None:
    window._run_task(
        lambda: _tasks.unlock_and_load(window, passphrase),
        on_success=lambda r: handle_unlocked_vault(window, r),
        error_title="Unlock failed",
        on_error=window.lock_screen.show_error,
    )


def handle_recovery_succeeded(
    window: "GlypheaveGUI",
    new_password: str,
    recovery_phrase: str,
) -> None:
    # The recovery words + new password are only needed for the duration of
    # this one service call. Snapshot them into the closure, then null the
    # references on this stack so the originals can be garbage-collected
    # once the input widgets are cleared. (Python strings are immutable so
    # we can't actually wipe the memory. so the goal is just to avoid extra
    # long-lived references.)
    words = recovery_phrase.split()

    def task() -> None:
        window.service.recover_vault(words, new_password)

    def _on_success(_result: object) -> None:
        # Drop the recovery-input form contents before navigating back to
        # the lock screen so the words don't linger in QLineEdits.
        window.recovery_input_screen.reset()
        clear_pending_recovery_words(window)
        show_lock_screen(window)

    def _on_error(message: str) -> None:
        window.recovery_input_screen.show_error(message)

    window._run_task(
        task,
        on_success=_on_success,
        on_error=_on_error,
        error_title="Recovery failed",
    )


def clear_pending_recovery_words(window: "GlypheaveGUI") -> None:
    """Discard the cached recovery phrase from the window. Call this after
    the confirm-phrase step succeeds or the recovery flow finishes."""
    if hasattr(window, "_pending_recovery_words"):
        try:
            window._pending_recovery_words.clear()
        except AttributeError:
            pass
        window._pending_recovery_words = []


# Result handlers

def handle_initial_entries_loaded(
    window: "GlypheaveGUI", result: object
) -> None:
    entries = list(result) if isinstance(result, list) else []
    if entries:
        show_vault_list_entries(window, entries)
        return
    show_create_vault_screen(window)


def handle_created_vault(
    window: "GlypheaveGUI", result: object
) -> None:
    if not isinstance(result, CreatedVaultResult):
        raise TypeError("Unexpected vault creation result.")
    window._selected_vault_id = result.vault_id
    # Cache the freshly generated phrase so the confirm-phrase screen can
    # validate against it without round-tripping to the service.
    window._pending_recovery_words = list(result.recovery_words)
    window.recovery_phrase_screen.set_words(result.recovery_words)
    window.recovery_phrase_screen.reset()
    window.stack.setCurrentWidget(window.recovery_phrase_screen)


def show_recovery_phrase_screen(window: "GlypheaveGUI") -> None:
    """"Back to phrase" target from the confirm screen."""
    window.stack.setCurrentWidget(window.recovery_phrase_screen)


def show_confirm_phrase_screen(window: "GlypheaveGUI") -> None:
    words = list(getattr(window, "_pending_recovery_words", []) or [])
    if len(words) < 24:
        # No phrase cached (shouldn't normally happen) - skip the
        # confirmation step rather than block the user with a broken UI.
        window.handle_vault_created()
        return
    window.confirm_phrase_screen.set_words(words)
    window.stack.setCurrentWidget(window.confirm_phrase_screen)


def handle_unlocked_vault(
    window: "GlypheaveGUI", result: object
) -> None:
    if not isinstance(result, FileViewPayload):
        raise TypeError("Unexpected unlock result.")
    window.lock_screen.set_loading(False)
    window.lock_screen.passphrase_input.clear()
    window.lock_screen.clear_error()
    show_app_shell_with_payload(window, result)
    window.add_toast("success", f"Unlocked {result.vault_name}")
    window.app_shell.start_sync()


def handle_vault_list_loaded(
    window: "GlypheaveGUI", result: object
) -> None:
    entries = list(result) if isinstance(result, list) else []
    if not entries:
        show_create_vault_screen(window)
        return
    show_vault_list_entries(window, entries)


def handle_delete_vault(window: "GlypheaveGUI", vault_id: str) -> None:
    entry = window.vault_list_screen.entry_for_id(vault_id)
    if entry is None:
        return
    box = QMessageBox(window)
    box.setIcon(QMessageBox.Icon.Warning)
    box.setWindowTitle("Delete vault")
    box.setText(f"Remove “{entry.name}” from GlyphWeave?")
    box.setInformativeText(
        "This only deletes the local registry entry and cached metadata under "
        ".glyphweave/vaults/<vault_id>. The vault directory at\n\n"
        f"{entry.path}\n\nis not touched and can be re-imported later."
    )
    delete_btn = box.addButton("Delete", QMessageBox.ButtonRole.DestructiveRole)
    cancel_btn = box.addButton("Cancel", QMessageBox.ButtonRole.RejectRole)
    box.setDefaultButton(cancel_btn)
    box.exec()
    if box.clickedButton() is not delete_btn:
        return
    window._run_task(
        lambda: _tasks.delete_vault_record_and_reload(window, vault_id),
        on_success=lambda r: _after_vault_deleted(window, entry, r),
        error_title="Failed to delete vault",
    )


def _after_vault_deleted(
    window: "GlypheaveGUI", entry, result: object
) -> None:
    handle_vault_list_loaded(window, result)
    window.add_toast("success", f"Vault “{entry.name}” record removed.")
    follow_up = QMessageBox(window)
    follow_up.setIcon(QMessageBox.Icon.Information)
    follow_up.setWindowTitle("Vault folder still on disk")
    follow_up.setText(
        f"GlyphWeave forgot “{entry.name}”, but the vault folder is still on disk."
    )
    follow_up.setInformativeText(
        "To completely remove the vault, open the folder below and delete its "
        "contents yourself:\n\n"
        f"{entry.path}"
    )
    open_btn = follow_up.addButton(
        "Open folder", QMessageBox.ButtonRole.ActionRole
    )
    close_btn = follow_up.addButton("Close", QMessageBox.ButtonRole.AcceptRole)
    follow_up.setDefaultButton(close_btn)
    follow_up.exec()
    if follow_up.clickedButton() is open_btn and entry.path:
        QDesktopServices.openUrl(QUrl.fromLocalFile(entry.path))


def handle_prepared_vault(
    window: "GlypheaveGUI", result: object
) -> None:
    if not isinstance(result, PreparedVaultResult):
        raise TypeError("Unexpected prepared vault result.")
    window._selected_vault_id = result.vault_id
    window.lock_screen.set_vault_details(result.name, result.path)
    show_lock_screen(window)


def handle_file_view_loaded(
    window: "GlypheaveGUI", result: object, *, show_screen: bool
) -> None:
    if not isinstance(result, FileViewPayload):
        raise TypeError("Unexpected file view payload.")
    apply_file_view_payload(window, result, show_screen=show_screen)


def apply_file_view_payload(
    window: "GlypheaveGUI",
    payload: FileViewPayload,
    *,
    show_screen: bool,
) -> None:
    # Route through AppShell so the sidebar header, vault selector,
    # status-footer counts, and search-screen state all update together
    # - calling file_view.set_vault_data directly skips the chrome.
    window.app_shell.set_vault_data(
        payload, preserve_navigation=not show_screen
    )
    if show_screen:
        window.app_shell.navigate("Library")
        window.stack.setCurrentWidget(window.app_shell)
        window._set_vault_unlocked_in_menu(True)


def show_app_shell_with_payload(
    window: "GlypheaveGUI", payload: FileViewPayload
) -> None:
    """Populate AppShell with vault data and navigate to the Library screen."""
    window.app_shell.set_vault_data(payload)
    window.app_shell.navigate("Library")
    window.stack.setCurrentWidget(window.app_shell)
    window._set_vault_unlocked_in_menu(True)


def handle_lock_request(window: "GlypheaveGUI") -> None:
    """Lock the vault and return to the LockScreen.

    If the user has files currently unlocked (e.g. an Office document
    open through the FUSE mount), prompt before locking - locking the
    vault unmounts files and would silently break any unsaved edits.

    A running batch import blocks locking entirely: cleanup would tear
    down the service mid-task and leave the import in an inconsistent
    state. Surface a blocking error rather than racing the worker.
    """
    if window.app_shell.is_importing():
        QMessageBox.warning(
            window,
            "Import in progress",
            "An import is currently running. Please wait for it to finish "
            "before locking the vault.",
        )
        return
    if window.app_shell.is_syncing():
        QMessageBox.warning(
            window,
            "Sync in progress",
            "A sync is currently running. Please wait for it to finish "
            "before locking the vault.",
        )
        return
    if window.app_shell.has_unlocked_files():
        if not _confirm_lock_unlocked_files(
            window,
            title="Lock vault",
            text=(
                "You have files still unlocked. Locking the vault will lock "
                "and unmount them. Continue?"
            ),
        ):
            return
        window.app_shell.lock_all_unlocked()
    window.app_shell.clear()
    vault_path = window.service.vault_path
    try:
        window.service.cleanup()
    except Exception as exc:  # noqa: BLE001
        logger.warning("Lock cleanup failed: %s", exc, exc_info=True)
    if vault_path is not None:
        try:
            window.service.prepare_existing_vault(vault_path)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to re-prepare vault after lock: %s", exc, exc_info=True)
    window._set_vault_unlocked_in_menu(False)
    show_lock_screen(window)
    window.add_toast("info", "Vault locked.")


def _confirm_lock_unlocked_files(
    window: "GlypheaveGUI", *, title: str, text: str
) -> bool:
    """Shared confirmation modal for actions that would lock unlocked files."""
    box = QMessageBox(window)
    box.setIcon(QMessageBox.Icon.Warning)
    box.setWindowTitle(title)
    box.setText(text)
    proceed = box.addButton(
        "Lock and continue", QMessageBox.ButtonRole.AcceptRole
    )
    cancel = box.addButton("Cancel", QMessageBox.ButtonRole.RejectRole)
    box.setDefaultButton(cancel)
    box.exec()
    return box.clickedButton() is proceed


def show_vault_list_entries(
    window: "GlypheaveGUI", entries: list[VaultListEntry]
) -> None:
    window.vault_list_screen.set_vaults(entries)
    window.stack.setCurrentWidget(window.vault_list_screen)
    window.vault_list_screen.focus_first_vault()


