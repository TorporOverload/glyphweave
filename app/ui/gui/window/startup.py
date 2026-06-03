from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from PySide6.QtWidgets import QApplication, QMessageBox

from app.common.config import is_event_encryption_enabled
from app.ui.gui.setup.resources import load_app_icon, load_application_fonts
from app.ui.gui.setup.theme import apply_theme

from . import menu as menu
from . import routing as routing

if TYPE_CHECKING:
    from ..glyphweave_ui import GlypheaveGUI


def wire_screen_signals(window: "GlypheaveGUI") -> None:
    """Connect every child screen's outgoing signals to the matching window
    methods. Called once at the end of :meth:`GlyphWeaveDemoWindow.__init__`."""
    window.vault_list_screen.create_new_vault_requested.connect(
        window.show_create_vault_form
    )
    window.vault_list_screen.vault_selected.connect(window.show_lock_screen_for_vault)
    window.vault_list_screen.vault_delete_requested.connect(window.handle_delete_vault)
    window.create_vault_screen.import_existing_requested.connect(
        window.import_existing_vault
    )
    window.create_vault_screen.vault_created.connect(window.handle_create_vault)
    window.recovery_phrase_screen.continue_requested.connect(
        lambda: routing.show_confirm_phrase_screen(window)
    )
    window.recovery_phrase_screen.copied_to_clipboard.connect(
        lambda: window.add_toast("success", "Recovery phrase copied to clipboard.")
    )
    window.recovery_phrase_screen.dismissed.connect(
        lambda: window.stack.setCurrentWidget(window.app_shell)
    )
    window.confirm_phrase_screen.continue_requested.connect(window.handle_vault_created)
    window.confirm_phrase_screen.back_requested.connect(
        lambda: routing.show_recovery_phrase_screen(window)
    )
    window.lock_screen.recovery_requested.connect(window.show_recovery_input_screen)
    window.lock_screen.unlock_requested.connect(window.handle_unlock)
    window.lock_screen.switch_vault_requested.connect(window.show_vault_list_screen)
    window.recovery_input_screen.back_requested.connect(window.show_vault_list_screen)
    window.recovery_input_screen.recovery_succeeded.connect(
        lambda pw, phrase: routing.handle_recovery_succeeded(window, pw, phrase)
    )
    window.file_view.file_open_requested.connect(window.open_file_from_view)
    window.file_view.unlocked_open_requested.connect(window.reopen_unlocked_file)
    window.file_view.unlocked_lock_requested.connect(window.lock_unlocked_file)
    window.file_view.import_requested.connect(window.import_into_vault)
    window.file_view.delete_requested.connect(window.delete_selected_entries)
    window.file_view.create_folder_requested.connect(window.create_folder_in_vault)
    window.file_view.export_requested.connect(window.export_selected_entries)
    window.file_view.rename_requested.connect(window.rename_entry)
    window.file_view.move_requested.connect(window.move_entries)
    window.file_view.cut_requested.connect(lambda paths: menu.handle_cut(window, paths))
    window.file_view.copy_requested.connect(
        lambda paths: menu.handle_copy(window, paths)
    )
    window.file_view.paste_requested.connect(
        lambda dest: menu.handle_paste(window, dest)
    )
    window.app_shell.vault_switch_requested.connect(window.show_vault_list_screen)
    window.app_shell.lock_requested.connect(window._handle_lock_request)
    window.app_shell.file_open_requested.connect(window.open_file_from_view)


def warn_if_event_encryption_disabled() -> bool:
    """Show a blocking warning if event encryption is disabled.

    Returns ``False`` if the user chose to quit, ``True`` otherwise."""
    if is_event_encryption_enabled():
        return True
    box = QMessageBox()
    box.setIcon(QMessageBox.Icon.Warning)
    box.setWindowTitle("Event encryption disabled")
    box.setText("Event encryption is currently disabled.")
    box.setInformativeText(
        "'GLYPHWEAVE_EVENT_ENCRYPTION' is set to a false value, so new events "
        "will be written to the event store as plaintext. This is intended for "
        "development and debugging only - your activity log will not be "
        "encrypted at rest.\n\n"
        "Unset the environment variable or set it to 'true' to re-enable "
        "encryption."
    )
    continue_btn = box.addButton("Continue anyway", QMessageBox.ButtonRole.AcceptRole)
    quit_btn = box.addButton("Quit", QMessageBox.ButtonRole.RejectRole)
    box.setDefaultButton(quit_btn)
    box.exec()
    return box.clickedButton() is continue_btn


def main() -> int:
    """Application entry point - instantiates the QApplication, applies the
    theme, surfaces the encryption warning if applicable, and shows the
    main window."""
    from ..glyphweave_ui import GlypheaveGUI

    app = QApplication(sys.argv)
    # Fusion is the only built-in QStyle that respects QSS consistently.
    # Must come before any window is constructed.
    app.setStyle("Fusion")
    app.setApplicationName("GlyphWeave")
    app.setApplicationDisplayName("GlyphWeave")
    load_application_fonts()
    app.setWindowIcon(load_app_icon())
    apply_theme(app)

    if not warn_if_event_encryption_disabled():
        return 0

    window = GlypheaveGUI()
    window.show()
    return app.exec()
