"""Menu-bar wiring and stub handlers for the application menu actions."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..glyphweave_ui import GlypheaveGUI


def wire_menu_bar(window: "GlypheaveGUI") -> None:
    m = window.menu_bar
    m.new_vault_requested.connect(window.show_create_vault_form)
    m.vault_switch_requested.connect(window.show_vault_list_screen)
    m.import_requested.connect(lambda: menu_import_into_current_folder(window))
    m.export_requested.connect(lambda: menu_export_selected(window))
    m.exit_requested.connect(window.close)
    m.lock_requested.connect(window._handle_lock_request)
    m.sync_now_requested.connect(lambda: menu_sync_now_stub(window))
    m.recovery_phrase_requested.connect(
        lambda: menu_recovery_phrase_stub(window)
    )
    m.find_in_vault_requested.connect(lambda: menu_find_in_vault(window))
    m.preferences_requested.connect(lambda: menu_preferences_stub(window))
    m.refresh_requested.connect(lambda: menu_refresh(window))
    m.documentation_requested.connect(lambda: menu_documentation_stub(window))
    m.about_requested.connect(window._show_about_modal)


def menu_import_into_current_folder(window: "GlypheaveGUI") -> None:
    # File-view path is the only context where Import is enabled; default
    # to the vault root folder otherwise.
    window.import_into_vault([], "/")


def menu_export_selected(window: "GlypheaveGUI") -> None:
    paths = window.file_view.get_selected_paths()
    if paths:
        window.export_selected_entries(paths)


def menu_find_in_vault(window: "GlypheaveGUI") -> None:
    if hasattr(window, "app_shell"):
        window.app_shell.show_search_overlay()


def menu_refresh(window: "GlypheaveGUI") -> None:
    # Only meaningful post-unlock; refresh is a no-op pre-unlock.
    if window.stack.currentWidget() is getattr(window, "app_shell", None):
        window.refresh_file_view()


def menu_sync_now_stub(window: "GlypheaveGUI") -> None:
    window.add_toast("info", "Sync is not yet implemented in this build.")


def menu_recovery_phrase_stub(window: "GlypheaveGUI") -> None:
    def task():
        return window.service.get_recovery_phrase()

    def on_success(phrase: str):
        window.recovery_phrase_screen.set_words(phrase.split())
        window.recovery_phrase_screen.set_view_mode(True)
        window.stack.setCurrentWidget(window.recovery_phrase_screen)

    window._run_task(
        task,
        on_success=on_success,
        error_title="Failed to retrieve recovery phrase",
    )


def menu_preferences_stub(window: "GlypheaveGUI") -> None:
    window.add_toast("info", "Preferences are not yet implemented.")


def menu_documentation_stub(window: "GlypheaveGUI") -> None:
    window.add_toast("info", "Documentation links are not yet set.")

# Cut / Copy / Paste (right-click menu)


def handle_cut(window: "GlypheaveGUI", paths: object) -> None:
    items = list(paths) if isinstance(paths, list) else []
    n = len(items)
    if not n:
        return
    label = items[0].rsplit("/", 1)[-1] if n == 1 else f"{n} items"
    window.add_toast("info", f"Cut {label} - paste to move")


def handle_copy(window: "GlypheaveGUI", paths: object) -> None:
    items = list(paths) if isinstance(paths, list) else []
    n = len(items)
    if not n:
        return
    label = items[0].rsplit("/", 1)[-1] if n == 1 else f"{n} items"
    window.add_toast("info", f"Copied {label} - paste to duplicate")


def handle_paste(window: "GlypheaveGUI", destination: str) -> None:
    # The clipboard payload is still populated here because PySide6 direct
    # connections are synchronous. on_paste() clears it only after this
    # slot returns.
    clipboard = window.file_view.get_clipboard()
    if clipboard is None:
        return
    mode = clipboard.get("mode", "copy")
    paths: list[str] = clipboard.get("paths", [])
    if not paths:
        return
    dest = destination or "/"

    if mode == "cut":
        def _task():
            window.service.move_entries(paths, dest)
        window._run_task(
            _task,
            on_success=lambda _: window.refresh_file_view(),
            error_title="Paste failed",
            block_ui=False,
        )
    else:
        def _task():  # type: ignore[no-redef]
            for path in paths:
                window.service.copy_entry(path, dest)
        window._run_task(
            _task,
            on_success=lambda _: window.refresh_file_view(),
            error_title="Paste failed",
            block_ui=False,
        )
