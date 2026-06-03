from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QHBoxLayout,
    QMessageBox,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)
from app.common.logging import logger

from ...screens.search import SearchScreen
from .breadcrumbs import _BreadcrumbsBar
from .search_overlay import SearchOverlay
from .status_footer import StatusFooter
from .top_bar import TopBar
from .vault_tree_panel import VaultTreePanel


class AppShell(QWidget):
    """Post-unlock container with TopBar + content stack + sidebar + footer."""

    vault_switch_requested = Signal()
    lock_requested = Signal()
    search_requested = Signal(str)
    file_open_requested = Signal(int)

    def __init__(
        self,
        file_view: QWidget,
        *,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("AppShell")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self._vault_name: str = ""
        self._search_overlay: SearchOverlay | None = None
        self._build_ui(file_view)

    def _build_ui(self, file_view: QWidget) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self.top_bar = TopBar(parent=self)
        self.top_bar.sync_bell_clicked.connect(self._handle_bell_clicked)
        self.top_bar.search_focused.connect(self.show_search_overlay)
        root.addWidget(self.top_bar)

        self.breadcrumbs_bar = _BreadcrumbsBar(self)
        # Sync now is decorative until a real sync backend lands; surface a
        # toast via the existing menubar stub by re-emitting at AppShell.
        self.breadcrumbs_bar.sync_now_clicked.connect(self._handle_sync_now_clicked)
        root.addWidget(self.breadcrumbs_bar)

        # Forward folder navigation in the file view → breadcrumbs update.
        if hasattr(file_view, "current_folder_changed"):
            file_view.current_folder_changed.connect(self._on_file_view_folder_changed)

        # Workspace: vault tree panel + content stack
        workspace = QWidget(self)
        workspace_layout = QHBoxLayout(workspace)
        workspace_layout.setContentsMargins(0, 0, 0, 0)
        workspace_layout.setSpacing(0)

        # Vault tree panel (placeholder until set via set_tree_panel).
        self.vault_tree_panel_placeholder = QWidget(workspace)
        workspace_layout.addWidget(self.vault_tree_panel_placeholder)

        # The search screen lives in the stack so it can be activated by
        # navigate("Search") when needed.
        self.content_stack = QStackedWidget(workspace)
        self.file_view = file_view

        self.search_screen = SearchScreen(self)
        self.search_screen.open_containing_folder_requested.connect(
            self._on_open_containing_folder
        )
        self.search_screen.file_open_requested.connect(self._on_search_file_open)
        self.search_screen.close_requested.connect(self._close_search_overlay)

        self.content_stack.addWidget(self.file_view)
        self.content_stack.addWidget(self.search_screen)
        workspace_layout.addWidget(self.content_stack, 1)

        root.addWidget(workspace, 1)

        # Status footer
        self.status_footer = StatusFooter(self)
        self.status_footer.lock_vault_clicked.connect(self.lock_requested.emit)
        root.addWidget(self.status_footer)

        # Vault tree panel for sidebar replacement.
        self.vault_tree_panel: VaultTreePanel | None = None

        self.content_stack.setCurrentWidget(self.file_view)

    # Public API
    
    def set_vault_data(
        self, payload: object, *, preserve_navigation: bool = False
    ) -> None:
        """Forward vault payload to the FileViewScreen and update chrome."""
        vault_name = getattr(payload, "vault_name", "")
        entries = getattr(payload, "entries", [])
        unlocked_files = getattr(payload, "unlocked_files", [])
        self._vault_name = vault_name

        try:
            self.file_view.set_vault_data(
                vault_name=vault_name,
                entries=entries,
                unlocked_files=unlocked_files,
                preserve_navigation=preserve_navigation,
            )
        except Exception:
            logger.exception("file_view.set_vault_data failed")

        if vault_name:
            self.breadcrumbs_bar.set_crumbs([vault_name])
        self.top_bar.set_vault_name(vault_name)
        self._refresh_conflict_indicator()

        if hasattr(self.search_screen, "set_vault_name"):
            self.search_screen.set_vault_name(vault_name)
        if hasattr(self.search_screen, "set_entries"):
            self.search_screen.set_entries(entries)

        if self.vault_tree_panel:
            self.vault_tree_panel.set_vault_name(vault_name)

        try:
            file_entries = [e for e in entries if not getattr(e, "is_folder", False)]
            self.status_footer.set_counts(len(file_entries), len(unlocked_files))
        except Exception:
            # Footer is decorative - log but never crash the unlock path.
            logger.warning("status_footer.set_counts failed", exc_info=True)

    def inject_service(self, service: object) -> None:
        """Inject VaultService into screens that need it."""
        self._service = service
        if hasattr(self.search_screen, "set_service"):
            self.search_screen.set_service(service)
        if self._search_overlay:
            self._search_overlay.inject_service(service)

    def set_tree_panel(self, tree_panel: VaultTreePanel) -> None:
        """Set the vault tree panel, replacing the placeholder."""
        self.vault_tree_panel = tree_panel
        self.vault_tree_panel_placeholder.hide()
        workspace_layout = self.vault_tree_panel_placeholder.parent().layout()
        if workspace_layout is not None:
            index = workspace_layout.indexOf(self.vault_tree_panel_placeholder)
            if index >= 0:
                workspace_layout.removeWidget(self.vault_tree_panel_placeholder)
            workspace_layout.insertWidget(0, tree_panel)
        if self._vault_name:
            tree_panel.set_vault_name(self._vault_name)
        tree_panel.home_requested.connect(self._navigate_to_root)

    def _navigate_to_root(self) -> None:
        """Move the file view back to the vault root."""
        self.navigate("Library")
        if hasattr(self.file_view, "navigate_to_folder"):
            self.file_view.navigate_to_folder("/")

    def navigate(self, name: str) -> None:
        """Switch the content area to the named screen."""
        screen_map: dict[str, QWidget] = {"Library": self.file_view}
        widget = screen_map.get(name)
        if widget is not None:
            self.content_stack.setCurrentWidget(widget)

    def clear(self) -> None:
        """Reset shell state before the vault is locked."""
        self._vault_name = ""
        self.top_bar.clear_vault_name()
        self.content_stack.setCurrentWidget(self.file_view)

    # Status footer pass-throughs

    def show_indexing_status(self, message: str) -> None:
        self.status_footer.show_indexing(message)

    def hide_indexing_status(self) -> None:
        self.status_footer.hide_indexing()

    def show_importing_status(self, _message: str | None = None) -> None:
        """Reveal the import progress bar at 0%.

        ``_message`` is accepted for back-compat with legacy callers
        (``actions.py`` still passes ``"Importing…"``); the new
        ``ImportProgressPill`` formats its own label from current/total
        and the active filename, so the argument is ignored.
        """
        self.status_footer.show_importing()

    def update_importing_status(
        self, current: int, total: int, filename: str
    ) -> None:
        self.status_footer.update_importing(current, total, filename)

    def hide_importing_status(self) -> None:
        self.status_footer.hide_importing()

    def show_syncing_status(self) -> None:
        self.status_footer.show_syncing()

    def update_syncing_status(
        self, current: int, total: int, label: str
    ) -> None:
        self.status_footer.update_syncing(current, total, label)

    def hide_syncing_status(self) -> None:
        self.status_footer.hide_syncing()

    def is_syncing(self) -> bool:
        pill = getattr(self.status_footer, "syncing_pill", None)
        return bool(pill and pill.isVisible())

    def has_unlocked_files(self) -> bool:
        if hasattr(self.file_view, "has_unlocked_files"):
            return self.file_view.has_unlocked_files()
        return False

    def is_importing(self) -> bool:
        """True while a batch import is in flight.

        Backed by the import-pill visibility because the pill is shown in
        ``actions.import_into_vault``'s ``before=`` callback and hidden
        in its ``after=`` / ``on_error=`` callbacks - so it's the single
        source of truth for "an import worker is running" without
        threading a separate flag through the task plumbing.
        """
        pill = getattr(self.status_footer, "importing_pill", None)
        return bool(pill and pill.isVisible())

    def lock_all_unlocked(self) -> None:
        if hasattr(self.file_view, "lock_all_unlocked"):
            self.file_view.lock_all_unlocked()

    # Internal slots

    def _refresh_conflict_indicator(self) -> None:
        """Recount active sync conflicts and toggle the bell red dot."""
        service = getattr(self, "_service", None)
        if service is None or not hasattr(service, "list_sync_conflicts"):
            self.top_bar.set_conflict_count(0)
            return
        try:
            count = len(service.list_sync_conflicts())
        except Exception:  # noqa: BLE001
            # Sync conflict storage may not be available before unlock -
            # treat as zero rather than blowing up the file view refresh.
            count = 0
        self.top_bar.set_conflict_count(count)

    def _handle_bell_clicked(self) -> None:
        """User clicked the bell - open the conflict resolution modal.

        The modal lists active conflicts when there are any and historical
        ones otherwise, so the click target is always meaningful.
        """
        from app.ui.gui.widgets.conflict_resolution import (
            ConflictResolutionDialog,
        )

        service = getattr(self, "_service", None)
        if service is None:
            return
        # Snapshot current file-view entries so the Restore overlay's
        # destination tree shows live folder structure.
        entries: list = []
        if hasattr(self.file_view, "get_entries_snapshot"):
            entries = list(self.file_view.get_entries_snapshot())
        dialog = ConflictResolutionDialog(
            service, entries=entries, parent=self.window()
        )
        dialog.state_changed.connect(self._on_conflict_state_changed)
        dialog.open_file_requested.connect(self._on_conflict_open_file)
        dialog.exec()
        # After close, ensure the bell red-dot reflects the latest count
        # (the dialog already calls refresh internally per-action, but
        # this catches anything an external sync may have changed).
        self._refresh_conflict_indicator()

    def _on_conflict_state_changed(self) -> None:
        """A conflict mutation succeeded - refresh the file view + bell."""
        window = self.window()
        if window is not None and hasattr(window, "refresh_file_view"):
            window.refresh_file_view()
        self._refresh_conflict_indicator()

    def _on_conflict_open_file(self, archived_file_ref_id: int) -> None:
        """Open an archived conflict file in the default app via FUSE.

        Routes through the existing ``open_file_from_view`` task so the
        file unlocks and mounts the same way as a normal double-click,
        even though the archived entry is filtered out of the tree.
        """
        window = self.window()
        if window is not None and hasattr(window, "open_file_from_view"):
            window.open_file_from_view(archived_file_ref_id)

    def _handle_sync_now_clicked(self) -> None:
        self.start_sync()

    def start_sync(self) -> None:
        """Replay pending sync events in the background with a progress
        pill.  Safe to call right after vault unlock - the file tree
        stays visible while events are applied."""
        window = self.window()
        service = getattr(self, "_service", None)
        if window is None or service is None or not hasattr(window, "_run_task"):
            return
        if not hasattr(service, "replay_pending_events"):
            window.add_toast(
                "info", "Sync is not available for this vault."
            )
            return
        if self.is_syncing():
            return

        from ...window import tasks as _tasks

        def _on_success(result: object) -> None:
            sync_result, payload = result  # type: ignore[misc]
            total = getattr(sync_result, "total", 0)
            failed = getattr(sync_result, "failed", 0)
            blocked = getattr(sync_result, "blocked", 0)
            if total == 0:
                window.add_toast("info", "Already up to date.")
            else:
                summary = f"Replayed {total} event{'s' if total != 1 else ''}"
                if failed or blocked:
                    summary += f" ({failed} failed, {blocked} blocked)"
                window.add_toast("success", summary)
            window._handle_file_view_loaded(payload, show_screen=False)
            self._refresh_conflict_indicator()

        window._run_task(
            lambda: _tasks.sync_and_refresh(window),
            on_success=_on_success,
            on_error=lambda msg: (
                self.hide_syncing_status(),
                window.add_toast("error", f"Sync failed: {msg}"),
            ),
            before=self.show_syncing_status,
            after=self.hide_syncing_status,
            block_ui=False,
        )

    def _on_file_view_folder_changed(self, parts: list[str]) -> None:
        """Update the breadcrumbs row when the file view navigates folders.

        ``parts`` always begins with the vault name."""
        if isinstance(parts, list) and parts:
            self.breadcrumbs_bar.set_crumbs(parts)

    def show_search_overlay(self) -> None:
        if self._search_overlay is None:
            self._search_overlay = SearchOverlay(self)
            self._search_overlay.set_search_screen(self.search_screen)
            self._search_overlay.inject_service(getattr(self, "_service", None))
        self._search_overlay.show()
        self._search_overlay.raise_()
        self._search_overlay.activateWindow()
        if self._search_overlay.search_input is not None:
            self._search_overlay.search_input.setFocus()

    def _close_search_overlay(self) -> None:
        if self._search_overlay is not None:
            self._search_overlay.accept()

    def _on_search_file_open(self, file_ref_id: int) -> None:
        """Open a search result and dismiss the command palette."""
        self._close_search_overlay()
        self.file_open_requested.emit(file_ref_id)

    def _on_open_containing_folder(self, parent_virtual_path: str) -> None:
        """Navigate to folder when user clicks 'Open containing folder'."""
        self._close_search_overlay()
        self.navigate("Library")
        if hasattr(self.file_view, "navigate_to_folder"):
            self.file_view.navigate_to_folder(parent_virtual_path)
