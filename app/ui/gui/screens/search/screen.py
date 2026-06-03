"""Full-page search screen used by the search overlay """

from __future__ import annotations

from typing import Any

from PySide6.QtCore import QTimer, Signal
from PySide6.QtWidgets import (
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from app.services.models import SearchPage
from app.services.vault_service import VaultService

from . import builders as _builders
from .card import SearchResultCard
from .helpers import SearchWorker


class SearchScreen(QWidget):
    open_containing_folder_requested = Signal(str)
    file_open_requested = Signal(int)
    close_requested = Signal()
    # True when the screen has nothing to show below the filter row (no query
    # / no results). The overlay dialog listens to this and collapses its
    # height so the empty 320px placeholder area doesn't sit visible.
    compact_changed = Signal(bool)

    SCOPES: tuple[tuple[str, str], ...] = (
        ("all", "all"),
        ("filename", "filename"),
        ("content", "content"),
    )

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._service: VaultService | None = None
        self._vault_name: str = ""
        self._current_page: int = 0
        self._page_size: int = 30
        self._total_results: int = 0
        self._has_more: bool = False
        self._current_query: str = ""
        self._scope: str = "all"
        self._scope_buttons: dict[str, QPushButton] = {}
        self._worker: SearchWorker | None = None
        self._selected_file_ref_id: int | None = None
        self._result_cards: dict[int, SearchResultCard] = {}

        # Populated by the builder helpers. Annotating these dynamic widgets
        # keeps static analysis in sync with the assembled UI.
        self._title_label: Any = None
        self._status_badge: Any = None
        self._search_bar: Any = None
        self._close_button: Any = None
        self._search_icon: Any = None
        self._search_input: Any = None
        self._clear_button: Any = None
        self._results_count_label: Any = None
        self._results_summary: Any = None
        self._results_scroll: Any = None
        self._results_container: Any = None
        self._results_layout: Any = None
        self._empty_state: Any = None
        self._empty_title: Any = None
        self._empty_hint: Any = None
        self._loading_label: Any = None
        self._prev_button: Any = None
        self._page_label: Any = None
        self._next_button: Any = None
        self._show_more_button: Any = None

        self._debounce_timer = QTimer(self)
        self._debounce_timer.setSingleShot(True)
        self._debounce_timer.timeout.connect(self._do_search)

        self._root_layout = QVBoxLayout(self)
        self._root_layout.setContentsMargins(0, 0, 0, 0)
        self._root_layout.setSpacing(0)

        _builders.build_header(self)
        _builders.build_search_input(self)
        _builders.build_filters(self)
        _builders.build_results_area(self)
        _builders.build_pagination(self)

    # Public API

    def set_vault_data(
        self, vault_name: str, service: VaultService | None = None
    ) -> None:
        self._vault_name = vault_name
        if service is not None:
            self._service = service

    def set_service(self, service: VaultService) -> None:
        self._service = service

    def refresh(self) -> None:
        if self._current_query:
            self._start_search(self._current_query)

    # Scope-pill handlers
    
    def _on_scope_clicked(self, scope: str) -> None:
        if scope == self._scope:
            # Re-clicking the active pill keeps it selected, never toggles off.
            self._scope_buttons[scope].setChecked(True)
            return
        self._set_scope(scope)
        if self._current_query.strip():
            self._cancel_worker()
            self._current_page = 0
            self._start_search(self._current_query.strip())

    def _set_scope(self, scope: str) -> None:
        self._scope = scope
        for value, btn in self._scope_buttons.items():
            is_active = value == scope
            btn.setChecked(is_active)
            btn.setProperty("state", "active" if is_active else "inactive")
            btn.style().unpolish(btn)
            btn.style().polish(btn)

    # Query / debounce handlers
    
    def _on_query_changed(self, text: str) -> None:
        self._clear_button.setVisible(bool(text))
        self._current_query = text
        self._debounce_timer.start(300)

    def _on_clear_clicked(self) -> None:
        self._search_input.clear()
        self._current_query = ""
        self._cancel_worker()
        self._clear_results()

    def _on_close_clicked(self) -> None:
        self.close_requested.emit()

    def _do_search(self) -> None:
        query = self._current_query.strip()
        if not query:
            self._clear_results()
            return
        self._cancel_worker()
        self._current_page = 0
        self._start_search(query)

    def _start_search(self, query: str) -> None:
        if self._service is None:
            return
        self._set_loading(True)
        self._worker = SearchWorker(
            service=self._service,
            query=query,
            page=self._current_page,
            limit=self._page_size,
            scope=self._scope,
            parent=self,
        )
        self._worker.results_ready.connect(self._on_results_ready)
        self._worker.failed.connect(self._on_search_failed)
        self._worker.start()

    def _cancel_worker(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            self._worker.cancel()
            self._worker.wait(1000)
        self._worker = None

    # Result rendering
    
    def _set_loading(self, loading: bool) -> None:
        if loading:
            # Only blank out the visible result area on the FIRST page (a
            # fresh search). For subsequent pages (Show more), keep the
            # existing cards on screen and let the user see them while the
            # next batch loads.
            if self._current_page == 0:
                self._loading_label.setVisible(True)
                self._results_scroll.setVisible(False)
                self._empty_state.setVisible(False)
                self.compact_changed.emit(False)
            self._status_badge.set_text("Searching...")
        else:
            self._loading_label.setVisible(False)
            self._status_badge.set_text("Ready")

    def _on_results_ready(self, page: SearchPage) -> None:
        self._set_loading(False)
        self._render_results(page)

    def _on_search_failed(self, error: str) -> None:
        self._set_loading(False)
        self._status_badge.set_text("Error")
        self._show_error(f"Search failed: {error}")

    def _render_results(self, page: SearchPage) -> None:
        is_first_page = self._current_page == 0
        if is_first_page:
            self._clear_result_cards()
            self._total_results = len(page.results)
        else:
            self._total_results += len(page.results)

        self._has_more = page.has_more

        if is_first_page and not page.results:
            self._show_empty_state()
            self._show_more_button.setVisible(False)
            return

        self._results_scroll.setVisible(True)
        self._empty_state.setVisible(False)
        self.compact_changed.emit(False)

        # Layout shape: [card_0, ..., card_n, show_more, stretch].
        # Insert each new card just before the show-more button + stretch
        # (the last two items) so they always remain at the bottom.
        for result in page.results:
            card = SearchResultCard(
                result, self._results_container, query=self._current_query
            )
            card.clicked.connect(self._on_result_clicked)
            card.open_requested.connect(self._on_result_open)
            card.open_containing_folder_requested.connect(
                self._on_open_containing_folder
            )
            card.copy_path_requested.connect(self._on_copy_path)
            insert_index = max(0, self._results_layout.count() - 2)
            self._results_layout.insertWidget(insert_index, card)
            self._result_cards[result.file_ref_id] = card

        self._show_more_button.setText("Show more results")
        self._show_more_button.setEnabled(True)
        self._show_more_button.setVisible(self._has_more)
        self._update_pagination()

    def _clear_result_cards(self) -> None:
        # Preserve the trailing show-more button and stretch; remove
        # everything before them.
        while self._results_layout.count() > 2:
            item = self._results_layout.takeAt(0)
            if item is not None:
                widget = item.widget()
                if widget is not None:
                    widget.deleteLater()
        self._result_cards.clear()
        if self._show_more_button is not None:
            self._show_more_button.setVisible(False)

    def _clear_results(self) -> None:
        self._cancel_worker()
        self._clear_result_cards()
        self._total_results = 0
        self._has_more = False
        self._current_page = 0
        self._selected_file_ref_id = None
        self._results_summary.clear()
        self._results_scroll.setVisible(False)
        self._empty_state.setVisible(False)
        self._loading_label.setVisible(False)
        self._status_badge.set_text("Ready")
        self.compact_changed.emit(True)

    def _show_empty_state(self) -> None:
        self._results_scroll.setVisible(False)
        self._empty_state.setVisible(True)
        self.compact_changed.emit(False)
        self._empty_title.setText("No results")
        # Scope pills replaced the older combo filters - only "all" is the
        # unfiltered default, anything else means the user narrowed scope.
        if self._scope != "all":
            self._empty_hint.setText(
                f'No matches for "{self._current_query}" in {self._scope}. '
                f"Try widening the scope."
            )
        else:
            self._empty_hint.setText("Try a different search term")

    def _show_error(self, message: str) -> None:
        self._results_scroll.setVisible(False)
        self._empty_state.setVisible(True)
        self._empty_title.setText("Search error")
        self._empty_hint.setText(message)

    def _update_pagination(self) -> None:
        total_pages = max(
            1,
            (self._total_results + self._page_size - 1) // self._page_size,
        )
        self._page_label.setText(f"Page {self._current_page + 1} of {total_pages}")
        self._prev_button.setEnabled(self._current_page > 0)
        self._next_button.setEnabled(self._has_more)

    # Result card events

    def _on_result_clicked(self, file_ref_id: int) -> None:
        if self._selected_file_ref_id is not None:
            card = self._result_cards.get(self._selected_file_ref_id)
            if card is not None:
                card.set_selected(False)
        self._selected_file_ref_id = file_ref_id
        card = self._result_cards.get(file_ref_id)
        if card is not None:
            card.set_selected(True)

    def _on_result_open(self, file_ref_id: int) -> None:
        self.file_open_requested.emit(file_ref_id)

    def _on_open_containing_folder(self, virtual_path: str) -> None:
        self.open_containing_folder_requested.emit(virtual_path)

    def _on_copy_path(self, virtual_path: str) -> None:
        from PySide6.QtWidgets import QApplication

        clipboard = QApplication.clipboard()
        clipboard.setText(virtual_path)

    # Pagination

    def _on_prev_page(self) -> None:
        if self._current_page > 0:
            self._current_page -= 1
            self._start_search(self._current_query)

    def _on_next_page(self) -> None:
        if self._has_more:
            self._current_page += 1
            self._start_search(self._current_query)

    def _on_show_more_clicked(self) -> None:
        if not self._has_more:
            return
        query = self._current_query.strip()
        if not query:
            return
        self._cancel_worker()
        self._current_page += 1
        self._show_more_button.setEnabled(False)
        self._show_more_button.setText("Loading…")
        self._start_search(query)

    def showEvent(self, event) -> None:  # type: ignore[override]
        super().showEvent(event)
        # Open in compact mode whenever there is nothing to display below
        # the filter row - the overlay listens to this and shrinks itself.
        if not self._current_query.strip():
            self.compact_changed.emit(True)
        elif self._result_cards:
            self.compact_changed.emit(False)
