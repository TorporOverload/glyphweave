from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def mock_cli():
    cli = MagicMock()
    cli._print_lines = MagicMock()
    cli.service = MagicMock()
    return cli


class TestListFiles:
    def test_list_files_shows_vault_contents(self, mock_cli, capsys):
        mock_entries = [
            MagicMock(id=1, name="file1.txt", is_folder=False),
            MagicMock(id=2, name="subdir", is_folder=True),
        ]
        mock_cli.service.list_root_entries.return_value = mock_entries
        mock_cli.service.list_children.return_value = []

        from app.ui.cli.browse_actions import list_files

        list_files(mock_cli)

        mock_cli._print_lines.assert_called_once()
        lines = mock_cli._print_lines.call_args[0][0]
        assert any("file1.txt" in line for line in lines)
        assert any("subdir" in line for line in lines)

    def test_list_files_handles_empty_vault(self, mock_cli, capsys):
        mock_cli.service.list_root_entries.return_value = []

        from app.ui.cli.browse_actions import list_files

        list_files(mock_cli)

        captured = capsys.readouterr()
        assert "(no files in vault)" in captured.out

    def test_list_files_handles_service_error(self, mock_cli, capsys):
        mock_cli.service.list_root_entries.side_effect = RuntimeError("Service error")

        from app.ui.cli.browse_actions import list_files

        list_files(mock_cli)

        captured = capsys.readouterr()
        assert "Error listing files" in captured.out


class TestOpenFile:
    def test_open_file_navigates_into_folder(self, mock_cli, monkeypatch):
        folder_entry = MagicMock(id=1, name="subdir", is_folder=True)
        mock_cli.service.list_root_entries.return_value = [folder_entry]
        mock_cli.service.list_children.return_value = []

        input_values = iter(["1", ""])
        monkeypatch.setattr("builtins.input", lambda _: next(input_values))

        from app.ui.cli.browse_actions import open_file

        open_file(mock_cli)

        mock_cli.service.list_children.assert_called_once_with(1)

    def test_open_file_navigates_to_parent(self, mock_cli, monkeypatch):
        folder_entry = MagicMock(id=1, name="subdir", is_folder=True)
        mock_cli.service.list_root_entries.return_value = [folder_entry]
        mock_cli.service.list_children.side_effect = [
            [MagicMock(id=2, name="child.txt", is_folder=False)],
            [folder_entry],
        ]

        input_values = iter(["1", "b", ""])
        monkeypatch.setattr("builtins.input", lambda _: next(input_values))

        from app.ui.cli.browse_actions import open_file

        open_file(mock_cli)

    def test_open_file_handles_invalid_selection(self, mock_cli, capsys, monkeypatch):
        mock_cli.service.list_root_entries.return_value = []

        input_values = iter(["invalid", ""])
        monkeypatch.setattr("builtins.input", lambda _: next(input_values))

        from app.ui.cli.browse_actions import open_file

        open_file(mock_cli)

        captured = capsys.readouterr()
        assert "Entry not found" in captured.out

    def test_open_file_cancels_on_blank_input(self, mock_cli, monkeypatch):
        mock_cli.service.list_root_entries.return_value = []

        input_values = iter([""])
        monkeypatch.setattr("builtins.input", lambda _: next(input_values))

        from app.ui.cli.browse_actions import open_file

        open_file(mock_cli)


class TestSearchFiles:
    def test_search_files_with_results(self, mock_cli, monkeypatch):
        mock_results = [
            MagicMock(
                file_ref_id="ref1",
                file_name="report.txt",
                virtual_path="/report.txt",
                snippet="test content",
            )
        ]
        mock_page = MagicMock(results=mock_results, has_more=False)
        mock_cli.service.search_page.return_value = mock_page
        mock_cli.service.open_file_by_ref.return_value = MagicMock(message="File opened")

        input_values = iter(["1", "1", "1"])
        monkeypatch.setattr("builtins.input", lambda _: next(input_values))
        monkeypatch.setattr("builtins.print", lambda *args, **kwargs: None)

        from app.ui.cli.browse_actions import search_files

        search_files(mock_cli)

        mock_cli.service.search_page.assert_called_once()

    def test_search_files_empty_query(self, mock_cli, capsys, monkeypatch):
        input_values = iter(["1", ""])
        monkeypatch.setattr("builtins.input", lambda _: next(input_values))

        from app.ui.cli.browse_actions import search_files

        search_files(mock_cli)

        captured = capsys.readouterr()
        assert "Empty query" in captured.out

    def test_search_files_no_results(self, mock_cli, monkeypatch):
        mock_page = MagicMock(results=[], has_more=False)
        mock_cli.service.search_page.return_value = mock_page

        input_values = iter(["2"])
        monkeypatch.setattr("builtins.input", lambda _: next(input_values))

        from app.ui.cli.browse_actions import search_files

        search_files(mock_cli)


class TestBrowsePagination:
    def test_search_pagination_next_page(self, mock_cli, monkeypatch):
        mock_results = [MagicMock(file_ref_id=f"ref{i}", file_name=f"file{i}.txt", virtual_path=f"/file{i}.txt", snippet="") for i in range(5)]
        mock_page_with_more = MagicMock(results=mock_results, has_more=True)
        mock_page_final = MagicMock(results=[], has_more=False)

        mock_cli.service.search_page.side_effect = [mock_page_with_more, mock_page_final]
        mock_cli.service.open_file_by_ref.return_value = MagicMock(message="Opened")

        input_values = iter(["1", "test", "n", ""])
        monkeypatch.setattr("builtins.input", lambda _: next(input_values))
        monkeypatch.setattr("builtins.print", lambda *args, **kwargs: None)

        from app.ui.cli.browse_actions import search_files

        search_files(mock_cli)

        assert mock_cli.service.search_page.call_count == 2
        call_args = mock_cli.service.search_page.call_args_list
        assert call_args[0][1]["offset"] == 0
        assert call_args[1][1]["offset"] == 20

    def test_search_pagination_invalid_page_choice(self, mock_cli, monkeypatch):
        mock_page = MagicMock(
            results=[MagicMock(file_ref_id="ref1", file_name="file.txt", virtual_path="/file.txt", snippet="")],
            has_more=True,
        )
        mock_cli.service.search_page.return_value = mock_page

        input_values = iter(["query", "invalid", ""])
        monkeypatch.setattr("builtins.input", lambda _: next(input_values))
        monkeypatch.setattr("builtins.print", lambda *args, **kwargs: None)

        from app.ui.cli.browse_actions import search_files

        search_files(mock_cli)


class TestReindexSupportedFiles:
    def test_reindex_supported_files_success(self, mock_cli, capsys):
        mock_cli.service.reindex_pending.return_value = (5, 1)

        from app.ui.cli.browse_actions import reindex_supported_files

        reindex_supported_files(mock_cli)

        captured = capsys.readouterr()
        assert "Indexed: 5" in captured.out
        assert "Failed: 1" in captured.out

    def test_reindex_supported_files_error(self, mock_cli, capsys):
        mock_cli.service.reindex_pending.side_effect = RuntimeError("Reindex failed")

        from app.ui.cli.browse_actions import reindex_supported_files

        reindex_supported_files(mock_cli)

        captured = capsys.readouterr()
        assert "Re-index failed" in captured.out