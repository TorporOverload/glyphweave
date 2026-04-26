import pytest

from app.common.file_extensions import (
    ensure_extension_from_mime,
    extension_from_mime,
)


class TestExtensionFromMime:
    def test_returns_none_for_none_mime(self) -> None:
        assert extension_from_mime(None) is None

    def test_returns_none_for_empty_string(self) -> None:
        assert extension_from_mime("") is None

    def test_returns_none_for_whitespace_string(self) -> None:
        assert extension_from_mime("   ") is None

    def test_returns_docx_for_word_document(self) -> None:
        result = extension_from_mime(
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
        assert result == ".docx"

    def test_returns_xlsx_for_spreadsheet(self) -> None:
        result = extension_from_mime(
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
        assert result == ".xlsx"

    def test_returns_pptx_for_presentation(self) -> None:
        result = extension_from_mime(
            "application/vnd.openxmlformats-officedocument.presentationml.presentation"
        )
        assert result == ".pptx"

    def test_returns_doc_for_msword(self) -> None:
        assert extension_from_mime("application/msword") == ".doc"

    def test_returns_xls_for_excel(self) -> None:
        assert extension_from_mime("application/vnd.ms-excel") == ".xls"

    def test_returns_ppt_for_powerpoint(self) -> None:
        assert extension_from_mime("application/vnd.ms-powerpoint") == ".ppt"

    def test_handles_uppercase_mime_type(self) -> None:
        assert extension_from_mime("APPLICATION/MSWORD") == ".doc"

    def test_handles_lowercase_mime_type(self) -> None:
        assert extension_from_mime("application/msword") == ".doc"

    def test_handles_mime_with_whitespace(self) -> None:
        assert extension_from_mime("  application/msword  ") == ".doc"

    def test_returns_standard_extension_for_plain_text(self) -> None:
        result = extension_from_mime("text/plain")
        assert result is not None


class TestEnsureExtensionFromMime:
    def test_appends_extension_when_missing(self) -> None:
        result = ensure_extension_from_mime("document", "application/msword")
        assert result == "document.doc"

    def test_preserves_existing_extension(self) -> None:
        result = ensure_extension_from_mime("document.doc", "application/msword")
        assert result == "document.doc"

    def test_appends_xlsx_for_spreadsheet(self) -> None:
        result = ensure_extension_from_mime("spreadsheet", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        assert result == "spreadsheet.xlsx"

    def test_returns_bin_for_unknown_mime(self) -> None:
        result = ensure_extension_from_mime("file", "application/unknown")
        assert result == "file.bin"

    def test_uses_provided_default_extension(self) -> None:
        result = ensure_extension_from_mime("file", "application/unknown", default_extension=".custom")
        assert result == "file.custom"

    def test_handles_file_with_leading_dot_in_name(self) -> None:
        result = ensure_extension_from_mime(".hidden", "application/msword")
        assert result == ".hidden.doc"

    def test_normalizes_extension_without_leading_dot(self) -> None:
        result = ensure_extension_from_mime("document", "application/unknown", default_extension="bin")
        assert result == "document.bin"

    def test_handles_empty_filename(self) -> None:
        result = ensure_extension_from_mime("", "application/msword")
        assert result == "file.doc"
