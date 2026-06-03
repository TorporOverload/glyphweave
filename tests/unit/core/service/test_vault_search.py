from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

from app.services.models import SearchPage, SearchResult, VaultContext
from app.services.vault_service import VaultService
from app.services.vault_files.vault_file_service import VaultFileService


@contextmanager
def _fake_session_scope(session):
    yield session


class _FakeQuery:
    def __init__(self, rows):
        self._rows = rows

    def filter(self, *args, **kwargs):
        return self

    def order_by(self, *args, **kwargs):
        return self

    def all(self):
        return list(self._rows)


class _FakeScalarResult:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return list(self._rows)


class _FakeSession:
    def __init__(self, refs):
        self.refs = refs

    def query(self, _model):
        return _FakeQuery(self.refs)

    def scalars(self, stmt):
        return _FakeScalarResult(self.refs)


def test_search_result_dataclass() -> None:
    result = SearchResult(
        file_ref_id=1,
        file_name="report.docx",
        virtual_path="/report.docx",
        snippet="...matching <b>text</b>...",
        rank=-1.5,
    )

    assert result.file_ref_id == 1
    assert result.file_name == "report.docx"
    assert result.virtual_path == "/report.docx"
    assert "<b>" in result.snippet
    assert result.rank == -1.5


def test_vault_file_service_search_returns_empty_for_blank_query(
    tmp_path: Path,
) -> None:
    service = VaultFileService(VaultContext(app_data_dir=tmp_path))

    assert service.search("   ") == []


def test_vault_file_service_search_maps_fts_results(
    tmp_path: Path, monkeypatch
) -> None:
    context = VaultContext(app_data_dir=tmp_path, session_factory=object())
    service = VaultFileService(context)
    refs = [
        SimpleNamespace(
            id=11,
            name="report.txt",
            virtual_path="/docs/report.txt",
            is_folder=False,
        )
    ]
    session = _FakeSession(refs)

    monkeypatch.setattr(
        "app.services.vault_files.queries.session_scope",
        lambda *args, **kwargs: _fake_session_scope(session),
    )
    monkeypatch.setattr(
        "app.services.vault_files.queries.search_file_references",
        lambda current_session, query, limit: [],
    )
    monkeypatch.setattr(
        "app.services.vault_files.queries.search_content",
        lambda current_session, query, limit: [("7", "...<b>hello</b>...", -1.0)],
    )

    results = service.search("hello")

    assert results == [
        SearchResult(
            file_ref_id=11,
            file_name="report.txt",
            virtual_path="/docs/report.txt",
            snippet="...<b>hello</b>...",
            rank=-1.0,
        )
    ]


def test_vault_file_service_search_supports_dhivehi_query(
    tmp_path: Path, monkeypatch
) -> None:
    context = VaultContext(app_data_dir=tmp_path, session_factory=object())
    service = VaultFileService(context)
    refs = [
        SimpleNamespace(
            id=22,
            name="Þ‹Þ¨ÞˆÞ¬Þ€Þ¨.txt",
            virtual_path="/docs/Þ‹Þ¨ÞˆÞ¬Þ€Þ¨.txt",
            is_folder=False,
        )
    ]
    session = _FakeSession(refs)
    seen = {}

    monkeypatch.setattr(
        "app.services.vault_files.queries.session_scope",
        lambda *args, **kwargs: _fake_session_scope(session),
    )
    monkeypatch.setattr(
        "app.services.vault_files.queries.search_file_references",
        lambda current_session, query, limit: [],
    )

    def _search_content(current_session, query, limit):
        seen["query"] = query
        return [("9", "<b>Þ‹Þ¨ÞˆÞ¬Þ€Þ¨</b> Þ„Þ¦ÞÞ°", -2.0)]

    monkeypatch.setattr(
        "app.services.vault_files.queries.search_content",
        _search_content,
    )

    results = service.search("Þ‹Þ¨ÞˆÞ¬Þ€Þ¨")

    assert seen["query"] == "Þ‹Þ¨ÞˆÞ¬Þ€Þ¨"
    assert len(results) == 1
    assert results[0].file_name == "Þ‹Þ¨ÞˆÞ¬Þ€Þ¨.txt"
    assert results[0].virtual_path == "/docs/Þ‹Þ¨ÞˆÞ¬Þ€Þ¨.txt"


def test_vault_file_service_search_returns_filename_matches_before_content(
    tmp_path: Path, monkeypatch
) -> None:
    context = VaultContext(app_data_dir=tmp_path, session_factory=object())
    service = VaultFileService(context)
    refs = [
        SimpleNamespace(
            id=11,
            name="budget.txt",
            virtual_path="/docs/budget.txt",
            is_folder=False,
        ),
        SimpleNamespace(
            id=12,
            name="notes.txt",
            virtual_path="/docs/notes.txt",
            is_folder=False,
        ),
    ]
    session = _FakeSession(refs)

    monkeypatch.setattr(
        "app.services.vault_files.queries.session_scope",
        lambda *args, **kwargs: _fake_session_scope(session),
    )
    monkeypatch.setattr(
        "app.services.vault_files.queries.search_file_references",
        lambda current_session, query, limit: [
            (11, "budget.txt", "/docs/budget.txt", -999000.0)
        ],
    )
    monkeypatch.setattr(
        "app.services.vault_files.queries.search_content",
        lambda current_session, query, limit: [("7", "...<b>budget</b> line...", -1.0)],
    )

    results = service.search("budget")

    assert [result.file_ref_id for result in results] == [11, 12]
    assert results[0].snippet == "Filename: <b>budget</b>.txt"
    assert results[1].snippet == "...<b>budget</b> line..."


def test_vault_file_service_search_deduplicates_filename_and_content_hits(
    tmp_path: Path, monkeypatch
) -> None:
    context = VaultContext(app_data_dir=tmp_path, session_factory=object())
    service = VaultFileService(context)
    refs = [
        SimpleNamespace(
            id=11,
            name="report.txt",
            virtual_path="/docs/report.txt",
            is_folder=False,
        )
    ]
    session = _FakeSession(refs)

    monkeypatch.setattr(
        "app.services.vault_files.queries.session_scope",
        lambda *args, **kwargs: _fake_session_scope(session),
    )
    monkeypatch.setattr(
        "app.services.vault_files.queries.search_file_references",
        lambda current_session, query, limit: [
            (11, "report.txt", "/docs/report.txt", -999000.0)
        ],
    )
    monkeypatch.setattr(
        "app.services.vault_files.queries.search_content",
        lambda current_session, query, limit: [("7", "...<b>report</b> body...", -1.0)],
    )

    results = service.search("report")

    assert len(results) == 1
    assert results[0].file_ref_id == 11
    assert results[0].snippet == "Filename: <b>report</b>.txt"


def test_vault_service_search_delegates_to_file_service(
    tmp_path: Path, monkeypatch
) -> None:
    service = VaultService(app_data_dir=tmp_path)
    expected = [
        SearchResult(
            file_ref_id=1,
            file_name="report.txt",
            virtual_path="/report.txt",
            snippet="hello",
            rank=-1.0,
        )
    ]

    monkeypatch.setattr(service.files, "search", lambda query, limit: expected)

    assert service.search("hello", 5) == expected


def test_vault_file_service_search_page_reports_has_more(
    tmp_path: Path, monkeypatch
) -> None:
    context = VaultContext(app_data_dir=tmp_path, session_factory=object())
    service = VaultFileService(context)
    refs = [
        SimpleNamespace(
            id=11,
            name="alpha.txt",
            virtual_path="/docs/alpha.txt",
            is_folder=False,
        ),
        SimpleNamespace(
            id=12,
            name="beta.txt",
            virtual_path="/docs/beta.txt",
            is_folder=False,
        ),
        SimpleNamespace(
            id=13,
            name="gamma.txt",
            virtual_path="/docs/gamma.txt",
            is_folder=False,
        ),
    ]
    session = _FakeSession(refs)

    monkeypatch.setattr(
        "app.services.vault_files.queries.session_scope",
        lambda *args, **kwargs: _fake_session_scope(session),
    )
    monkeypatch.setattr(
        "app.services.vault_files.queries.search_file_references",
        lambda current_session, query, limit: [
            (11, "alpha.txt", "/docs/alpha.txt", -10.0),
            (12, "beta.txt", "/docs/beta.txt", -9.0),
            (13, "gamma.txt", "/docs/gamma.txt", -8.0),
        ],
    )
    monkeypatch.setattr(
        "app.services.vault_files.queries.search_content",
        lambda current_session, query, limit: [],
    )

    page = service.search_page("a", limit=2, offset=0)

    assert page == SearchPage(
        results=[
            SearchResult(
                file_ref_id=11,
                file_name="alpha.txt",
                virtual_path="/docs/alpha.txt",
                snippet="Filename: <b>a</b>lpha.txt",
                rank=-10.0,
            ),
            SearchResult(
                file_ref_id=12,
                file_name="beta.txt",
                virtual_path="/docs/beta.txt",
                snippet="Filename: bet<b>a</b>.txt",
                rank=-9.0,
            ),
        ],
        has_more=True,
    )


def test_vault_service_search_page_delegates_to_file_service(
    tmp_path: Path, monkeypatch
) -> None:
    service = VaultService(app_data_dir=tmp_path)
    expected = SearchPage(results=[], has_more=True)
    captured: dict = {}

    def fake_search_page(query, limit, offset, *, scope="all"):
        captured["query"] = query
        captured["limit"] = limit
        captured["offset"] = offset
        captured["scope"] = scope
        return expected

    monkeypatch.setattr(service.files, "search_page", fake_search_page)

    # Default scope is "all" when caller omits it.
    assert service.search_page("hello", 5, 20) == expected
    assert captured == {"query": "hello", "limit": 5, "offset": 20, "scope": "all"}

    # Explicit scope is forwarded to the file service.
    assert (
        service.search_page("hello", 5, 20, scope="filename") == expected
    )
    assert captured["scope"] == "filename"


def test_vault_service_reindex_pending_delegates(tmp_path: Path, monkeypatch) -> None:
    service = VaultService(app_data_dir=tmp_path)
    monkeypatch.setattr(service.files, "reindex_pending", lambda limit: (2, 1))

    assert service.reindex_pending(25) == (2, 1)
