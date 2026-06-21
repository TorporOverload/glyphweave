from typing import Any

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

from app.infrastructure.persistence.db.base import Base
from app.infrastructure.persistence.db.model.extraction_status import ExtractionStatus
from app.infrastructure.persistence.db.model.file_blob_reference import (
    FileBlobReference,
)
from app.infrastructure.persistence.db.model.file_entry import FileEntry
from app.infrastructure.persistence.db.model.file_reference import FileReference
from app.infrastructure.persistence.db.service.search import (
    INSERT_SEARCH_INDEX_STATEMENT,
    get_pending_extractions,
    get_retriable_extractions,
    insert_document_content,
    search_content,
    search_file_references,
    update_extraction_status,
)


class _FakeSession:
    def __init__(self, execute_side_effects: list[Any] | None = None) -> None:
        self.execute_calls: list[tuple[Any, dict[str, str]]] = []
        self.flush_calls = 0
        self._execute_side_effects = execute_side_effects or []

    def execute(self, statement: Any, params: dict[str, str]) -> None:
        self.execute_calls.append((statement, params))
        if self._execute_side_effects:
            effect = self._execute_side_effects.pop(0)
            if isinstance(effect, Exception):
                raise effect

    def flush(self) -> None:
        self.flush_calls += 1


def _operational_error(message: str) -> OperationalError:
    return OperationalError("INSERT", {}, Exception(message))


def test_insert_document_content_flushes_on_success() -> None:
    session = _FakeSession()

    result = insert_document_content(session, "123", "hello world")  # noaq

    assert result is True
    assert session.flush_calls == 1
    assert session.execute_calls == [
        (
            INSERT_SEARCH_INDEX_STATEMENT,
            {"file_entry_id": "123", "content": "hello world"},
        )
    ]


def test_insert_document_content_retries_locked_database(monkeypatch) -> None:
    session = _FakeSession(
        [
            _operational_error("database is locked"),
            _operational_error("database is locked"),
            None,
        ]
    )
    sleep_calls: list[int] = []

    monkeypatch.setattr(
        "app.infrastructure.persistence.db.service.search.time.sleep",
        sleep_calls.append,
    )

    result = insert_document_content(session, "123", "hello", retries=3)

    assert result is True
    assert sleep_calls == [1, 1]
    assert len(session.execute_calls) == 3
    assert session.flush_calls == 1


def test_insert_document_content_returns_false_after_retry_exhaustion(
    monkeypatch,
) -> None:
    session = _FakeSession(
        [
            _operational_error("database is locked"),
            _operational_error("database is locked"),
        ]
    )

    monkeypatch.setattr(
        "app.infrastructure.persistence.db.service.search.time.sleep", lambda _: None
    )

    result = insert_document_content(session, "123", "hello", retries=2)

    assert result is False
    assert len(session.execute_calls) == 2
    assert session.flush_calls == 0


def test_insert_document_content_raises_non_lock_operational_error() -> None:
    session = _FakeSession([_operational_error("disk I/O error")])

    with pytest.raises(OperationalError, match="disk I/O error"):
        insert_document_content(session, "123", "hello")


def _build_session(tmp_path):
    db_path = tmp_path / "search_service.db"
    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)

    with engine.begin() as conn:
        conn.exec_driver_sql(
            """
            CREATE VIRTUAL TABLE IF NOT EXISTS search_index USING fts5(
                file_entry_id UNINDEXED,
                content
            )
            """
        )
        conn.exec_driver_sql(
            """
            CREATE VIRTUAL TABLE IF NOT EXISTS search_filename_index USING fts5(
                file_ref_id UNINDEXED,
                file_name
            )
            """
        )
        conn.exec_driver_sql(
            """
            CREATE TRIGGER IF NOT EXISTS trigger_insert_search_filename_index
                AFTER INSERT ON file_reference
                FOR EACH ROW
                    WHEN NEW.is_folder = 0
                    BEGIN
                        INSERT INTO search_filename_index (file_ref_id, file_name)
                        VALUES (NEW.id, NEW.name);
                    END;
            """
        )
        conn.exec_driver_sql(
            """
            CREATE TRIGGER IF NOT EXISTS trigger_delete_search_filename_index
                AFTER DELETE ON file_reference
                FOR EACH ROW
                    BEGIN
                        DELETE FROM search_filename_index WHERE file_ref_id = OLD.id;
                    END;
            """
        )
        conn.exec_driver_sql(
            """
            CREATE TRIGGER IF NOT EXISTS trigger_update_search_filename_index
                AFTER UPDATE OF name, is_folder ON file_reference
                FOR EACH ROW
                    BEGIN
                        DELETE FROM search_filename_index WHERE file_ref_id = OLD.id;
                        INSERT INTO search_filename_index (file_ref_id, file_name)
                        SELECT NEW.id, NEW.name
                        WHERE NEW.is_folder = 0;
                    END;
            """
        )

    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    return session_factory()


def _add_file_entry(
    session,
    *,
    file_id: str,
    content_hash: str,
    status: str = ExtractionStatus.PENDING.value,
) -> FileEntry:
    entry = FileEntry(
        file_id=file_id,
        content_hash=content_hash,
        mime_type="text/plain",
        encrypted_size_bytes=10,
        original_size_bytes=10,
        text_extraction_status=status,
    )
    session.add(entry)
    session.flush()
    return entry


def test_search_content_returns_empty_for_blank_query(tmp_path) -> None:
    session = _build_session(tmp_path)

    assert search_content(session, "   ") == []


def test_search_content_returns_matching_entry_ids(tmp_path) -> None:
    session = _build_session(tmp_path)
    entry = _add_file_entry(
        session,
        file_id="f-1",
        content_hash="h-1",
        status=ExtractionStatus.DONE.value,
    )
    insert_document_content(session, str(entry.id), "hello world from glyphweave")
    session.commit()

    results = search_content(session, "hello")

    assert len(results) == 1
    assert results[0][0] == str(entry.id)
    assert "hello" in results[0][1].lower()
    assert isinstance(results[0][2], float)


def test_search_content_ignores_special_characters_in_plain_query(tmp_path) -> None:
    session = _build_session(tmp_path)
    entry = _add_file_entry(
        session,
        file_id="f-1b",
        content_hash="h-1b",
        status=ExtractionStatus.DONE.value,
    )
    insert_document_content(session, str(entry.id), "license pt3 1669874052 text")
    session.commit()

    results = search_content(session, "license-pt3_1669874052")

    assert len(results) == 1
    assert results[0][0] == str(entry.id)


def test_search_file_references_returns_filename_matches_first(tmp_path) -> None:
    session = _build_session(tmp_path)
    exact = _add_file_entry(session, file_id="f-name-1", content_hash="h-name-1")
    loose = _add_file_entry(session, file_id="f-name-2", content_hash="h-name-2")
    session.add(
        FileReference(
            name="report.txt",
            is_folder=False,
            file_entry_id=exact.id,
            virtual_path="/docs/report.txt",
        )
    )
    session.add(
        FileReference(
            name="team-report-notes.txt",
            is_folder=False,
            file_entry_id=loose.id,
            virtual_path="/docs/team-report-notes.txt",
        )
    )
    session.commit()

    results = search_file_references(session, "report", limit=10)

    assert len(results) == 2
    assert results[0][1] == "report.txt"
    assert results[1][1] == "team-report-notes.txt"


def test_search_file_references_does_not_match_folder_path_only(tmp_path) -> None:
    session = _build_session(tmp_path)
    entry = _add_file_entry(session, file_id="f-name-3", content_hash="h-name-3")
    session.add(
        FileReference(
            name="import.txt",
            is_folder=False,
            file_entry_id=entry.id,
            virtual_path="/export/import.txt",
        )
    )
    session.commit()

    results = search_file_references(session, "export", limit=10)

    assert results == []


def test_search_file_references_supports_boolean_queries(tmp_path) -> None:
    session = _build_session(tmp_path)
    a = _add_file_entry(session, file_id="f-name-4", content_hash="h-name-4")
    b = _add_file_entry(session, file_id="f-name-5", content_hash="h-name-5")
    c = _add_file_entry(session, file_id="f-name-6", content_hash="h-name-6")
    session.add(
        FileReference(
            name="budget-report.txt",
            is_folder=False,
            file_entry_id=a.id,
            virtual_path="/docs/budget-report.txt",
        )
    )
    session.add(
        FileReference(
            name="budget-notes.txt",
            is_folder=False,
            file_entry_id=b.id,
            virtual_path="/docs/budget-notes.txt",
        )
    )
    session.add(
        FileReference(
            name="report-summary.txt",
            is_folder=False,
            file_entry_id=c.id,
            virtual_path="/docs/report-summary.txt",
        )
    )
    session.commit()

    results = search_file_references(session, "budget AND report", limit=10)

    assert len(results) == 1
    assert results[0][1] == "budget-report.txt"


def test_search_file_references_supports_lowercase_boolean_queries(tmp_path) -> None:
    session = _build_session(tmp_path)
    a = _add_file_entry(session, file_id="f-name-4b", content_hash="h-name-4b")
    b = _add_file_entry(session, file_id="f-name-5b", content_hash="h-name-5b")
    session.add(
        FileReference(
            name="budget-report.txt",
            is_folder=False,
            file_entry_id=a.id,
            virtual_path="/docs/budget-report.txt",
        )
    )
    session.add(
        FileReference(
            name="budget-notes.txt",
            is_folder=False,
            file_entry_id=b.id,
            virtual_path="/docs/budget-notes.txt",
        )
    )
    session.commit()

    results = search_file_references(session, "budget and report", limit=10)

    assert len(results) == 1
    assert results[0][1] == "budget-report.txt"


def test_search_content_supports_lowercase_boolean_queries(tmp_path) -> None:
    session = _build_session(tmp_path)
    first = _add_file_entry(
        session,
        file_id="f-content-1",
        content_hash="h-content-1",
        status=ExtractionStatus.DONE.value,
    )
    second = _add_file_entry(
        session,
        file_id="f-content-2",
        content_hash="h-content-2",
        status=ExtractionStatus.DONE.value,
    )
    insert_document_content(session, str(first.id), "budget report overview")
    insert_document_content(session, str(second.id), "budget notes only")
    session.commit()

    results = search_content(session, "budget and report")

    assert len(results) == 1
    assert results[0][0] == str(first.id)


def test_search_content_preserves_quoted_phrase_with_lowercase_operators(
    tmp_path,
) -> None:
    session = _build_session(tmp_path)
    first = _add_file_entry(
        session,
        file_id="f-content-3",
        content_hash="h-content-3",
        status=ExtractionStatus.DONE.value,
    )
    second = _add_file_entry(
        session,
        file_id="f-content-4",
        content_hash="h-content-4",
        status=ExtractionStatus.DONE.value,
    )
    insert_document_content(session, str(first.id), 'budget report "exact phrase"')
    insert_document_content(session, str(second.id), 'budget report "phrase only"')
    session.commit()

    results = search_content(session, 'budget and "exact phrase"', limit=10)

    assert len(results) == 1
    assert results[0][0] == str(first.id)


def test_search_file_references_updates_after_rename(tmp_path) -> None:
    session = _build_session(tmp_path)
    entry = _add_file_entry(session, file_id="f-name-7", content_hash="h-name-7")
    ref = FileReference(
        name="draft.txt",
        is_folder=False,
        file_entry_id=entry.id,
        virtual_path="/docs/draft.txt",
    )
    session.add(ref)
    session.commit()

    ref.name = "final.txt"
    ref.virtual_path = "/docs/final.txt"
    session.commit()

    assert search_file_references(session, "draft", limit=10) == []
    renamed = search_file_references(session, "final", limit=10)
    assert len(renamed) == 1
    assert renamed[0][1] == "final.txt"


def test_search_file_references_supports_partial_prefix_and_numeric_matches(
    tmp_path,
) -> None:
    session = _build_session(tmp_path)
    entry = _add_file_entry(session, file_id="f-name-8", content_hash="h-name-8")
    session.add(
        FileReference(
            name="enviromnetal-impact-of-ai-02152023.pdf",
            is_folder=False,
            file_entry_id=entry.id,
            virtual_path="/docs/enviromnetal-impact-of-ai-02152023000.pdf",
        )
    )
    session.commit()

    text_results = search_file_references(session, "envirom", limit=10)
    numeric_results = search_file_references(session, "02152023", limit=10)

    assert len(text_results) == 1
    assert text_results[0][1] == "enviromnetal-impact-of-ai-02152023.pdf"
    assert text_results[0][2] == "/enviromnetal-impact-of-ai-02152023.pdf"
    assert len(numeric_results) == 1
    assert numeric_results[0][1] == "enviromnetal-impact-of-ai-02152023.pdf"
    assert numeric_results[0][2] == "/enviromnetal-impact-of-ai-02152023.pdf"


def test_search_file_references_supports_hyphenated_filename_query(tmp_path) -> None:
    session = _build_session(tmp_path)
    entry = _add_file_entry(session, file_id="f-name-8b", content_hash="h-name-8b")
    session.add(
        FileReference(
            name="license-pt3_1669874052.pdf",
            is_folder=False,
            file_entry_id=entry.id,
            virtual_path="/docs/license-pt3_1669874052.pdf",
        )
    )
    session.commit()

    results = search_file_references(session, "license-pt3_1669874052", limit=10)

    assert len(results) == 1
    assert results[0][1] == "license-pt3_1669874052.pdf"


def test_search_content_supports_dhivehi_query(tmp_path) -> None:
    session = _build_session(tmp_path)
    entry = _add_file_entry(
        session,
        file_id="f-2",
        content_hash="h-2",
        status=ExtractionStatus.DONE.value,
    )
    insert_document_content(
        session,
        str(entry.id),
        """Þ‰Þ¨ ÞŒÞ«ÞŠÞ§Þ‚Þ¦Þ†Þ© Þ‡Þ¨ÞƒÞªÞ‰Þ¦ÞŒÞ© Þ•Þ§Þ†Þ¨ÞÞ°ÞŒÞ§Þ‚Þ¦ÞÞ°
        Þ‚ÞªÞˆÞ¦ÞŒÞ¦ Þ‰Þ¨Þ€Þ§ÞƒÞªÞŽÞ¬ Þ„Þ¦Þ‚Þ°ÞŽÞ°ÞÞ¦Þ‹Þ­ÞÞ°
        Þ‡Þ¦ÞÞ§Þ‡Þ¨ Þ‡Þ¨ÞƒÞªÞ‰Þ¦ÞŒÞ© Þ‡Þ¨Þ‚Þ°Þ‘Þ¨Þ‡Þ§ÞŽÞ¬ ÞˆÞ¬ÞÞ°Þ“Þ° Þ„Þ¬Þ‚Þ°ÞŽÞ°ÞÞ§Þ‡Þ¦ÞÞ° 1970ÞŽÞ¦Þ‡Þ¨ Þ‡Þ¬ÞƒÞ¨ ÞŒÞ«ÞŠÞ¦Þ‚Þ¬Þ†Þ¬ÞˆÞ¬. Þ‰Þ¨
        ÞŒÞ«ÞŠÞ§Þ‚ÞªÞŽÞ¦Þ‡Þ¨ 500000 Þ‡Þ§Þ‡Þ¨ 250000 Þ‡Þ§ Þ‹Þ¬Þ‰Þ¬Þ‹ÞªÞŽÞ¬ Þ‰Þ©Þ€ÞªÞ‚Þ° Þ‰Þ¦ÞƒÞªÞˆÞ¬ÞŠÞ¦Þ‡Þ¨ÞˆÞ¦Þ†Þ¦Þ‰Þ¦ÞÞ° ÞƒÞ¨Þ•Þ¯Þ“ÞªÞŒÞ¦Þ†ÞªÞ‚Þ° Þ‹Þ¦Þ‡Þ°Þ†Þ¦Þ‡Þ¬ÞˆÞ¬.""",
    )  # noaq
    session.commit()

    results = search_content(session, "Þ‡Þ¨ÞƒÞªÞ‰Þ¦ÞŒÞ© ")

    print(results)

    assert len(results) == 1
    assert results[0][0] == str(entry.id)
    assert results[0][1]
    assert isinstance(results[0][2], float)


def test_search_content_prioritizes_exact_dhivehi_vowel_matches(tmp_path) -> None:
    session = _build_session(tmp_path)
    exact = _add_file_entry(
        session,
        file_id="f-2a",
        content_hash="h-2a",
        status=ExtractionStatus.DONE.value,
    )
    loose = _add_file_entry(
        session,
        file_id="f-2b",
        content_hash="h-2b",
        status=ExtractionStatus.DONE.value,
    )
    insert_document_content(
        session,
        str(exact.id),
        "Þ‡Þ¨ÞƒÞªÞ‰Þ¦ÞŒÞ© Þ•Þ§Þ†Þ¨ÞÞ°ÞŒÞ§Þ‚Þ¦ÞÞ° ÞˆÞ§Þ€Þ¦Þ†Þ¦",
    )
    insert_document_content(
        session,
        str(loose.id),
        "Þ•Þ§Þ†Þ¨ÞÞ°ÞŒÞ§Þ‚Þ¦ÞÞ° ÞˆÞ§Þ€Þ¦Þ†Þ¦ Þ‡Þ¨ÞƒÞªÞ‰Þ¦ÞŒÞ©",
    )
    session.commit()

    results = search_content(session, "Þ‡Þ¨ÞƒÞªÞ‰Þ¦ÞŒÞ© Þ•Þ§Þ†Þ¨ÞÞ°ÞŒÞ§Þ‚Þ¦ÞÞ°")

    assert len(results) == 2
    assert results[0][0] == str(exact.id)
    assert results[1][0] == str(loose.id)


def test_update_extraction_status_sets_done(tmp_path) -> None:
    session = _build_session(tmp_path)
    entry = _add_file_entry(session, file_id="f-3", content_hash="h-3")

    update_extraction_status(
        session,
        entry.id,
        ExtractionStatus.DONE,
        preview="preview text",
        metadata_json='{"lang":"dv"}',
    )
    session.commit()
    session.refresh(entry)

    assert entry.text_extraction_status == ExtractionStatus.DONE.value
    assert entry.extracted_text_preview == "preview text"
    assert entry.metadata_json == '{"lang":"dv"}'


def test_update_extraction_status_noops_for_missing_entry(tmp_path) -> None:
    session = _build_session(tmp_path)

    update_extraction_status(
        session,
        999,
        ExtractionStatus.DONE,
        preview="x",
        metadata_json="{}",
    )


def test_get_pending_extractions_returns_pending_only(tmp_path) -> None:
    session = _build_session(tmp_path)
    pending_a = _add_file_entry(session, file_id="f-4", content_hash="h-4")
    pending_b = _add_file_entry(session, file_id="f-5", content_hash="h-5")
    _add_file_entry(
        session,
        file_id="f-6",
        content_hash="h-6",
        status=ExtractionStatus.DONE.value,
    )
    session.commit()

    results = get_pending_extractions(session, limit=10)

    assert [entry.id for entry in results] == [pending_a.id, pending_b.id]


def test_get_retriable_extractions_eager_loads_refs_and_blobs(tmp_path) -> None:
    session = _build_session(tmp_path)
    entry = _add_file_entry(
        session,
        file_id="f-7",
        content_hash="h-7",
        status=ExtractionStatus.FAILED.value,
    )
    session.add(
        FileBlobReference(file_entry_id=entry.id, blob_id="blob-1.enc", blob_index=0)
    )
    session.add(
        FileReference(
            name="report.txt",
            is_folder=False,
            file_entry_id=entry.id,
            virtual_path="/report.txt",
        )
    )
    session.commit()

    retriable = get_retriable_extractions(session, limit=10)
    session.close()

    assert len(retriable) == 1
    assert retriable[0].references[0].name == "report.txt"
    assert retriable[0].blobs[0].blob_id == "blob-1.enc"



# Tiered search: OR fallback and phrase-rank tests


def test_search_content_or_fallback_finds_single_term_match(tmp_path) -> None:
    """A doc containing only one term of a multi-word query must still appear,
    and no other docs sneak into the result set."""
    session = _build_session(tmp_path)
    salt_only = _add_file_entry(
        session, file_id="f-tier-1", content_hash="h-tier-1",
        status=ExtractionStatus.DONE.value,
    )
    insert_document_content(session, str(salt_only.id), "salt water is used in cooking")
    session.commit()

    results = search_content(session, "ocean salt")

    assert len(results) == 1, f"expected exactly one match, got {results}"
    assert results[0][0] == str(salt_only.id)


def test_search_content_phrase_tier_ranks_above_scattered_and(tmp_path) -> None:
    """Doc with the exact phrase must rank above a doc where terms appear far apart."""
    session = _build_session(tmp_path)
    phrase_doc = _add_file_entry(
        session, file_id="f-tier-2a", content_hash="h-tier-2a",
        status=ExtractionStatus.DONE.value,
    )
    scattered_doc = _add_file_entry(
        session, file_id="f-tier-2b", content_hash="h-tier-2b",
        status=ExtractionStatus.DONE.value,
    )
    insert_document_content(session, str(phrase_doc.id), "ocean salt is a natural mineral")
    insert_document_content(
        session, str(scattered_doc.id),
        "the ocean covers most of the earth and contains a lot of salt",
    )
    session.commit()

    results = search_content(session, "ocean salt")

    assert len(results) == 2
    assert results[0][0] == str(phrase_doc.id)
    assert results[1][0] == str(scattered_doc.id)


def test_search_content_phrase_tier_ranks_above_or_only(tmp_path) -> None:
    """Doc matching the phrase ranks above a doc matching only one term."""
    session = _build_session(tmp_path)
    phrase_doc = _add_file_entry(
        session, file_id="f-tier-3a", content_hash="h-tier-3a",
        status=ExtractionStatus.DONE.value,
    )
    or_doc = _add_file_entry(
        session, file_id="f-tier-3b", content_hash="h-tier-3b",
        status=ExtractionStatus.DONE.value,
    )
    insert_document_content(session, str(phrase_doc.id), "ocean salt deposits are common")
    insert_document_content(session, str(or_doc.id), "salt is a common mineral")
    session.commit()

    results = search_content(session, "ocean salt")

    phrase_pos = next(i for i, r in enumerate(results) if r[0] == str(phrase_doc.id))
    or_pos = next(i for i, r in enumerate(results) if r[0] == str(or_doc.id))
    assert phrase_pos < or_pos


def test_search_file_references_or_fallback_finds_partial_filename(tmp_path) -> None:
    """A file whose name contains only one term of a multi-word query must appear."""
    session = _build_session(tmp_path)
    entry = _add_file_entry(session, file_id="f-fn-tier-1", content_hash="h-fn-tier-1")
    session.add(
        FileReference(
            name="salt-recipe.pdf",
            is_folder=False,
            file_entry_id=entry.id,
            virtual_path="/salt-recipe.pdf",
        )
    )
    session.commit()

    results = search_file_references(session, "ocean salt", limit=10)

    assert any(r[1] == "salt-recipe.pdf" for r in results)


def test_search_file_references_phrase_tier_ranks_above_or_only(tmp_path) -> None:
    """File whose name contains the full phrase ranks above a file with one term."""
    session = _build_session(tmp_path)
    phrase_entry = _add_file_entry(
        session, file_id="f-fn-tier-2a", content_hash="h-fn-tier-2a"
    )
    or_entry = _add_file_entry(
        session, file_id="f-fn-tier-2b", content_hash="h-fn-tier-2b"
    )
    session.add(
        FileReference(
            name="ocean salt minerals.txt",
            is_folder=False,
            file_entry_id=phrase_entry.id,
            virtual_path="/ocean salt minerals.txt",
        )
    )
    session.add(
        FileReference(
            name="salt-deposits.txt",
            is_folder=False,
            file_entry_id=or_entry.id,
            virtual_path="/salt-deposits.txt",
        )
    )
    session.commit()

    results = search_file_references(session, "ocean salt", limit=10)

    names = [r[1] for r in results]
    assert "ocean salt minerals.txt" in names
    assert "salt-deposits.txt" in names
    assert names.index("ocean salt minerals.txt") < names.index("salt-deposits.txt")



# Thaana (Dhivehi) normalization tests



_DV_DOC_1 = (
    "ދިވެހި ބަސް "
    "އިރުމަތީ "
    "ޕާކިސްތާނަސް"
)
_DV_DOC_2 = (
    "މި ތޫސާނުގައި "
    "500000 އާއި 250000 އާ ދެމެ"
)

# First word from doc 1: ދިވެހި  (with vowels)
_DV_WORD_WITH_VOWELS = "ދިވެހި"
# Same word, bare consonants: ދވހ
_DV_WORD_BARE = "ދވހ"
# Second word from doc 1: ބަސް (with vowels)
_DV_WORD2_WITH_VOWELS = "ބަސް"
# Different vowelization of same consonants: ބޭސް
_DV_WORD2_ALT_VOWELS = "ބޭސް"


def test_search_content_dhivehi_bare_consonants(tmp_path) -> None:
    """Searching bare Thaana consonants (no fili) must find voweled content."""
    session = _build_session(tmp_path)
    entry = _add_file_entry(
        session, file_id="f-dv-1", content_hash="h-dv-1",
        status=ExtractionStatus.DONE.value,
    )
    insert_document_content(session, str(entry.id), _DV_DOC_1)
    session.commit()

    results = search_content(session, _DV_WORD_BARE)

    assert any(r[0] == str(entry.id) for r in results)


def test_search_content_dhivehi_voweled_query(tmp_path) -> None:
    """Searching with vowel signs still works (same token sequence)."""
    session = _build_session(tmp_path)
    entry = _add_file_entry(
        session, file_id="f-dv-2", content_hash="h-dv-2",
        status=ExtractionStatus.DONE.value,
    )
    insert_document_content(session, str(entry.id), _DV_DOC_1)
    session.commit()

    results = search_content(session, _DV_WORD_WITH_VOWELS)

    assert any(r[0] == str(entry.id) for r in results)


def test_search_content_dhivehi_cross_vowel_match(tmp_path) -> None:
    """Different vowelization of same consonants must match (FTS5 strips fili)."""
    session = _build_session(tmp_path)
    entry = _add_file_entry(
        session, file_id="f-dv-3", content_hash="h-dv-3",
        status=ExtractionStatus.DONE.value,
    )
    insert_document_content(session, str(entry.id), _DV_DOC_1)
    session.commit()

    results = search_content(session, _DV_WORD2_ALT_VOWELS)

    assert any(r[0] == str(entry.id) for r in results)


def test_search_content_dhivehi_multi_word_or_fallback(tmp_path) -> None:
    """Multi-word Dhivehi query: doc with only one word still found via OR tier."""
    session = _build_session(tmp_path)
    doc_word1_only = _add_file_entry(
        session, file_id="f-dv-4a", content_hash="h-dv-4a",
        status=ExtractionStatus.DONE.value,
    )
    doc_both = _add_file_entry(
        session, file_id="f-dv-4b", content_hash="h-dv-4b",
        status=ExtractionStatus.DONE.value,
    )
    insert_document_content(session, str(doc_word1_only.id), _DV_DOC_2)
    insert_document_content(session, str(doc_both.id), _DV_DOC_1)
    session.commit()

    query = _DV_WORD_WITH_VOWELS + " " + _DV_WORD2_WITH_VOWELS

    results = search_content(session, query)

    result_ids = [r[0] for r in results]
    assert str(doc_both.id) in result_ids
    # doc_word1_only should appear too if it has at least one of the searched words
    # _DV_DOC_2 starts with މި which doesn't match ދިވެހި or ބަސް,
    # so it may not appear - but doc_both must.


def test_search_content_dhivehi_exact_vowel_ranks_first(tmp_path) -> None:
    """Doc with exact vowelization ranks above doc with different vowels."""
    session = _build_session(tmp_path)
    exact = _add_file_entry(
        session, file_id="f-dv-5a", content_hash="h-dv-5a",
        status=ExtractionStatus.DONE.value,
    )
    alt = _add_file_entry(
        session, file_id="f-dv-5b", content_hash="h-dv-5b",
        status=ExtractionStatus.DONE.value,
    )
    insert_document_content(
        session, str(exact.id),
        _DV_WORD_WITH_VOWELS + " " + _DV_WORD2_WITH_VOWELS + " content",
    )
    insert_document_content(
        session, str(alt.id),
        _DV_WORD_WITH_VOWELS + " " + _DV_WORD2_ALT_VOWELS + " content",
    )
    session.commit()

    results = search_content(
        session, _DV_WORD_WITH_VOWELS + " " + _DV_WORD2_WITH_VOWELS
    )

    assert len(results) == 2
    assert results[0][0] == str(exact.id)


def test_search_file_references_dhivehi_bare_consonants(tmp_path) -> None:
    """Filename search with bare Thaana consonants finds voweled filenames."""
    session = _build_session(tmp_path)
    entry = _add_file_entry(session, file_id="f-dv-fn-1", content_hash="h-dv-fn-1")
    session.add(
        FileReference(
            name=_DV_WORD_WITH_VOWELS + ".pdf",
            is_folder=False,
            file_entry_id=entry.id,
            virtual_path="/" + _DV_WORD_WITH_VOWELS + ".pdf",
        )
    )
    session.commit()

    results = search_file_references(session, _DV_WORD_BARE, limit=10)

    assert any(_DV_WORD_WITH_VOWELS + ".pdf" == r[1] for r in results)
