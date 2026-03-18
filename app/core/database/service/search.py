import time
from typing import TYPE_CHECKING, Optional

from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.utils.logging import logger

if TYPE_CHECKING:
    from app.core.database.model.file_entry import FileEntry

INSERT_SEARCH_INDEX_STATEMENT = text("""
    INSERT INTO search_index (file_entry_id, content)
    VALUES (:file_entry_id, :content)
""")

SEARCH_CONTENT_STATEMENT = text("""
    SELECT
        file_entry_id,
        snippet(search_index, 1, '<b>', '</b>', '...', 32) AS snippet_text,
        bm25(search_index) AS rank
    FROM search_index
    WHERE search_index MATCH :query
    ORDER BY rank
    LIMIT :limit
""")

SEARCH_CONTENT_DHIVEHI_VOWEL_STATEMENT = text("""
    SELECT
        file_entry_id,
        snippet(search_index, 1, '<b>', '</b>', '...', 32) AS snippet_text,
        bm25(search_index) AS rank,
        CASE WHEN instr(content, :exact_query) > 0 THEN 1 ELSE 0 END AS exact_match_boost
    FROM search_index
    WHERE search_index MATCH :query
    ORDER BY exact_match_boost DESC, rank, file_entry_id
    LIMIT :limit
""")

DHIVEHI_VOWEL_SIGNS = frozenset(
    {
        "\u07a6",
        "\u07a7",
        "\u07a8",
        "\u07a9",
        "\u07aa",
        "\u07ab",
        "\u07ac",
        "\u07ad",
        "\u07ae",
        "\u07af",
        "\u07b0",
    }
)


def _contains_dhivehi_vowel_signs(text_value: str) -> bool:
    return any(char in DHIVEHI_VOWEL_SIGNS for char in text_value)


def insert_document_content(
    session: Session, file_entry_id: str, content: str, retries: int = 3
) -> bool:
    """Insert file content into the FTS index.

    The caller owns the surrounding transaction and commit.
    """
    params = {"file_entry_id": file_entry_id, "content": content}

    for attempt in range(retries):
        try:
            session.execute(INSERT_SEARCH_INDEX_STATEMENT, params)
            session.flush()
            return True
        except OperationalError as e:
            if "database is locked" in str(e).lower():
                logger.warning(
                    f"Database locked during search index insert, retrying "
                    f"({attempt + 1}/{retries})"
                )
                time.sleep(1)
                continue
            raise

    return False


def search_content(
    session: Session,
    query: str,
    limit: int = 20,
) -> list[tuple[str, str, float]]:
    """Search indexed content and return `(file_entry_id, snippet, rank)` tuples."""
    normalized = query.strip()
    if not normalized:
        return []

    statement = SEARCH_CONTENT_STATEMENT
    params = {"query": normalized, "limit": limit}
    if _contains_dhivehi_vowel_signs(normalized):
        statement = SEARCH_CONTENT_DHIVEHI_VOWEL_STATEMENT
        params["exact_query"] = normalized

    rows = session.execute(statement, params).fetchall()
    return [(str(row[0]), row[1] or "", float(row[2])) for row in rows]


def update_extraction_status(
    session: Session,
    file_entry_id: int,
    status: str,
    preview: Optional[str] = None,
    metadata_json: Optional[str] = None,
) -> None:
    """Update the extraction status and optional preview/metadata for a file entry."""
    from app.core.database.model.file_entry import FileEntry

    entry = session.get(FileEntry, file_entry_id)
    if entry is None:
        return

    entry.text_extraction_status = status
    if preview is not None:
        entry.extracted_text_preview = preview
    if metadata_json is not None:
        entry.metadata_json = metadata_json
    session.flush()


def get_pending_extractions(
    session: Session,
    limit: int = 50,
) -> list["FileEntry"]:
    """Return file entries pending text extraction."""
    from app.core.database.model.file_entry import FileEntry

    return (
        session.query(FileEntry)
        .filter(FileEntry.text_extraction_status == "pending")
        .order_by(FileEntry.id)
        .limit(limit)
        .all()
    )


def get_retriable_extractions(
    session: Session,
    limit: int = 50,
) -> list["FileEntry"]:
    """Return file entries whose extraction should be retried."""
    from sqlalchemy.orm import joinedload

    from app.core.database.model.file_entry import FileEntry

    return (
        session.query(FileEntry)
        .options(
            joinedload(FileEntry.references),
            joinedload(FileEntry.blobs),
        )
        .filter(FileEntry.text_extraction_status.in_(("pending", "failed")))
        .order_by(FileEntry.id)
        .limit(limit)
        .all()
    )
