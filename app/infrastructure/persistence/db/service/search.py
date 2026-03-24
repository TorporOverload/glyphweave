import re
import time
from typing import TYPE_CHECKING, Optional

from sqlalchemy import select, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.infrastructure.persistence.db.model.extraction_status import ExtractionStatus
from app.common.logging import logger

if TYPE_CHECKING:
    from app.infrastructure.persistence.db.model.file_entry import FileEntry

INSERT_SEARCH_INDEX_STATEMENT = text("""
    INSERT INTO search_index (file_entry_id, content)
    VALUES (:file_entry_id, :content)
""")

SEARCH_FILE_REFERENCES_STATEMENT = text("""
    SELECT
        fr.id,
        fr.name,
        fr.virtual_path,
        snippet(search_filename_index, 1, '<b>', '</b>', '...', 32) AS snippet_text,
        CASE
            WHEN fr.name = :exact_query THEN 3
            WHEN instr(fr.name, :exact_query) = 1 THEN 2
            WHEN :use_dhivehi_exact_boost = 1 AND 
                instr(fr.name, :exact_query) > 0 THEN 1
            WHEN instr(fr.name, :exact_query) > 0 THEN 1
            ELSE 0
        END AS exact_match_boost,
        bm25(search_filename_index) AS rank
    FROM search_filename_index
    JOIN file_reference AS fr ON fr.id = search_filename_index.file_ref_id
    WHERE search_filename_index MATCH :query
      AND fr.is_folder = 0
    ORDER BY exact_match_boost DESC, rank, fr.id
    LIMIT :limit
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
        CASE WHEN instr(content, :exact_query) > 0 
            THEN 1 ELSE 0 END AS exact_match_boost
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

FTS_BOOLEAN_OPERATOR_PATTERN = re.compile(r"\b(?:AND|OR|NOT)\b")
FTS_BOOLEAN_OPERATOR_NORMALIZE_PATTERN = re.compile(
    r"\b(and|or|not)\b",
    re.IGNORECASE,
)
FTS_QUERY_TOKEN_PATTERN = re.compile(r"[^\W_]+", re.UNICODE)


def _contains_dhivehi_vowel_signs(text_value: str) -> bool:
    return any(char in DHIVEHI_VOWEL_SIGNS for char in text_value)


def _normalize_boolean_operators(text_value: str) -> str:
    parts = text_value.split('"')
    for index in range(0, len(parts), 2):
        parts[index] = FTS_BOOLEAN_OPERATOR_NORMALIZE_PATTERN.sub(
            lambda match: match.group(1).upper(),
            parts[index],
        )
    return '"'.join(parts)


def _prepare_fts_match_query(text_value: str, *, prefix_terms: bool) -> str:
    normalized_text = _normalize_boolean_operators(text_value)
    if (
        not normalized_text
        or '"' in normalized_text
        or "(" in normalized_text
        or ")" in normalized_text
        or "*" in normalized_text
        or ":" in normalized_text
        or FTS_BOOLEAN_OPERATOR_PATTERN.search(normalized_text)
    ):
        return normalized_text

    terms = FTS_QUERY_TOKEN_PATTERN.findall(normalized_text)
    if not terms:
        return normalized_text

    if prefix_terms:
        return " ".join(f"{term}*" for term in terms)
    return " ".join(terms)


def _prepare_filename_match_query(text_value: str) -> str:
    return _prepare_fts_match_query(text_value, prefix_terms=True)


def _prepare_content_match_query(text_value: str) -> str:
    return _prepare_fts_match_query(text_value, prefix_terms=False)


def insert_document_content(
    session: Session,
    file_entry_id: int,
    content: str,
    retries: int = 3,
) -> bool:
    """Insert file content into the FTS index."""
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
    params = {"query": _prepare_content_match_query(normalized), "limit": limit}
    if _contains_dhivehi_vowel_signs(normalized):
        statement = SEARCH_CONTENT_DHIVEHI_VOWEL_STATEMENT
        params["exact_query"] = normalized

    rows = session.execute(statement, params).fetchall()
    return [(str(row[0]), row[1] or "", float(row[2])) for row in rows]


def search_file_references(
    session: Session,
    query: str,
    limit: int = 20,
) -> list[tuple[int, str, str, float]]:
    """Search visible filenames via FTS and return ranked file reference hits."""
    normalized = query.strip()
    if not normalized:
        return []

    rows = session.execute(
        SEARCH_FILE_REFERENCES_STATEMENT,
        {
            "query": _prepare_filename_match_query(normalized),
            "exact_query": normalized,
            "limit": limit,
            "use_dhivehi_exact_boost": int(_contains_dhivehi_vowel_signs(normalized)),
        },
    ).fetchall()
    return [(int(row[0]), row[1], row[2], float(row[5])) for row in rows]


def update_extraction_status(
    session: Session,
    file_entry_id: int,
    status: ExtractionStatus,
    preview: Optional[str] = None,
    metadata_json: Optional[str] = None,
) -> None:
    """Update the extraction status and optional preview/metadata for a file entry."""
    from app.infrastructure.persistence.db.model.file_entry import FileEntry

    entry = session.get(FileEntry, file_entry_id)
    if entry is None:
        return

    entry.text_extraction_status = status.value
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
    from app.infrastructure.persistence.db.model.file_entry import FileEntry

    return list(
        session.scalars(
            select(FileEntry)
            .where(FileEntry.text_extraction_status == ExtractionStatus.PENDING.value)
            .order_by(FileEntry.id)
            .limit(limit)
        ).all()
    )


def get_retriable_extractions(
    session: Session,
    limit: int = 50,
) -> list["FileEntry"]:
    """Return file entries whose extraction should be retried."""
    from sqlalchemy.orm import joinedload

    from app.infrastructure.persistence.db.model.file_entry import FileEntry

    return list(
        session.scalars(
            select(FileEntry)
            .options(
                joinedload(FileEntry.references),
                joinedload(FileEntry.blobs),
            )
            .where(
                FileEntry.text_extraction_status.in_(
                    (
                        ExtractionStatus.PENDING.value,
                        ExtractionStatus.FAILED.value,
                    )
                )
            )
            .order_by(FileEntry.id)
            .limit(limit)
        )
        .unique()
        .all()
    )
