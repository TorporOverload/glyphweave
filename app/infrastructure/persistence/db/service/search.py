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


def _contains_thaana(text_value: str) -> bool:
    """Return True if text contains any Thaana script characters (consonants or vowels)."""
    return any(0x0780 <= ord(ch) <= 0x07B1 for ch in text_value)


def _normalize_thaana_for_fts(text_value: str) -> str:
    """Normalize Thaana text to match FTS5 unicode61 tokenization.

    The unicode61 tokenizer treats Thaana vowel signs (fili, U+07A6-U+07B0) as
    token separators, shattering each Dhivehi word into individual consonant
    tokens. This function strips fili and inserts spaces between consecutive
    Thaana consonants so the query produces the same token sequence FTS5 stores.

    Non-Thaana characters pass through unchanged.
    """
    result: list[str] = []
    prev_was_thaana_consonant = False
    for ch in text_value:
        cp = ord(ch)
        if 0x07A6 <= cp <= 0x07B0:
            continue  # fili: FTS5 discards these during tokenization
        is_thaana = (0x0780 <= cp <= 0x07A5) or cp == 0x07B1
        if is_thaana and prev_was_thaana_consonant:
            result.append(" ")
        result.append(ch)
        prev_was_thaana_consonant = is_thaana
    return "".join(result)


def _thaana_word_phrases(text_value: str) -> list[str]:
    """Parse text into word-level FTS5 queries for Thaana-aware search.

    Each Thaana word becomes a quoted phrase of its constituent consonants
    (e.g. ``"ދ ވ ހ"`` for ``ދިވެހި``).  Non-Thaana words pass through as
    plain terms.
    """
    phrases: list[str] = []
    for word in text_value.split():
        consonants: list[str] = []
        has_thaana = False
        for ch in word:
            cp = ord(ch)
            if 0x07A6 <= cp <= 0x07B0:
                continue
            if (0x0780 <= cp <= 0x07A5) or cp == 0x07B1:
                consonants.append(ch)
                has_thaana = True
            else:
                consonants.append(ch)
        if not consonants:
            continue
        if has_thaana and len(consonants) > 1:
            phrases.append('"' + " ".join(consonants) + '"')
        elif has_thaana:
            phrases.append(consonants[0])
        else:
            phrases.append("".join(consonants))
    return phrases


def _normalize_boolean_operators(text_value: str) -> str:
    parts = text_value.split('"')
    for index in range(0, len(parts), 2):
        parts[index] = FTS_BOOLEAN_OPERATOR_NORMALIZE_PATTERN.sub(
            lambda match: match.group(1).upper(),
            parts[index],
        )
    return '"'.join(parts)


def _is_user_fts_syntax(text_value: str) -> bool:
    """Return True if the text already contains FTS5 syntax that should pass through unchanged."""
    return bool(
        '"' in text_value
        or "(" in text_value
        or ")" in text_value
        or "*" in text_value
        or ":" in text_value
        or FTS_BOOLEAN_OPERATOR_PATTERN.search(text_value)
    )


def _build_thaana_tiers(text_value: str, *, prefix_terms: bool) -> list[str]:
    """Build FTS5 query tiers for Thaana-containing text.

    Each Dhivehi word becomes a quoted phrase of its consonants so that
    ``ދިވެހި`` and bare-consonant ``ދވހ`` both resolve to ``"ދ ވ ހ"``.

    For multi-word queries the OR tier uses word-level phrases rather than
    individual consonants, avoiding the single-consonant over-matching
    problem inherent to FTS5's treatment of Thaana.
    """
    word_phrases = _thaana_word_phrases(text_value)
    if prefix_terms:
        word_phrases = [
            wp if wp.startswith('"') else f"{wp}*"
            for wp in word_phrases
        ]
    if not word_phrases:
        return [text_value]
    if len(word_phrases) == 1:
        return word_phrases

    tiers: list[str] = []

    all_thaana = all(wp.startswith('"') for wp in word_phrases)
    if all_thaana:
        fts_normalized = _normalize_thaana_for_fts(text_value)
        consonants = FTS_QUERY_TOKEN_PATTERN.findall(fts_normalized)
        if len(consonants) > 1:
            tiers.append('"' + " ".join(consonants) + '"')

    tiers.append(" ".join(word_phrases))
    tiers.append(" OR ".join(word_phrases))
    return tiers


def _build_content_tiers(text_value: str) -> list[str]:
    """Return FTS5 query strings for content search, from strictest to most permissive.

    For a multi-word query like "ocean salt" this produces three tiers:
      0. ``"ocean salt"``   — exact adjacent phrase (highest rank)
      1. ``ocean salt``     — both terms anywhere in document (AND)
      2. ``ocean OR salt``  — either term present (OR fallback)

    Thaana (Dhivehi) queries use word-level consonant phrases instead of
    individual tokens, avoiding single-consonant over-matching.
    """
    normalized = _normalize_boolean_operators(text_value)
    if not normalized or _is_user_fts_syntax(normalized):
        return [normalized]
    if _contains_thaana(normalized):
        return _build_thaana_tiers(normalized, prefix_terms=False)
    terms = FTS_QUERY_TOKEN_PATTERN.findall(normalized)
    if not terms:
        return [normalized]
    if len(terms) == 1:
        return [terms[0]]
    return [
        '"' + " ".join(terms) + '"',  # Tier 0: exact phrase
        " ".join(terms),               # Tier 1: all terms (AND)
        " OR ".join(terms),            # Tier 2: any term (OR)
    ]


def _build_filename_tiers(text_value: str) -> list[str]:
    """Return FTS5 query strings for filename search, from strictest to most permissive.

    Prefix wildcards (``*``) are appended to non-Thaana terms so partial
    filename tokens match.  Thaana words use consonant-phrase matching.
    """
    normalized = _normalize_boolean_operators(text_value)
    if not normalized or _is_user_fts_syntax(normalized):
        return [normalized]
    if _contains_thaana(normalized):
        return _build_thaana_tiers(normalized, prefix_terms=True)
    terms = FTS_QUERY_TOKEN_PATTERN.findall(normalized)
    if not terms:
        return [normalized]
    if len(terms) == 1:
        return [f"{terms[0]}*"]
    return [
        '"' + " ".join(terms) + '"',           # Tier 0: exact phrase
        " ".join(f"{t}*" for t in terms),       # Tier 1: all terms prefix (AND)
        " OR ".join(f"{t}*" for t in terms),    # Tier 2: any term prefix (OR)
    ]


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
    """Search indexed content and return `(file_entry_id, snippet, rank)` tuples.

    Runs up to three FTS5 tiers (phrase → AND → OR) and merges results so that
    phrase matches rank above scattered-term matches, which rank above single-term
    matches.  Results from a higher tier always outrank results from a lower tier.
    Within the same tier, BM25 order is preserved.
    """
    normalized = query.strip()
    if not normalized:
        return []

    is_dhivehi = _contains_thaana(normalized)
    tiers = _build_content_tiers(normalized)

    # seen[file_entry_id] = (tier_index, snippet, bm25_rank)
    seen: dict[str, tuple[int, str, float]] = {}

    for tier_idx, fts_query in enumerate(tiers):
        statement = SEARCH_CONTENT_DHIVEHI_VOWEL_STATEMENT if is_dhivehi else SEARCH_CONTENT_STATEMENT
        params: dict = {"query": fts_query, "limit": limit}
        if is_dhivehi:
            params["exact_query"] = normalized

        try:
            rows = session.execute(statement, params).fetchall()
        except OperationalError:
            logger.warning("Invalid FTS5 query syntax, skipping tier %d", tier_idx)
            continue

        for row in rows:
            feid = str(row[0])
            if feid not in seen:
                seen[feid] = (tier_idx, row[1] or "", float(row[2]))

    sorted_entries = sorted(seen.items(), key=lambda kv: (kv[1][0], kv[1][2]))
    return [(feid, data[1], data[2]) for feid, data in sorted_entries[:limit]]


def search_file_references(
    session: Session,
    query: str,
    limit: int = 20,
) -> list[tuple[int, str, str, float]]:
    """Search visible filenames via FTS and return ranked file reference hits.

    Runs up to three FTS5 tiers (phrase → AND-prefix → OR-prefix) so that a
    query like "ocean salt" also surfaces files whose name contains only "salt".
    """
    normalized = query.strip()
    if not normalized:
        return []

    is_dhivehi = _contains_thaana(normalized)
    tiers = _build_filename_tiers(normalized)

    # seen[ref_id] = (tier_index, name, virtual_path, bm25_rank)
    seen: dict[int, tuple[int, str, str, float]] = {}

    for tier_idx, fts_query in enumerate(tiers):
        params = {
            "query": fts_query,
            "exact_query": normalized,
            "limit": limit,
            "use_dhivehi_exact_boost": int(is_dhivehi),
        }
        try:
            rows = session.execute(SEARCH_FILE_REFERENCES_STATEMENT, params).fetchall()
        except OperationalError:
            logger.warning("Invalid FTS5 query syntax, skipping tier %d", tier_idx)
            continue

        for row in rows:
            ref_id = int(row[0])
            if ref_id not in seen:
                seen[ref_id] = (tier_idx, row[1], row[2], float(row[5]))

    sorted_entries = sorted(seen.items(), key=lambda kv: (kv[1][0], kv[1][3]))
    return [(ref_id, data[1], data[2], data[3]) for ref_id, data in sorted_entries[:limit]]


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
