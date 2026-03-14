import time

from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.utils.logging import logger

INSERT_SEARCH_INDEX_STATEMENT = text("""
    INSERT INTO search_index (file_entry_id, content)
    VALUES (:file_entry_id, :content)
""")


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
