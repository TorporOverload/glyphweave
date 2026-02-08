import time

from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.utils.logging import logger


def insert_document_content(
    session: Session, file_entry_id: str, content: str, retries: int = 3
) -> bool:
    """Inserts file content to search index. 
        Args:
            session: SQLAlchemy session object.
            file_entry_id: ID of the file entry.
            content: Content of the file.
            retries: Number of retries if the database is locked defualt 3.
        Returns:
            True if the content was inserted successfully, False otherwise.
            
        Remember to commit after this
    """
    statement = text("""
        INSERT INTO search_index (file_entry_id, content)
        VALUES (:file_entry_id, :content)
    """)

    for attempt in range(retries):
        try:
            session.execute(
                statement, {"file_entry_id": file_entry_id, "content": content}
            )
            session.flush()
            return True 
        except OperationalError as e:
            if "database is locked" in str(e).lower():
                # Retry if the db is locked
                logger.warning(f"Database locked, {attempt/retries} retrying... ")
                time.sleep(1)
                continue
            raise e 

    return False 
