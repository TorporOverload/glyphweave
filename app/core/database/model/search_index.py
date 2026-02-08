"""FQLite fts virtual table and triggers"""

from sqlalchemy import DDL, Result, event, text
from sqlalchemy.orm import Session

from app.core.database.base import Base

create_search_index_table = DDL("""
CREATE VIRTUAL TABLE IF NOT EXISTS search_index USING fts5(
    file_entry_id UNINDEXED,
    content
);
""")

trigger_search_index_delete = DDL("""
CREATE TRIGGER IF NOT EXISTS trigger_delete_search_index AFTER DELETE ON file_entry
    BEGIN
        DELETE FROM search_index WHERE file_entry_id = old.id;
    END;
""")

trigger_file_entry_content_changed = DDL("""
CREATE TRIGGER IF NOT EXISTS trigger_file_entry_content_changed
    AFTER UPDATE OF content_hash ON file_entry
    FOR EACH ROW
        WHEN NEW.content_hash != OLD.content_hash
        BEGIN
            -- clear old FTS rows
            DELETE FROM search_index WHERE file_entry_id = OLD.id;

            -- mark for re‑extraction / re‑index
            UPDATE file_entry
            SET text_extraction_status = 'pending'
            WHERE id = NEW.id;
        END;
""")


def insert_document_content(
    session: Session, file_entry_id: str, content: str
) -> Result:
    """Insert document content into the search index"""
    statement = text("""
        INSERT INTO search_index (file_entry_id, content)
        VALUES (:file_entry_id, :content)
    """)
    status = session.execute(
        statement, {"file_entry_id": file_entry_id, "content": content}
    )
    session.commit()
    return status


def register_ddl_listeners():
    """Register all database views and triggers."""
    event.listen(Base.metadata, "after_create", create_search_index_table)
    event.listen(Base.metadata, "after_create", trigger_search_index_delete)
    event.listen(Base.metadata, "after_create", trigger_file_entry_content_changed)
