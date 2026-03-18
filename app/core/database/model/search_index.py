"""FQLite fts virtual table and triggers"""

from sqlalchemy import DDL, event

from app.core.database.base import Base

create_search_index_table = DDL("""
CREATE VIRTUAL TABLE IF NOT EXISTS search_index USING fts5(
    file_entry_id UNINDEXED,
    content
);
""")

create_search_filename_index_table = DDL("""
CREATE VIRTUAL TABLE IF NOT EXISTS search_filename_index USING fts5(
    file_ref_id UNINDEXED,
    file_name
);
""")

trigger_search_index_delete = DDL("""
CREATE TRIGGER IF NOT EXISTS trigger_delete_search_index AFTER DELETE ON file_entry
    BEGIN
        DELETE FROM search_index WHERE file_entry_id = old.id;
    END;
""")

trigger_search_filename_index_insert = DDL("""
CREATE TRIGGER IF NOT EXISTS trigger_insert_search_filename_index
    AFTER INSERT ON file_reference
    FOR EACH ROW
        WHEN NEW.is_folder = 0
        BEGIN
            INSERT INTO search_filename_index (file_ref_id, file_name)
            VALUES (NEW.id, NEW.name);
        END;
""")

trigger_search_filename_index_delete = DDL("""
CREATE TRIGGER IF NOT EXISTS trigger_delete_search_filename_index
    AFTER DELETE ON file_reference
    FOR EACH ROW
        BEGIN
            DELETE FROM search_filename_index WHERE file_ref_id = OLD.id;
        END;
""")

trigger_search_filename_index_update = DDL("""
CREATE TRIGGER IF NOT EXISTS trigger_update_search_filename_index
    AFTER UPDATE OF name, is_folder ON file_reference
    FOR EACH ROW
        BEGIN
            DELETE FROM search_filename_index WHERE file_ref_id = OLD.id;
            INSERT INTO search_filename_index (file_ref_id, file_name)
            SELECT NEW.id, NEW.name
            WHERE NEW.is_folder = 0;
        END;
""")

sync_search_filename_index = DDL("""
INSERT INTO search_filename_index (file_ref_id, file_name)
SELECT fr.id, fr.name
FROM file_reference AS fr
WHERE fr.is_folder = 0
  AND NOT EXISTS (
      SELECT 1
      FROM search_filename_index AS sfi
      WHERE sfi.file_ref_id = fr.id
  );
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


def register_ddl_listeners():
    """Register all database views and triggers."""
    event.listen(Base.metadata, "after_create", create_search_index_table)
    event.listen(Base.metadata, "after_create", create_search_filename_index_table)
    event.listen(Base.metadata, "after_create", trigger_search_index_delete)
    event.listen(Base.metadata, "after_create", trigger_search_filename_index_insert)
    event.listen(Base.metadata, "after_create", trigger_search_filename_index_delete)
    event.listen(Base.metadata, "after_create", trigger_search_filename_index_update)
    event.listen(Base.metadata, "after_create", trigger_file_entry_content_changed)
    event.listen(Base.metadata, "after_create", sync_search_filename_index)
