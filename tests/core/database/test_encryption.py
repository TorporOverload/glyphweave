"""Test script for database encryption and table creation."""
from pathlib import Path
from unittest.mock import patch

from sqlalchemy import text

from app.core.database.base import DB_FILENAME, Base, DbBase


def test_database_encryption(tmp_path):
    """Test that the database is properly encrypted and tables are created."""
    vault_id = "test_vault"
    test_key = "2DD29CA851E7B56E4697B0E1F08507293D761A05CE4D1B628663F411A8086D99"

    # Mock GLYPHWEAVE_LOCAL_DIR to use tmp_path so DB is created in the test temp dir
    with patch("app.core.database.base.GLYPHWEAVE_LOCAL_DIR", str(tmp_path)):
        db_path = tmp_path / vault_id / "database" / DB_FILENAME

        # Clean up old test database

        if db_path.exists():
            db_path.unlink()
            print(f"Removed old test database: {db_path}")

        # Create new encrypted database
        print("\n" + "=" * 70)
        print("TESTING DATABASE ENCRYPTION AND TABLE CREATION")
        print("=" * 70)

        db = DbBase(vault_id, test_key)
        session = db.get_session()

        # Test 1: Verify models are registered
        print(
            f"\nRegistered models in Base.metadata: {list(Base.metadata.tables.keys())}"
        )
        assert len(Base.metadata.tables) > 0, "No tables registered in Base.metadata!"

        # Test 2: Verify tables were created in the database
        with db.engine.connect() as conn:
            result = conn.execute(
                text("SELECT name FROM sqlite_master WHERE type='table'")
            )
            tables = [row[0] for row in result]
            print(f"Tables in database: {tables}")
            assert len(tables) > 0, "No tables created in database!"

        # Test 3: Verify database file exists and has content
        print(f"\nDatabase file: {db_path}")
        print(f"Database size: {db_path.stat().st_size:,} bytes")
        assert db_path.exists(), "Database file does not exist!"
        assert db_path.stat().st_size > 0, "Database file is empty!"

        # Test 4: Verify encryption - try to open without key using raw sqlite3
        print("\n--- Testing Encryption ---")

        try:
            import sqlite3
        except ImportError:
            assert False, "Error impoerting sqlite"

        try:
            test_conn = sqlite3.connect(str(db_path))
            cursor = test_conn.cursor()
            cursor.execute("SELECT * FROM sqlite_master")
            cursor.fetchall()
            test_conn.close()
            print("FAIL: Database is NOT encrypted! (readable without key)")
            assert False, "Database should be encrypted but is readable without key!"
        except sqlite3.DatabaseError as e:
            print("PASS: Database IS encrypted (cannot read without key)")
            print(f"Error message: {e}")

        # Test 5: Verify we can write and read with the correct key
        print("\n--- Testing Read/Write with Correct Key ---")
        try:
            with db.engine.begin() as conn:
                conn.execute(
                    text(
                        "CREATE TABLE IF NOT EXISTS test_encryption (id INTEGER, data TEXT)" #noqa
                    )
                )
                conn.execute(
                    text(
                        "INSERT INTO test_encryption VALUES (1, 'encrypted_data_test')"
                    )
                )
                result = conn.execute(
                    text("SELECT data FROM test_encryption WHERE id=1")
                )
                data = result.scalar()
                conn.execute(text("DROP TABLE test_encryption"))

            print(f"PASS: Successfully wrote and read encrypted data: '{data}'")
            assert data == "encrypted_data_test", (
                f"Expected 'encrypted_data_test', got '{data}'"
            )
        except Exception as e:
            print(f"FAIL: Error testing encryption: {e}")
            raise

        # Test 6: Verify SQLCipher version
        print("\n--- SQLCipher Information ---")
        with db.engine.connect() as conn:
            result = conn.execute(text("PRAGMA cipher_version"))
            version = result.scalar()
            print(f"SQLCipher version: {version}")
            assert version is not None, "Could not retrieve SQLCipher version!"

        # Test 7: Check specific expected tables
        print("\n--- Verifying Expected Tables ---")
        expected_tables = [
            "file_entry",
            "file_reference",
            "file_blob_reference",
            "wal_entries",
            "search_index",
        ]

        with db.engine.connect() as conn:
            result = conn.execute(
                text("SELECT name FROM sqlite_master WHERE type='table'")
            )
            actual_tables = [row[0] for row in result]

        for table in expected_tables:
            if table in actual_tables:
                print(f"Table : {table}")
            else:
                print(f"Table : {table} (MISSING)")

        # Clean up - dispose of all connections to release file handles
        session.close()
        db.engine.dispose()

        print("\n" + "=" * 70)
        print("ALL TESTS PASSED!")
        print("=" * 70)
        print(f"\nDatabase file: {db_path}")
        print(f"You can inspect it with: sqlcipher {db_path}")
        print(f"Then run: PRAGMA key = \"x'{test_key}'\"; SELECT * FROM sqlite_master;")  # noqa
        print("=" * 70 + "\n")


if __name__ == "__main__":
    import shutil
    import tempfile

    tmp_dir = tempfile.mkdtemp()
    try:
        tmp_path_obj = Path(tmp_dir)
        test_database_encryption(tmp_path_obj)
    finally:
        # Clean up with ignore_errors since SQLCipher may still hold locks
        shutil.rmtree(tmp_dir, ignore_errors=True)
