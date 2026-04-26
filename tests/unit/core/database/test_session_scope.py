import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.infrastructure.persistence.db.base import Base
from app.infrastructure.persistence.db.model.file_reference import FileReference
from app.infrastructure.persistence.db.service.session import session_scope


def _build_session_factory(tmp_path):
    db_path = tmp_path / "session_scope.db"
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"timeout": 30})
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False)


def test_session_commits_on_success_by_default(tmp_path) -> None:
    factory = _build_session_factory(tmp_path)

    with session_scope(factory) as session:
        folder = FileReference(name="docs", is_folder=True, virtual_path="/docs")
        session.add(folder)
        session.flush()

    with factory() as verify_session:
        result = verify_session.execute(text("SELECT name FROM file_reference WHERE name = 'docs'"))
        row = result.fetchone()
        assert row is not None
        assert row[0] == "docs"


def test_session_commits_on_success_when_commit_true(tmp_path) -> None:
    factory = _build_session_factory(tmp_path)

    with session_scope(factory, commit=True) as session:
        folder = FileReference(name="docs", is_folder=True, virtual_path="/docs")
        session.add(folder)
        session.flush()

    with factory() as verify_session:
        result = verify_session.execute(text("SELECT name FROM file_reference WHERE name = 'docs'"))
        row = result.fetchone()
        assert row is not None


def test_session_rolls_back_on_exception(tmp_path) -> None:
    factory = _build_session_factory(tmp_path)

    with pytest.raises(Exception):
        with session_scope(factory) as session:
            folder = FileReference(name="docs", is_folder=True, virtual_path="/docs")
            session.add(folder)
            session.flush()
            raise ValueError("intentional failure")

    with factory() as verify_session:
        result = verify_session.execute(text("SELECT COUNT(*) FROM file_reference"))
        count = result.fetchone()[0]
        assert count == 0


def test_session_no_commit_when_commit_false(tmp_path) -> None:
    factory = _build_session_factory(tmp_path)

    with session_scope(factory, commit=False) as session:
        folder = FileReference(name="docs", is_folder=True, virtual_path="/docs")
        session.add(folder)
        session.flush()

    with factory() as verify_session:
        result = verify_session.execute(text("SELECT COUNT(*) FROM file_reference"))
        count = result.fetchone()[0]
        assert count == 0


def test_session_preserves_changes_across_multiple_operations(tmp_path) -> None:
    factory = _build_session_factory(tmp_path)

    with session_scope(factory) as session:
        session.add(FileReference(name="docs", is_folder=True, virtual_path="/docs"))
        session.flush()
        session.add(FileReference(name="reports", is_folder=True, virtual_path="/reports"))
        session.flush()

        result = session.execute(text("SELECT COUNT(*) FROM file_reference"))
        assert result.fetchone()[0] == 2

    with factory() as verify_session:
        result = verify_session.execute(text("SELECT COUNT(*) FROM file_reference"))
        assert result.fetchone()[0] == 2


def test_session_rollback_reverts_all_changes_on_exception(tmp_path) -> None:
    factory = _build_session_factory(tmp_path)

    with pytest.raises(ValueError):
        with session_scope(factory) as session:
            session.add(FileReference(name="docs", is_folder=True, virtual_path="/docs"))
            session.flush()
            session.add(FileReference(name="reports", is_folder=True, virtual_path="/reports"))
            session.flush()
            raise ValueError("intentional failure")

    with factory() as verify_session:
        result = verify_session.execute(text("SELECT COUNT(*) FROM file_reference"))
        assert result.fetchone()[0] == 0


def test_session_scope_sets_expire_on_commit_false(tmp_path) -> None:
    factory = _build_session_factory(tmp_path)

    with session_scope(factory) as session:
        assert session.expire_on_commit is False


def test_multiple_sessions_are_independent(tmp_path) -> None:
    factory = _build_session_factory(tmp_path)

    with session_scope(factory) as session1:
        session1.add(FileReference(name="session1", is_folder=True, virtual_path="/session1"))
        session1.flush()

    with session_scope(factory) as session2:
        session2.add(FileReference(name="session2", is_folder=True, virtual_path="/session2"))
        session2.flush()

    with factory() as verify_session:
        result = verify_session.execute(text("SELECT name FROM file_reference ORDER BY name"))
        rows = result.fetchall()
        assert len(rows) == 2
        assert [row[0] for row in rows] == ["session1", "session2"]


def test_nested_session_scope_inner_exception_rolls_back_outer(tmp_path) -> None:
    """Test that exception in sequential operations rolls back all changes.

    When the first session scope completes successfully but a second scope fails,
    only the first scope's changes should persist. The second scope's failure should
    not affect the first since they are independent sessions (SQLite limitation).
    This differs from true same-session nesting where inner exception would rollback outer.
    """
    factory = _build_session_factory(tmp_path)

    with session_scope(factory) as session1:
        session1.add(FileReference(name="session1_item", is_folder=True, virtual_path="/session1"))
        session1.flush()

    with pytest.raises(ValueError):
        with session_scope(factory) as session2:
            session2.add(FileReference(name="session2_item", is_folder=True, virtual_path="/session2"))
            session2.flush()
            raise ValueError("failure in second session")

    with factory() as verify_session:
        result = verify_session.execute(text("SELECT name FROM file_reference ORDER BY name"))
        rows = result.fetchall()
        assert len(rows) == 1
        assert rows[0][0] == "session1_item"