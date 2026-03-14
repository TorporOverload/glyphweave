from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy.orm import Session, sessionmaker


@contextmanager
def session_scope(
    session_factory: sessionmaker,
    *,
    commit: bool = True,
) -> Iterator[Session]:
    """Provide a transactional scope around a series of operations."""
    session: Session = session_factory()
    session.expire_on_commit = False
    try:
        yield session
        if commit:
            session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
