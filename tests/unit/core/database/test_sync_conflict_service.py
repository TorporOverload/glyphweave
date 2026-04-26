from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.infrastructure.persistence.db.base import Base
from app.infrastructure.persistence.db.model.sync_conflict import SyncConflict
from app.services.vault_files import queries as vault_queries
from app.infrastructure.persistence.db.service.sync_conflict_service import (
    get_active_sync_conflict_for_node,
    get_sync_conflict_by_id,
    list_active_sync_conflicts,
    list_active_sync_conflicts_for_node_ids,
    resolve_active_sync_conflicts_for_node_ids,
    resolve_sync_conflict,
    upsert_sync_conflict,
)


def test_sync_conflict_service_upsert_query_and_resolve(tmp_path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'sync_conflict.db'}")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    with session_factory.begin() as session:
        created = upsert_sync_conflict(
            session,
            conflict_id="conflict-1",
            node_id="node-1",
            node_kind="file",
            archived_name="report.txt.conflict",
            archived_virtual_path="/.glyphweave_conflicts/report.txt.conflict",
            archived_file_ref_id=None,
            file_entry_id=None,
            reason_code="deleted_parent_move",
            reason_text="File move targeted a deleted parent",
            trigger_event_id="evt-1",
            trigger_event_hash="hash-1",
            trigger_event_type="file_move",
            origin_device_id="device-a",
            status="active",
        )
        assert created.conflict_id == "conflict-1"

    with session_factory.begin() as session:
        fetched = get_sync_conflict_by_id(session, "conflict-1")
        assert fetched is not None
        assert fetched.reason_code == "deleted_parent_move"
        assert get_active_sync_conflict_for_node(session, "node-1") is not None
        assert len(list_active_sync_conflicts(session)) == 1

    service = type(
        "_Service",
        (),
        {"context": type("_Context", (), {"session_factory": session_factory})()},
    )()
    info = vault_queries.get_sync_conflict(service, "conflict-1")
    assert info is not None
    assert info.conflict_id == "conflict-1"
    assert info.reason_code == "deleted_parent_move"

    with session_factory.begin() as session:
        resolved = resolve_sync_conflict(
            session,
            conflict_id="conflict-1",
            resolution_event_id="evt-2",
            status="deleted",
        )
        assert resolved is not None
        assert resolved.status == "deleted"

    with session_factory.begin() as session:
        assert get_active_sync_conflict_for_node(session, "node-1") is None
        fetched = get_sync_conflict_by_id(session, "conflict-1")
        assert fetched is not None
        assert fetched.status == "deleted"


def test_sync_conflict_service_bulk_lists_and_resolves_by_node_ids(tmp_path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'sync_conflict_bulk.db'}")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    with session_factory.begin() as session:
        upsert_sync_conflict(
            session,
            conflict_id="conflict-1",
            node_id="node-1",
            node_kind="file",
            archived_name="a.conflict",
            archived_virtual_path="/.glyphweave_conflicts/a.conflict",
            archived_file_ref_id=None,
            file_entry_id=None,
            reason_code="deleted_parent_move",
            reason_text="File move targeted a deleted parent",
            trigger_event_id="evt-1",
            trigger_event_hash="hash-1",
            trigger_event_type="file_move",
            origin_device_id="device-a",
        )
        upsert_sync_conflict(
            session,
            conflict_id="conflict-2",
            node_id="node-2",
            node_kind="folder",
            archived_name="b.conflict",
            archived_virtual_path="/.glyphweave_conflicts/b.conflict",
            archived_file_ref_id=None,
            file_entry_id=None,
            reason_code="deleted_parent_folder_move",
            reason_text="Folder move targeted a deleted parent",
            trigger_event_id="evt-2",
            trigger_event_hash="hash-2",
            trigger_event_type="folder_move",
            origin_device_id="device-a",
        )

    with session_factory.begin() as session:
        listed = list_active_sync_conflicts_for_node_ids(
            session,
            ["node-1", "node-2", "missing"],
        )
        assert {conflict.conflict_id for conflict in listed} == {
            "conflict-1",
            "conflict-2",
        }

        resolved = resolve_active_sync_conflicts_for_node_ids(
            session,
            node_ids=["node-1", "node-2"],
            resolution_event_id="evt-resolve",
            status="resolved",
        )
        assert {conflict.conflict_id for conflict in resolved} == {
            "conflict-1",
            "conflict-2",
        }

    with session_factory.begin() as session:
        assert list_active_sync_conflicts_for_node_ids(session, ["node-1", "node-2"]) == []
        statuses = {
            conflict.conflict_id: conflict.status
            for conflict in session.query(SyncConflict).all()
        }
        assert statuses == {"conflict-1": "resolved", "conflict-2": "resolved"}
