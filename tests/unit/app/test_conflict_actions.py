from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

from app.ui.cli import conflict_actions


def _conflict(conflict_id: str = "conflict-1") -> SimpleNamespace:
    return SimpleNamespace(
        conflict_id=conflict_id,
        node_id="node-1",
        node_kind="file",
        archived_name="report.txt.conflict",
        archived_virtual_path="/.glyphweave_conflicts/report.txt.conflict",
        reason_code="deleted_parent_move",
        reason_text="File move targeted a deleted parent",
        trigger_event_id="evt-1",
        trigger_event_hash="hash-1",
        trigger_event_type="file_move",
        origin_device_id="device-a",
        status="active",
        created_at=datetime(2026, 4, 3, 12, 30, tzinfo=timezone.utc),
    )


def test_manage_sync_conflicts_lists_and_restores(monkeypatch, capsys) -> None:
    restored = []
    event_store = SimpleNamespace(
        read_frontier_record=lambda device_id: {"alias": "Work Laptop" if device_id == "device-a" else ""}
    )
    cli = SimpleNamespace(
        service=SimpleNamespace(
            context=SimpleNamespace(app_data_dir="app-data", event_store=event_store),
            list_sync_conflicts=lambda: [_conflict()],
            restore_sync_conflict=lambda conflict_id,
            destination_folder_virtual_path,
            new_name: restored.append(
                (conflict_id, destination_folder_virtual_path, new_name)
            )
            or SimpleNamespace(virtual_path="/restored.txt"),
        )
    )
    answers = iter(["1", "1", "/", "restored.txt"])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))

    conflict_actions.manage_sync_conflicts(cli)

    output = capsys.readouterr().out
    assert restored == [("conflict-1", "/", "restored.txt")]
    assert "Device : Work Laptop (device-a)" in output
    assert "Created: 2026-04-03 12:30:00 UTC" in output
    assert "Event  : file_move" in output
    assert "Status : active" in output
    assert "Restored to /restored.txt" in output


def test_manage_sync_conflicts_lists_and_deletes(monkeypatch, capsys) -> None:
    deleted = []
    event_store = SimpleNamespace(read_frontier_record=lambda _device_id: {"alias": ""})
    cli = SimpleNamespace(
        service=SimpleNamespace(
            context=SimpleNamespace(app_data_dir="app-data", event_store=event_store),
            list_sync_conflicts=lambda: [_conflict()],
            delete_entries=lambda paths: deleted.append(paths) or 1,
        )
    )
    answers = iter(["1", "2", "DELETE"])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))

    conflict_actions.manage_sync_conflicts(cli)

    assert deleted == [["/.glyphweave_conflicts/report.txt.conflict"]]
    assert "Deleted 1 entry." in capsys.readouterr().out


def test_manage_sync_conflicts_sets_device_alias(monkeypatch, capsys) -> None:
    updated = []
    event_store = SimpleNamespace(read_frontier_record=lambda _device_id: {"alias": ""})
    monkeypatch.setattr(conflict_actions, "resolve_device_alias", lambda *_args: "Work Laptop")
    monkeypatch.setattr(
        conflict_actions,
        "set_device_alias",
        lambda _app_data_dir, device_id, alias: updated.append((device_id, alias))
        or alias,
    )
    cli = SimpleNamespace(
        service=SimpleNamespace(
            context=SimpleNamespace(app_data_dir="app-data", event_store=event_store),
            list_sync_conflicts=lambda: [_conflict()],
        )
    )
    answers = iter(["1", "3", "Travel Laptop"])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))

    conflict_actions.manage_sync_conflicts(cli)

    output = capsys.readouterr().out
    assert updated == [("device-a", "Travel Laptop")]
    assert "Saved global alias 'Travel Laptop' for device-a." in output


def test_manage_sync_conflicts_handles_empty_state(capsys) -> None:
    cli = SimpleNamespace(
        service=SimpleNamespace(
            context=SimpleNamespace(
                app_data_dir="app-data",
                event_store=SimpleNamespace(read_frontier_record=lambda _device_id: {"alias": ""}),
            ),
            list_sync_conflicts=lambda: [],
        )
    )

    conflict_actions.manage_sync_conflicts(cli)

    assert "No active sync conflicts." in capsys.readouterr().out
