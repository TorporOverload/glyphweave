from __future__ import annotations

from types import SimpleNamespace

from app.ui.cli import manage_actions
from app.ui.cli.renderers import render_vault_menu_lines


def test_render_vault_menu_lines_includes_device_alias_entry() -> None:
    lines = render_vault_menu_lines("Vault")

    assert "10. Manage device aliases" in lines
    assert "11. Check vault integrity" in lines
    assert "12. Repair local state from events" in lines
    assert "13. Exit" in lines


def test_manage_device_aliases_updates_local_device_alias(monkeypatch, capsys) -> None:
    updated_frontier = []
    monkeypatch.setattr(
        manage_actions,
        "load_device_profile",
        lambda _app_data_dir: {
            "device_id": "device-local",
            "alias": "Old Name",
            "status": "active",
            "global_aliases": {"device-a": "Work Laptop"},
        },
    )
    monkeypatch.setattr(
        manage_actions,
        "resolve_device_alias",
        lambda _app_data_dir, device_id: "Old Name"
        if device_id == "device-local"
        else "Work Laptop"
        if device_id == "device-a"
        else None,
    )
    event_store = SimpleNamespace(
        read_frontier_record=lambda device_id: {
            "alias": "Vault Alias" if device_id == "device-local" else "",
            "frontier": ["hash-1"],
        },
        write_frontier_alias=lambda device_id, alias: updated_frontier.append((device_id, alias)),
    )
    cli = SimpleNamespace(
        service=SimpleNamespace(
            context=SimpleNamespace(app_data_dir="app-data", event_store=event_store),
        )
    )
    answers = iter(["1", "Travel Laptop"])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))

    manage_actions.manage_device_aliases(cli)

    output = capsys.readouterr().out
    assert updated_frontier == [("device-local", "Travel Laptop")]
    assert "Current device ID   : device-local" in output
    assert "Synced vault alias  : Vault Alias" in output
    assert "Global device alias : Old Name" in output
    assert "Saved synced alias 'Travel Laptop' for this vault." in output


def test_manage_device_aliases_updates_remote_device_alias(monkeypatch, capsys) -> None:
    updated = []
    monkeypatch.setattr(
        manage_actions,
        "load_device_profile",
        lambda _app_data_dir: {
            "device_id": "device-local",
            "alias": "",
            "status": "active",
            "global_aliases": {"device-a": "Work Laptop"},
        },
    )
    monkeypatch.setattr(manage_actions, "resolve_device_alias", lambda *_args: None)
    monkeypatch.setattr(
        manage_actions,
        "set_device_alias",
        lambda _app_data_dir, device_id, alias: updated.append((device_id, alias))
        or alias,
    )
    monkeypatch.setattr(
        manage_actions,
        "_list_other_vault_devices",
        lambda _app_data_dir, _event_store, *, exclude_device_id: [
            {"device_id": "device-a", "label": "Work Laptop (device-a)"},
            {"device_id": "device-b", "label": "Tablet (device-b)"},
        ],
    )
    cli = SimpleNamespace(
        service=SimpleNamespace(
            context=SimpleNamespace(
                app_data_dir="app-data",
                event_store=SimpleNamespace(
                    read_frontier_record=lambda _device_id: {"alias": "", "frontier": []},
                    write_frontier_alias=lambda *_args, **_kwargs: None,
                ),
            ),
        )
    )
    answers = iter(["3", "2", "Travel Tablet"])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))

    manage_actions.manage_device_aliases(cli)

    output = capsys.readouterr().out
    assert updated == [("device-b", "Travel Tablet")]
    assert "Devices on this vault:" in output
    assert "1. Work Laptop (device-a)" in output
    assert "2. Tablet (device-b)" in output
    assert "Saved global alias 'Travel Tablet' for device-b." in output


def test_repair_local_state_rebuilds_when_integrity_issue_is_db_only(
    monkeypatch, capsys
) -> None:
    initial_report = SimpleNamespace(
        ok=False,
        total_events=4,
        replayed_events=4,
        blocked_events=0,
        issues=[SimpleNamespace(code="db_mismatch", message="db differs")],
    )
    repaired_report = SimpleNamespace(
        ok=True,
        total_events=4,
        replayed_events=4,
        blocked_events=0,
        issues=[],
    )
    calls = []
    cli = SimpleNamespace(
        service=SimpleNamespace(
            check_integrity=lambda: initial_report,
            repair_local_state=lambda report: calls.append(report) or repaired_report,
        )
    )
    monkeypatch.setattr("builtins.input", lambda _prompt="": "REBUILD LOCAL")

    manage_actions.repair_local_state(cli)

    output = capsys.readouterr().out
    assert calls == [initial_report]
    assert "Local runtime state rebuilt from vault events." in output
    assert "Integrity check passed after repair." in output


def test_repair_local_state_refuses_unsafe_integrity_failures(
    monkeypatch, capsys
) -> None:
    del monkeypatch
    report = SimpleNamespace(
        ok=False,
        total_events=4,
        replayed_events=3,
        blocked_events=1,
        issues=[
            SimpleNamespace(code="missing_blob", message="blob missing"),
            SimpleNamespace(code="blocked_event", message="blocked"),
        ],
    )
    repair_calls = []
    cli = SimpleNamespace(
        service=SimpleNamespace(
            check_integrity=lambda: report,
            repair_local_state=lambda report: repair_calls.append(report),
        )
    )

    manage_actions.repair_local_state(cli)

    output = capsys.readouterr().out
    assert repair_calls == []
    assert "Automatic repair was not started." in output
    assert "missing_blob" in output
