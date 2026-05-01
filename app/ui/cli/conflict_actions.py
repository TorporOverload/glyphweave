from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.common.device_id import resolve_device_alias, set_device_alias
from app.common.logging import logger


def manage_sync_conflicts(cli: Any) -> None:
    app_data_dir = _app_data_dir(cli)
    event_store = getattr(cli.service.context, "event_store", None)
    print("\n=== Sync Conflicts ===\n")
    try:
        conflicts = cli.service.list_sync_conflicts()
    except Exception as exc:
        print(f"Failed to load sync conflicts: {exc}")
        logger.exception("Failed to load sync conflicts")
        return

    if not conflicts:
        print("No active sync conflicts.")
        return

    for index, conflict in enumerate(conflicts, 1):
        print(f"  {index}. [{conflict.node_kind}] {conflict.archived_name}")
        print(f"     Path   : {conflict.archived_virtual_path}")
        print(f"     Reason : {conflict.reason_text}")
        print(f"     Event  : {conflict.trigger_event_type}")
        print(
            f"     Device : {_format_device_label(app_data_dir, event_store, conflict)}"
        )
        print(f"     Created: {_format_created_at(conflict.created_at)}")
        print(f"     Status : {conflict.status}")
        print(f"     ID     : {conflict.conflict_id}")

    choice = input("\nSelect conflict number (blank to go back): ").strip()
    if not choice:
        return
    if not choice.isdigit():
        print("Invalid selection.")
        return

    selected_index = int(choice) - 1
    if not (0 <= selected_index < len(conflicts)):
        print("Invalid selection.")
        return

    selected = conflicts[selected_index]
    print(f"\nSelected conflict: {selected.archived_name}")
    print(f"  Device : {_format_device_label(app_data_dir, event_store, selected)}")
    print(f"  Created: {_format_created_at(selected.created_at)}")
    print(f"  Event  : {selected.trigger_event_type}")
    print(f"  Status : {selected.status}")
    print("1. Restore from conflict archive")
    print("2. Delete archived item")
    print("3. Set global alias")
    print("4. Cancel")

    action = input("Select option (1-4): ").strip()
    if action == "1":
        _restore_sync_conflict(cli, selected.conflict_id)
        return
    if action == "2":
        _delete_conflict_item(cli, selected)
        return
    if action == "3":
        _set_device_alias(cli, selected)
        return
    print("Cancelled.")


def _restore_sync_conflict(cli: Any, conflict_id: str) -> None:
    destination = input("Destination folder path in vault (default: /): ").strip()
    new_name = input("New name (blank to keep archived name): ").strip()
    try:
        restored = cli.service.restore_sync_conflict(
            conflict_id,
            destination_folder_virtual_path=destination or "/",
            new_name=new_name or None,
        )
    except Exception as exc:
        print(f"\nRestore failed: {exc}")
        logger.exception("Restore sync conflict failed")
        return

    print(f"Restored to {restored.virtual_path}")


def _delete_conflict_item(cli: Any, conflict: Any) -> None:
    if not conflict.archived_virtual_path:
        print("Archived path is unavailable for this conflict.")
        return
    confirm = input("Type DELETE to confirm: ").strip()
    if confirm != "DELETE":
        print("Cancelled.")
        return

    try:
        deleted = cli.service.delete_entries([conflict.archived_virtual_path])
    except Exception as exc:
        print(f"\nDelete failed: {exc}")
        logger.exception("Delete conflict item failed")
        return

    print(f"Deleted {deleted} entr{'y' if deleted == 1 else 'ies'}.")


def _set_device_alias(cli: Any, conflict: Any) -> None:
    device_id = str(getattr(conflict, "origin_device_id", "") or "").strip()
    if not device_id:
        print("Device ID is unavailable for this conflict.")
        return

    current_alias = resolve_device_alias(_app_data_dir(cli), device_id) or ""
    prompt = f"Global alias for {device_id}"
    if current_alias:
        prompt += f" (current: {current_alias})"
    prompt += " (blank to clear): "
    alias_input = input(prompt).strip()

    try:
        alias = set_device_alias(_app_data_dir(cli), device_id, alias_input or None)
    except Exception as exc:
        print(f"\nFailed to update global device alias: {exc}")
        logger.exception("Set global device alias failed")
        return

    if alias:
        print(f"Saved global alias '{alias}' for {device_id}.")
        return
    print(f"Cleared global alias for {device_id}.")


def _format_device_label(app_data_dir, event_store, conflict: Any) -> str:
    device_id = str(getattr(conflict, "origin_device_id", "") or "").strip()
    alias = _resolve_device_label_alias(app_data_dir, event_store, device_id)
    alias = str(alias or "").strip()
    if alias and device_id:
        return f"{alias} ({device_id})"
    return device_id or "unknown"


def _app_data_dir(cli: Any):
    return cli.service.context.app_data_dir


def _resolve_device_label_alias(
    app_data_dir, event_store, device_id: str
) -> str | None:
    if event_store is not None:
        try:
            alias = str(
                event_store.read_frontier_record(device_id).get("alias") or ""
            ).strip()
        except Exception:
            alias = ""
        if alias:
            return alias
    return resolve_device_alias(app_data_dir, device_id)


def _format_created_at(value: Any) -> str:
    if not isinstance(value, datetime):
        return str(value) if value else "unknown"
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
