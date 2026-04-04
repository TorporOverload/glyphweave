from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.common.logging import logger


def manage_sync_conflicts(cli: Any) -> None:
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
        print(f"     Device : {conflict.origin_device_id or 'unknown'}")
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
    print(f"  Device : {selected.origin_device_id or 'unknown'}")
    print(f"  Created: {_format_created_at(selected.created_at)}")
    print(f"  Event  : {selected.trigger_event_type}")
    print(f"  Status : {selected.status}")
    print("1. Restore from conflict archive")
    print("2. Delete archived item")
    print("3. Cancel")

    action = input("Select option (1-3): ").strip()
    if action == "1":
        _restore_sync_conflict(cli, selected.conflict_id)
        return
    if action == "2":
        _delete_conflict_item(cli, selected)
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


def _format_created_at(value: Any) -> str:
    if not isinstance(value, datetime):
        return str(value) if value else "unknown"
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
