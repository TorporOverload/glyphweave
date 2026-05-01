from __future__ import annotations

from pathlib import Path
from typing import Any

from app.common.device_id import (
    default_frontier_alias,
    load_device_profile,
    resolve_device_alias,
    sanitize_device_id,
    set_device_alias,
)
from app.common.logging import logger

from .conflict_actions import manage_sync_conflicts
from .renderers import parse_path_list, render_vault_menu_lines


def manage_entries(cli: Any) -> None:
    print("\n=== Manage Vault Entries ===\n")
    print_entry_paths(cli)
    print("\n1. Copy file/folder")
    print("2. Move file/folder(s)")
    print("3. Delete file/folder(s)")
    print("4. Rename file/folder")
    print("5. Export file/folder(s)")
    print("6. Manage sync conflicts")

    action = input("\nSelect option (blank to go back): ").strip()
    if not action:
        return
    if action == "1":
        copy_entry(cli)
        return
    if action == "2":
        move_entries(cli)
        return
    if action == "3":
        delete_entries(cli)
        return
    if action == "4":
        rename_entry(cli)
        return
    if action == "5":
        export_entries(cli)
        return
    if action == "6":
        manage_sync_conflicts(cli)
        return
    print("Invalid selection.")


def copy_entry(cli: Any) -> None:
    source_path = input("Source vault path: ").strip().strip('"')
    if not source_path:
        print("No source selected.")
        return

    destination = input("Destination folder path in vault (default: /): ").strip()
    new_name = input("New name in destination (blank to keep current): ").strip()
    try:
        copied = cli.service.copy_entry(
            source_path, destination or "/", new_name or None
        )
    except Exception as exc:
        print(f"\nCopy failed: {exc}")
        logger.exception("Copy failed")
        return

    print(f"Copied to {copied.virtual_path}")


def move_entries(cli: Any) -> None:
    source_input = input("Source vault paths (comma-separated for multiple): ").strip()
    source_paths = parse_path_list(source_input)
    if not source_paths:
        print("No source selected.")
        return

    destination = input("Destination folder path in vault (default: /): ").strip()
    try:
        moved = cli.service.move_entries(source_paths, destination or "/")
    except Exception as exc:
        print(f"\nMove failed: {exc}")
        logger.exception("Move failed")
        return

    print(f"Moved {len(moved)} entr{'y' if len(moved) == 1 else 'ies'}.")
    for entry in moved:
        print(f"  {entry.virtual_path}")


def delete_entries(cli: Any) -> None:
    source_input = input(
        "Vault paths to delete (comma-separated for multiple): "
    ).strip()
    source_paths = parse_path_list(source_input)
    if not source_paths:
        print("No source selected.")
        return

    confirm = input("Type DELETE to confirm: ").strip()
    if confirm != "DELETE":
        print("Cancelled.")
        return

    try:
        deleted = cli.service.delete_entries(source_paths)
    except Exception as exc:
        print(f"\nDelete failed: {exc}")
        logger.exception("Delete failed")
        return

    print(f"Deleted {deleted} entr{'y' if deleted == 1 else 'ies'}.")


def rename_entry(cli: Any) -> None:
    source_path = input("Vault path to rename: ").strip().strip('"')
    if not source_path:
        print("No source selected.")
        return

    new_name = input("New name: ").strip()
    if not new_name:
        print("New name cannot be empty.")
        return

    try:
        renamed = cli.service.rename_entry(source_path, new_name)
    except Exception as exc:
        print(f"\nRename failed: {exc}")
        logger.exception("Rename failed")
        return

    print(f"Renamed to {renamed.virtual_path}")


def export_entries(cli: Any) -> None:
    source_input = input(
        "Vault paths to export (comma-separated for multiple): "
    ).strip()
    source_paths = parse_path_list(source_input)
    if not source_paths:
        print("No source selected.")
        return

    destination = input("Destination directory on this system: ").strip().strip('"')
    if not destination:
        print("Destination directory is required.")
        return

    try:
        exported = cli.service.export_entries(source_paths, Path(destination))
    except Exception as exc:
        print(f"\nExport failed: {exc}")
        logger.exception("Export failed")
        return

    print(f"Exported {len(exported)} entr{'y' if len(exported) == 1 else 'ies'}.")
    for path in exported:
        print(f"  {path}")


def print_entry_paths(cli: Any) -> None:
    try:
        entries = cli.service.list_all_entries()
    except Exception as exc:
        print(f"Failed to load entries: {exc}")
        return

    if not entries:
        print("  (no files in vault)")
        return

    for entry in entries:
        prefix = "[DIR] " if entry.is_folder else ""
        print(f"  {prefix}{entry.virtual_path}")


def check_vault_integrity(cli: Any) -> None:
    print("\n=== Vault Integrity Check ===\n")
    print("Replaying event history and verifying blobs. This may take a while.")
    try:
        report = cli.service.check_integrity()
    except Exception as exc:
        print(f"\nIntegrity check failed: {exc}")
        logger.exception("Integrity check failed")
        return

    print(
        "Events discovered: "
        f"{report.total_events} | replayed: {report.replayed_events} | "
        f"blocked: {report.blocked_events}"
    )
    if report.ok:
        print("Integrity check passed.")
        return

    print(f"Integrity check found {len(report.issues)} issue(s):")
    for issue in report.issues[:20]:
        print(f"  - [{issue.code}] {issue.message}")
    if len(report.issues) > 20:
        print(f"  ... {len(report.issues) - 20} more issue(s) omitted")


def repair_local_state(cli: Any) -> None:
    print("\n=== Repair Local State ===\n")
    print("This rebuilds the local DB/cache from vault events and blobs.")
    print("It does not modify the vault itself.")

    try:
        report = cli.service.check_integrity()
    except Exception as exc:
        print(f"\nIntegrity check failed: {exc}")
        logger.exception("Integrity check before repair failed")
        return

    if report.ok:
        print("Integrity check already passes. No repair is needed.")
        return

    unsafe_codes = sorted(
        {
            issue.code
            for issue in report.issues
            if issue.code
            in {
                "blocked_event",
                "blob_hash_mismatch",
                "corrupt_blob",
                "corrupt_event",
                "missing_blob",
            }
        }
    )
    if unsafe_codes:
        print("Automatic repair was not started.")
        print(
            "The vault has event/blob problems that require restoring data first: "
            + ", ".join(unsafe_codes)
        )
        return

    confirm = input("Type REBUILD LOCAL to continue: ").strip()
    if confirm != "REBUILD LOCAL":
        print("Cancelled.")
        return

    try:
        repaired = cli.service.repair_local_state(report)
    except Exception as exc:
        print(f"\nLocal repair failed: {exc}")
        logger.exception("Local repair failed")
        return

    print("Local runtime state rebuilt from vault events.")
    print(
        "Post-repair integrity: "
        f"events={repaired.total_events}, replayed={repaired.replayed_events}, "
        f"blocked={repaired.blocked_events}"
    )
    if repaired.ok:
        print("Integrity check passed after repair.")
        return

    print(f"Integrity check still reports {len(repaired.issues)} issue(s):")
    for issue in repaired.issues[:20]:
        print(f"  - [{issue.code}] {issue.message}")
    if len(repaired.issues) > 20:
        print(f"  ... {len(repaired.issues) - 20} more issue(s) omitted")


def manage_device_aliases(cli: Any) -> None:
    app_data_dir = cli.service.context.app_data_dir
    event_store = cli.service.context.event_store
    if event_store is None:
        print("Event store is not initialized.")
        return

    profile = load_device_profile(app_data_dir)
    local_device_id = str(profile["device_id"])
    global_local_alias = resolve_device_alias(app_data_dir, local_device_id)
    synced_local_alias = str(
        event_store.read_frontier_record(local_device_id).get("alias") or ""
    ).strip()
    aliases = dict(profile.get("global_aliases") or {})

    print("\n=== Device Aliases ===\n")
    print(f"Current device ID   : {local_device_id}")
    print(f"Synced vault alias  : {synced_local_alias or '(not set)'}")
    print(f"Global device alias : {global_local_alias or '(not set)'}")

    if aliases:
        print("\nSaved global aliases for other devices:")
        for index, device_id in enumerate(sorted(aliases), 1):
            print(f"  {index}. {aliases[device_id]}  ({device_id})")
    else:
        print("\nSaved global aliases for other devices: none")

    print("\n1. Set synced alias for this vault")
    print("2. Set global alias for this device")
    print("3. Set global alias for another device ID")
    print("4. Clear global alias for another device ID")
    print("5. Back")

    action = input("\nSelect option (1-5): ").strip()
    if action == "1":
        alias_input = input("Synced alias for this vault (blank to clear): ").strip()
        _update_synced_device_alias(
            cli,
            local_device_id,
            alias_input or None,
        )
        return
    if action == "2":
        alias_input = input("Global alias for this device (blank to clear): ").strip()
        _update_global_device_alias(
            cli,
            local_device_id,
            alias_input or None,
            is_local=True,
            current_synced_alias=synced_local_alias,
            current_global_alias=global_local_alias or "",
        )
        return
    if action == "3":
        _prompt_set_remote_device_alias(cli)
        return
    if action == "4":
        _prompt_clear_remote_device_alias(cli, aliases)
        return
    if action in {"", "5"}:
        return
    print("Invalid selection.")


def _prompt_set_remote_device_alias(cli: Any) -> None:
    event_store = cli.service.context.event_store
    if event_store is None:
        print("Event store is not initialized.")
        return

    app_data_dir = cli.service.context.app_data_dir
    local_device_id = str(load_device_profile(app_data_dir)["device_id"])
    known_devices = _list_other_vault_devices(
        app_data_dir,
        event_store,
        exclude_device_id=local_device_id,
    )

    if known_devices:
        print("\nDevices on this vault:")
        for index, device in enumerate(known_devices, 1):
            label = device["label"]
            print(f"  {index}. {label}")
        print("  Or type a device ID directly.")
    else:
        print("No other devices are known on this vault yet.")

    choice = input("Device number or ID: ").strip()
    if choice.isdigit():
        selected_index = int(choice) - 1
        if not (0 <= selected_index < len(known_devices)):
            print("Invalid selection.")
            return
        normalized_device_id = str(known_devices[selected_index]["device_id"])
    else:
        normalized_device_id = sanitize_device_id(choice)
    if normalized_device_id == "unknown-device":
        print("Device ID is required.")
        return

    alias_input = input("Alias (blank to clear): ").strip()
    _update_global_device_alias(
        cli,
        normalized_device_id,
        alias_input or None,
        is_local=False,
    )


def _prompt_clear_remote_device_alias(cli: Any, aliases: dict[str, str]) -> None:
    if not aliases:
        print("No global aliases to clear.")
        return

    device_id = input("Device ID to clear: ").strip()
    normalized_device_id = sanitize_device_id(device_id)
    if normalized_device_id == "unknown-device":
        print("Device ID is required.")
        return
    if normalized_device_id not in aliases:
        print("No alias found for that device ID.")
        return

    _update_global_device_alias(cli, normalized_device_id, None, is_local=False)


def _update_synced_device_alias(
    cli: Any,
    device_id: str,
    alias: str | None,
) -> None:
    event_store = cli.service.context.event_store
    if event_store is None:
        print("Event store is not initialized.")
        return

    try:
        event_store.write_frontier_alias(device_id, alias or "")
    except Exception as exc:
        print(f"\nFailed to update synced device alias: {exc}")
        logger.exception("Update synced device alias failed")
        return

    if alias:
        print(f"Saved synced alias '{alias}' for this vault.")
        return
    print("Cleared synced alias for this vault.")


def _update_global_device_alias(
    cli: Any,
    device_id: str,
    alias: str | None,
    *,
    is_local: bool,
    current_synced_alias: str = "",
    current_global_alias: str = "",
) -> None:
    try:
        saved = set_device_alias(cli.service.context.app_data_dir, device_id, alias)
    except Exception as exc:
        print(f"\nFailed to update global device alias: {exc}")
        logger.exception("Update global device alias failed")
        return

    if is_local:
        _maybe_sync_local_frontier_alias_from_global(
            cli,
            device_id,
            new_global_alias=saved or "",
            previous_global_alias=current_global_alias,
            current_synced_alias=current_synced_alias,
        )

    subject = "this device" if is_local else device_id
    if saved:
        print(f"Saved global alias '{saved}' for {subject}.")
        return
    print(f"Cleared global alias for {subject}.")


def _maybe_sync_local_frontier_alias_from_global(
    cli: Any,
    device_id: str,
    *,
    new_global_alias: str,
    previous_global_alias: str,
    current_synced_alias: str,
) -> None:
    event_store = cli.service.context.event_store
    if event_store is None:
        return

    if current_synced_alias not in {"", previous_global_alias}:
        return

    event_store.write_frontier_alias(
        device_id,
        new_global_alias
        or default_frontier_alias(cli.service.context.app_data_dir, device_id),
    )


def _list_other_vault_devices(
    app_data_dir,
    event_store,
    *,
    exclude_device_id: str,
) -> list[dict[str, str]]:
    devices: list[dict[str, str]] = []
    seen: set[str] = set()
    for path in sorted(event_store.roots_dir.glob("*.json")):
        device_id = sanitize_device_id(path.stem)
        if device_id == "unknown-device" or device_id == exclude_device_id:
            continue
        if device_id in seen:
            continue
        seen.add(device_id)
        try:
            record = event_store.read_frontier_record(device_id)
        except Exception:
            record = {"alias": ""}
        synced_alias = str(record.get("alias") or "").strip()
        global_alias = resolve_device_alias(app_data_dir, device_id) or ""
        label = synced_alias or global_alias or device_id
        if label != device_id:
            label = f"{label} ({device_id})"
        devices.append(
            {
                "device_id": device_id,
                "label": label,
            }
        )
    return devices


def vault_menu(cli: Any) -> None:
    while True:
        print("\n" + "=" * 40)
        cli._print_lines(render_vault_menu_lines(cli.service.vault_name))

        choice = input("\nSelect option (1-13): ").strip()

        if choice == "1":
            cli.list_files()
        elif choice == "2":
            cli.open_file()
        elif choice == "3":
            cli.list_unlocked_files()
        elif choice == "4":
            cli.add_file()
        elif choice == "5":
            cli.search_files()
        elif choice == "6":
            cli.manage_entries()
        elif choice == "7":
            cli.show_recovery_phrase()
        elif choice == "8":
            cli.show_db_key()
        elif choice == "9":
            cli.manage_sync_conflicts()
        elif choice == "10":
            cli.manage_device_aliases()
        elif choice == "11":
            cli.check_vault_integrity()
        elif choice == "12":
            cli.repair_local_state()
        elif choice == "13":
            print("\nClosing vault...")
            break
        else:
            print("Invalid option. Please try again.")

    cli.service.cleanup()
    print("Goodbye!")
