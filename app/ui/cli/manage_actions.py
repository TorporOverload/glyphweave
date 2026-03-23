from __future__ import annotations

from pathlib import Path
from typing import Any

from app.common.logging import logger

from .renderers import parse_path_list, render_vault_menu_lines


def manage_entries(cli: Any) -> None:
    print("\n=== Manage Vault Entries ===\n")
    print_entry_paths(cli)
    print("\n1. Copy file/folder")
    print("2. Move file/folder(s)")
    print("3. Delete file/folder(s)")
    print("4. Rename file/folder")
    print("5. Export file/folder(s)")

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


def vault_menu(cli: Any) -> None:
    while True:
        print("\n" + "=" * 40)
        cli._print_lines(render_vault_menu_lines(cli.service.vault_name))

        choice = input("\nSelect option (1-9): ").strip()

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
            print("\nClosing vault...")
            break
        else:
            print("Invalid option. Please try again.")

    cli.service.cleanup()
    print("Goodbye!")
