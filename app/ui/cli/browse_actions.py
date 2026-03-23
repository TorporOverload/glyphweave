from __future__ import annotations

from pathlib import Path
from typing import Any

from app.common.logging import logger

from .renderers import (
    render_directory_entry_lines,
    render_search_options_lines,
    render_search_result_lines,
    render_unlocked_file_lines,
    render_vault_contents_lines,
    select_file_by_choice,
)


def list_files(cli: Any) -> None:
    print("\n=== Vault Contents ===\n")
    try:
        root_entries = cli.service.list_root_entries()
        if not root_entries:
            print("  (no files in vault)")
            return

        cli._print_lines(
            render_vault_contents_lines(root_entries, cli.service.list_children)
        )
    except Exception as exc:
        print(f"\nError listing files: {exc}")
        logger.exception("Failed to list files")


def add_file(cli: Any) -> None:
    print("\n=== Add File to Vault ===\n")

    source_path = input("Enter path to file: ").strip().strip('"')
    source = Path(source_path)

    default_dest = source.name
    dest_input = input(f"Destination name in vault (default: {default_dest}): ").strip()
    dest_name = dest_input if dest_input else default_dest

    try:
        result = cli.service.add_file(source, dest_name)
        print(f"\nFile added successfully: {result.file_name}")
        if result.deduplicated:
            print("  Deduplicated: reused existing encrypted content")
        else:
            print(f"  File ID: {result.file_id}")
            print(f"  Blobs: {result.blob_count}")
        print(f"  Indexed: {'yes' if result.indexed else 'no'}")
        print(f"  Original size: {result.original_size} bytes")
        print(f"  Encrypted size: {result.encrypted_size} bytes")
    except Exception as exc:
        print(f"\nError adding file: {exc}")
        logger.exception("Failed to add file")


def open_file(cli: Any) -> None:
    print("\n=== Open File from Vault ===\n")

    try:
        current_entries = list(cli.service.list_root_entries())
    except Exception as exc:
        print(f"Failed to load files: {exc}")
        return

    current_path = "/"
    history: list[tuple[str, list[Any]]] = []

    while True:
        print(f"Current directory: {current_path}")
        if current_entries:
            cli._print_lines(render_directory_entry_lines(current_entries))
        else:
            print("  (empty)")

        if history:
            print("  b. Go to parent directory")
        print("  [blank]. Cancel")

        choice = input("\nEnter selection: ").strip()
        if not choice:
            return
        if choice.lower() == "b":
            if history:
                current_path, current_entries = history.pop()
            else:
                print("Already at root.")
            continue

        selected = select_file_by_choice(choice, current_entries)
        if not selected:
            print(f"Entry not found: {choice}")
            continue

        if selected.is_folder:
            try:
                child_entries = list(cli.service.list_children(selected.id))
            except Exception as exc:
                print(f"\nError opening folder: {exc}")
                logger.exception("Failed to browse folder")
                continue

            history.append((current_path, current_entries))
            current_path = (
                f"/{selected.name}"
                if current_path == "/"
                else f"{current_path}/{selected.name}"
            )
            current_entries = child_entries
            continue

        try:
            result = cli.service.open_file_by_ref(
                file_ref_id=selected.id,
                launch_in_default_app=True,
            )
        except Exception as exc:
            print(f"\nError opening file: {exc}")
            logger.exception("Failed to open file")
            return

        print(f"\n{result.message}")
        print("Use 'List unlocked files' to open again or unmount it.")
        return


def list_unlocked_files(cli: Any) -> None:
    print("\n=== Unlocked Files ===\n")
    unlocked_items = cli.service.list_unlocked_files()
    if not unlocked_items:
        print("No unlocked files.")
        return

    cli._print_lines(render_unlocked_file_lines(unlocked_items))

    choice = input("\nSelect unlocked file number (blank to go back): ").strip()
    if not choice:
        return
    if not choice.isdigit():
        print("Invalid selection.")
        return

    selected_index = int(choice) - 1
    if not (0 <= selected_index < len(unlocked_items)):
        print("Invalid selection.")
        return

    selected = unlocked_items[selected_index]
    print(f"\nSelected unlocked file: {selected.file_name}")
    print("1. Open again")
    print("2. Unmount")
    print("3. Cancel")

    action = input("Select option (1-3): ").strip()
    if action == "1":
        try:
            message = cli.service.reopen_unlocked(selected.file_ref_id)
            print(message)
        except Exception as exc:
            print(str(exc))
        return

    if action == "2":
        try:
            message = cli.service.unmount_unlocked(selected.file_ref_id)
            print(message)
        except Exception as exc:
            print(str(exc))
        return

    print("Cancelled.")


def search_files(cli: Any) -> None:
    print("\n=== Search Vault ===\n")
    print("1. Search by content")
    print("2. Re-index supported pending/failed files")
    action = input("\nSelect option (blank to go back): ").strip()
    if not action:
        return
    if action == "2":
        reindex_supported_files(cli)
        return
    if action != "1":
        print("Invalid selection.")
        return

    query = input("\nSearch query: ").strip()
    if not query:
        print("Empty query.")
        return

    limit = 20
    offset = 0
    while True:
        try:
            page = cli.service.search_page(query, limit=limit, offset=offset)
        except Exception as exc:
            print(f"Search failed: {exc}")
            logger.exception("Search failed")
            return

        results = page.results
        cli._print_lines(render_search_result_lines(results))
        if not results:
            return

        cli._print_lines(render_search_options_lines(page.has_more))
        choice = input("\nSelect option: ").strip()
        if not choice:
            return
        if choice.lower() == "n" and page.has_more:
            offset += limit
            continue
        if not choice.isdigit():
            print("Invalid selection.")
            continue

        selected_index = int(choice) - 1
        if not (0 <= selected_index < len(results)):
            print("Invalid selection.")
            continue

        selected = results[selected_index]
        try:
            result = cli.service.open_file_by_ref(
                file_ref_id=selected.file_ref_id,
                launch_in_default_app=True,
            )
            print(f"\n{result.message}")
        except Exception as exc:
            print(f"\nError opening file: {exc}")
            logger.exception("Failed to open search result")
        return


def reindex_supported_files(cli: Any) -> None:
    print("\nRe-indexing supported pending/failed files...")
    try:
        success, failed = cli.service.reindex_pending()
    except Exception as exc:
        print(f"Re-index failed: {exc}")
        logger.exception("Re-index failed")
        return

    print(f"Done. Indexed: {success}, Failed: {failed}")


def show_db_key(cli: Any) -> None:
    print("\n=== Database Debug Info ===\n")
    try:
        info = cli.service.get_db_debug_info()
    except Exception as exc:
        print(str(exc))
        return

    print(f"  DB Path    : {info['db_path']}")
    print(f"  Vault Dir  : {info['vault_path']}")
    print(f"  DB Key     : {info['db_key']}")
    print("\n  SQLCipher PRAGMA:")
    print(f"    PRAGMA key = \"x'{info['db_key']}'\";")
    print()


def show_recovery_phrase(cli: Any) -> None:
    print("\n=== Recovery Phrase ===\n")
    try:
        phrase = cli.service.get_recovery_phrase()
    except Exception as exc:
        print(f"Recovery phrase is unavailable: {exc}")
        return

    print("Store this phrase securely. It can recover your vault password.")
    print(f"\n{phrase}\n")
