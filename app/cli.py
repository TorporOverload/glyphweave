#!/usr/bin/env python3

from __future__ import annotations

import platform
import sys
from collections.abc import Callable, Sequence
from getpass import getpass
from pathlib import Path
from typing import Any

from app.core.service.safe_paths import safe_cache_path
from app.core.service.vault_service import VaultService
from app.utils.logging import logger


def check_os() -> None:
    """Raise OSError if the current platform is not Windows."""
    if platform.system() != "Windows":
        raise OSError("GlyphWeave currently supports Windows only")


def render_setup_vault_lines(known_vaults: list[dict]) -> list[str]:
    """Return display lines for the vault setup menu including known vaults and action
    options."""
    lines = render_known_vault_lines(known_vaults)
    lines.extend(
        [
            "  98. Recover vault with recovery phrase",
            "  99. Create new vault",
        ]
    )
    return lines


def render_known_vault_lines(known_vaults: list[dict]) -> list[str]:
    """Return numbered display lines for the list of known vaults."""
    if not known_vaults:
        return ["No known vaults yet."]

    lines = ["Known vaults:"]
    for index, vault in enumerate(known_vaults, 1):
        lines.append(f"  {index}. {vault['vault_alias']}  ({vault['path']})")
    return lines


def render_vault_contents_lines(
    root_entries: Sequence[Any],
    get_children: Callable[[int], Sequence[Any]],
) -> list[str]:
    """Return indented display lines for all vault entries, recursively expanding
    folders."""
    lines: list[str] = []
    for index, ref in enumerate(root_entries, 1):
        if ref.is_folder:
            lines.append(f"  {index}. [DIR]  {ref.name}")
            lines.extend(
                _render_child_lines(get_children(ref.id), get_children, "         ")
            )
        else:
            lines.append(f"  {index}. {ref.name}{_size_suffix(ref)}")
    return lines


def _render_child_lines(
    entries: Sequence[Any],
    get_children: Callable[[int], Sequence[Any]],
    prefix: str,
) -> list[str]:
    """Recursively render child entries with the given indentation prefix."""
    lines: list[str] = []
    for ref in entries:
        if ref.is_folder:
            lines.append(f"{prefix}[DIR] {ref.name}")
            lines.extend(
                _render_child_lines(get_children(ref.id), get_children, prefix + "  ")
            )
        else:
            lines.append(f"{prefix}{ref.name}{_size_suffix(ref)}")
    return lines


def render_available_file_lines(file_refs: Sequence[Any]) -> list[str]:
    """Return numbered display lines for a flat list of file references."""
    return [
        f"  {index}. {ref.name}{_size_suffix(ref)}"
        for index, ref in enumerate(file_refs, 1)
    ]


def render_unlocked_file_lines(unlocked_items: Sequence[Any]) -> list[str]:
    """Return numbered display lines for all currently unlocked files."""
    lines: list[str] = []
    for index, item in enumerate(unlocked_items, 1):
        source_label = "FUSE" if item.source == "mount" else "CACHE"
        lines.append(
            f"  {index}. [{source_label}] {item.file_name}  ({item.file_path})"
        )
    return lines


def render_vault_menu_lines(vault_name: str | None) -> list[str]:
    """Return the main vault action menu lines for display."""
    return [
        "=" * 40,
        f"GlyphWeave - {vault_name}",
        "=" * 40,
        "1. List files",
        "2. Open file",
        "3. List unlocked files",
        "4. Add file",
        "5. Show recovery phrase",
        "6. Show DB key (debug)",
        "7. Exit",
        "=" * 40,
    ]


def select_file_by_choice(choice: str, file_refs: Sequence[Any]) -> Any | None:
    """Select a file reference by index number or by name from user input."""
    if choice.isdigit():
        index = int(choice) - 1
        if 0 <= index < len(file_refs):
            return file_refs[index]
        return None

    for ref in file_refs:
        if ref.name == choice:
            return ref
    return None


def _size_suffix(ref: Any) -> str:
    """Return a formatted size string for a file reference, or empty string for
    folders."""
    if getattr(ref, "file_entry", None):
        return f"  ({ref.file_entry.original_size_bytes} bytes)"
    return ""


class VaultCLI:
    def __init__(self):
        self.service = VaultService()

    def setup_vault(self) -> bool:
        """Run the interactive vault selection or creation flow and return True on
        success."""
        print("\n=== GlyphWeave Vault Setup ===\n")

        while True:
            known = self.service.load_known_vaults()
            self._print_lines(render_setup_vault_lines(known))

            choice = input("\nSelect vault number: ").strip()

            if choice == "99":
                if self._create_new_vault_interactive():
                    return True
                continue

            if choice == "98":
                if self.recover_vault_with_recovery_phrase(known):
                    return True
                continue

            if choice.isdigit():
                index = int(choice) - 1
                if 0 <= index < len(known):
                    selected = known[index]
                    try:
                        self.service.prepare_existing_vault(
                            vault_path=Path(str(selected["path"])),
                            fallback_alias=selected.get("vault_alias"),
                            fallback_vault_id=selected.get("vault_id"),
                        )
                        password = getpass("Enter vault password: ")
                        self.service.open_existing_vault(password)
                        print("\nVault unlocked successfully")
                        return True
                    except Exception as e:
                        print(f"\nFailed to unlock vault: {e}")
                        logger.exception("Failed to unlock vault")
                        continue

            print("Invalid selection. Please try again.\n")

    @staticmethod
    def _prompt_new_password() -> str:
        """Prompt the user to enter and confirm a new vault password interactively."""
        while True:
            password = getpass("Enter vault password: ")
            password_confirm = getpass("Confirm password: ")

            if password != password_confirm:
                print("Passwords don't match. Try again.")
                continue

            if len(password) < 8:
                print("Password must be at least 8 characters.")
                continue

            return password

    def _create_new_vault_interactive(self) -> bool:
        """Interactively prompt for vault location, name, and password to create a new
        vault."""
        print("\n=== Create New Vault ===\n")

        default_location = str(Path.cwd())
        location_input = (
            input(f"Enter vault directory path (default: {default_location}): ")
            .strip()
            .strip('"')
        )
        vault_path = Path(location_input) if location_input else Path(default_location)

        default_name = vault_path.name
        name_input = input(
            f"Enter vault display name (default: {default_name}): "
        ).strip()
        vault_name = name_input if name_input else default_name

        password = self._prompt_new_password()

        try:
            recovery_phrase = self.service.create_new_vault(
                vault_path=vault_path,
                vault_name=vault_name,
                password=password,
            )
        except FileExistsError:
            print(
                "A vault already exists in that directory."
                "Please select it from the list."
            )
            return False
        except Exception as e:
            print(f"\nFailed to create vault: {e}")
            logger.exception("Failed to create vault")
            return False

        print("\n" + "=" * 60)
        print("IMPORTANT: Save your recovery phrase!")
        print("=" * 60)
        print(f"\nRecovery Phrase:\n\n{recovery_phrase}\n")
        print("=" * 60)

        input("\nPress Enter once you've saved your recovery phrase...")
        print("\nVault created successfully!")
        print(f"  Vault dir  : {self.service.vault_path}")
        print(f"  Local data : {self.service.context.local_data_path}")
        return True

    def recover_vault_with_recovery_phrase(self, known_vaults: list[dict]) -> bool:
        """Interactively recover a vault using the recovery phrase and set a new
        password."""
        print("\n=== Recover Vault ===\n")

        if known_vaults:
            self._print_lines(render_known_vault_lines(known_vaults))

        selection = (
            input("Select vault number to recover or enter vault directory path: ")
            .strip()
            .strip('"')
        )

        selected_alias: str | None = None
        selected_id: str | None = None
        if selection.isdigit():
            index = int(selection) - 1
            if 0 <= index < len(known_vaults):
                selected = known_vaults[index]
                vault_path = Path(str(selected["path"]))
                selected_alias = selected.get("vault_alias")
                selected_id = selected.get("vault_id")
            else:
                print("Invalid vault number.")
                return False
        else:
            if not selection:
                print("No vault selected.")
                return False
            vault_path = Path(selection)

        try:
            self.service.prepare_existing_vault(vault_path, selected_alias, selected_id)
        except Exception as e:
            print(str(e))
            return False

        recovery_input = getpass("Enter recovery phrase: ")
        new_password = self._prompt_new_password()

        try:
            self.service.recover_with_recovery_phrase(
                recovery_phrase=recovery_input,
                new_password=new_password,
            )
        except Exception as e:
            print(f"\nFailed to recover vault: {e}")
            logger.exception("Failed to recover vault")
            return False

        print("\nVault recovered successfully. Your password has been reset.")
        return True

    def list_files(self) -> None:
        """Print all files and folders in the vault to stdout."""
        print("\n=== Vault Contents ===\n")
        try:
            root_entries = self.service.list_root_entries()
            if not root_entries:
                print("  (no files in vault)")
                return

            self._print_lines(
                render_vault_contents_lines(root_entries, self.service.list_children)
            )
        except Exception as e:
            print(f"\nError listing files: {e}")
            logger.exception("Failed to list files")

    def add_file(self) -> None:
        """Interactively prompt for a file path and import it into the vault."""
        print("\n=== Add File to Vault ===\n")

        source_path = input("Enter path to file: ").strip().strip('"')
        source = Path(source_path)

        default_dest = source.name
        dest_input = input(
            f"Destination name in vault (default: {default_dest}): "
        ).strip()
        dest_name = dest_input if dest_input else default_dest

        try:
            result = self.service.add_file(source, dest_name)
            print(f"\nFile added successfully: {result.file_name}")
            if result.deduplicated:
                print("  Deduplicated: reused existing encrypted content")
            else:
                print(f"  File ID: {result.file_id}")
                print(f"  Blobs: {result.blob_count}")
            print(f"  Original size: {result.original_size} bytes")
            print(f"  Encrypted size: {result.encrypted_size} bytes")
        except Exception as e:
            print(f"\nError adding file: {e}")
            logger.exception("Failed to add file")

    def open_file(self) -> None:
        """Interactively select and open a file from the vault."""
        print("\n=== Open File from Vault ===\n")

        try:
            root_entries = self.service.list_root_entries()
        except Exception as e:
            print(f"Failed to load files: {e}")
            return

        file_refs = [r for r in root_entries if not r.is_folder]
        if not file_refs:
            print("No files in vault.")
            return

        print("Available files:")
        self._print_lines(render_available_file_lines(file_refs))

        choice = input("\nEnter file number or name: ").strip()
        selected = select_file_by_choice(choice, file_refs)
        if not selected:
            print(f"File not found: {choice}")
            return

        try:
            result = self.service.open_file_by_ref(
                file_ref_id=selected.id,
                launch_in_default_app=True,
            )
        except Exception as e:
            print(f"\nError opening file: {e}")
            logger.exception("Failed to open file")
            return

        print(f"\n{result.message}")
        print("Use 'List unlocked files' to open again or unmount it.")

    def list_unlocked_files(self) -> None:
        """Display all unlocked files and let the user reopen or unmount one."""
        print("\n=== Unlocked Files ===\n")
        unlocked_items = self.service.list_unlocked_files()
        if not unlocked_items:
            print("No unlocked files.")
            return

        self._print_lines(render_unlocked_file_lines(unlocked_items))

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
                message = self.service.reopen_unlocked(selected.file_ref_id)
                print(message)
            except Exception as e:
                print(str(e))
            return

        if action == "2":
            try:
                message = self.service.unmount_unlocked(selected.file_ref_id)
                print(message)
            except Exception as e:
                print(str(e))
            return

        print("Cancelled.")

    def show_db_key(self) -> None:
        """Print the vault database path and SQLCipher key for debugging."""
        print("\n=== Database Debug Info ===\n")
        try:
            info = self.service.get_db_debug_info()
        except Exception as e:
            print(str(e))
            return

        print(f"  DB Path    : {info['db_path']}")
        print(f"  Vault Dir  : {info['vault_path']}")
        print(f"  DB Key     : {info['db_key']}")
        print("\n  SQLCipher PRAGMA:")
        print(f"    PRAGMA key = \"x'{info['db_key']}'\";")
        print()

    def show_recovery_phrase(self) -> None:
        """Print the vault recovery phrase to stdout."""
        print("\n=== Recovery Phrase ===\n")
        try:
            phrase = self.service.get_recovery_phrase()
        except Exception as e:
            print(f"Recovery phrase is unavailable: {e}")
            return

        print("Store this phrase securely. It can recover your vault password.")
        print(f"\n{phrase}\n")

    @staticmethod
    def _safe_cache_path(cache_dir: Path, file_name: str) -> Path:
        """Delegate to safe_cache_path to resolve a path-traversal-safe cache path."""
        return safe_cache_path(cache_dir, file_name)

    @staticmethod
    def _print_lines(lines: list[str]) -> None:
        """Print each line in the list to stdout."""
        for line in lines:
            print(line)

    def vault_menu(self) -> None:
        """Run the main vault action loop until the user chooses to exit."""
        while True:
            print("\n" + "=" * 40)
            self._print_lines(render_vault_menu_lines(self.service.vault_name))

            choice = input("\nSelect option (1-7): ").strip()

            if choice == "1":
                self.list_files()
            elif choice == "2":
                self.open_file()
            elif choice == "3":
                self.list_unlocked_files()
            elif choice == "4":
                self.add_file()
            elif choice == "5":
                self.show_recovery_phrase()
            elif choice == "6":
                self.show_db_key()
            elif choice == "7":
                print("\nClosing vault...")
                break
            else:
                print("Invalid option. Please try again.")

        self.service.cleanup()
        print("Goodbye!")


def run_cli() -> None:
    """Entry point for the GlyphWeave CLI: validate OS, set up the vault, and run the
    menu."""
    check_os()
    cli = VaultCLI()
    if not cli.setup_vault():
        sys.exit(1)
    cli.vault_menu()


def main() -> None:
    """Invoke the CLI entry point."""
    run_cli()


if __name__ == "__main__":
    main()
