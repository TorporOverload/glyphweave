from __future__ import annotations

from getpass import getpass
from pathlib import Path
from typing import Any

from app.common.logging import logger

from .renderers import render_known_vault_lines, render_setup_vault_lines


def setup_vault(cli: Any) -> bool:
    print("\n=== GlyphWeave Vault Setup ===\n")

    while True:
        known = cli.service.load_known_vaults()
        cli._print_lines(render_setup_vault_lines(known))

        choice = input("\nSelect vault number: ").strip()

        if choice == "99":
            if create_new_vault_interactive(cli):
                return True
            continue

        if choice == "97":
            if import_vault_interactive(cli):
                return True
            continue

        if choice == "98":
            if recover_vault_with_recovery_phrase(cli, known):
                return True
            continue

        if choice.isdigit():
            index = int(choice) - 1
            if 0 <= index < len(known):
                selected = known[index]
                try:
                    cli.service.prepare_existing_vault(
                        vault_path=Path(str(selected["path"])),
                        fallback_alias=selected.get("vault_alias"),
                        fallback_vault_id=selected.get("vault_id"),
                    )
                    password = getpass("Enter vault password: ")
                    cli.service.open_existing_vault(password)
                    print("\nVault unlocked successfully")
                    return True
                except Exception as exc:
                    print(f"\nFailed to unlock vault: {exc}")
                    logger.exception("Failed to unlock vault")
                    continue

        print("Invalid selection. Please try again.\n")


def prompt_new_password() -> str:
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


def create_new_vault_interactive(cli: Any) -> bool:
    print("\n=== Create New Vault ===\n")

    default_location = str(Path.cwd())
    location_input = (
        input(f"Enter vault directory path (default: {default_location}): ")
        .strip()
        .strip('"')
    )
    vault_path = Path(location_input) if location_input else Path(default_location)

    default_name = vault_path.name
    name_input = input(f"Enter vault display name (default: {default_name}): ").strip()
    vault_name = name_input if name_input else default_name

    password = prompt_new_password()

    try:
        recovery_phrase = cli.service.create_new_vault(
            vault_path=vault_path,
            vault_name=vault_name,
            password=password,
        )
    except FileExistsError:
        print(
            "A vault already exists in that directory.Please select it from the list."
        )
        return False
    except Exception as exc:
        print(f"\nFailed to create vault: {exc}")
        logger.exception("Failed to create vault")
        return False

    print("\n" + "=" * 60)
    print("IMPORTANT: Save your recovery phrase!")
    print("=" * 60)
    print(f"\nRecovery Phrase:\n\n{recovery_phrase}\n")
    print("=" * 60)

    input("\nPress Enter once you've saved your recovery phrase...")
    print("\nVault created successfully!")
    print(f"  Vault dir  : {cli.service.vault_path}")
    print(f"  Local data : {cli.service.context.local_data_path}")
    return True


def import_vault_interactive(cli: Any) -> bool:
    print("\n=== Import Existing Vault ===\n")

    location_input = input("Enter vault directory path: ").strip().strip('"')
    if not location_input:
        print("No vault directory provided.")
        return False

    vault_path = Path(location_input)
    alias_input = input(
        "Override vault display name (blank to keep stored name): "
    ).strip()
    fallback_alias = alias_input or None

    try:
        imported = cli.service.import_vault(vault_path, fallback_alias)
        print(f"Imported vault: {imported['vault_alias']}")
    except Exception as exc:
        print(f"\nFailed to import vault: {exc}")
        logger.exception("Failed to import vault")
        return False

    try:
        password = getpass("Enter vault password: ")
        cli.service.open_existing_vault(password)
    except Exception as exc:
        print(f"\nFailed to unlock imported vault: {exc}")
        logger.exception("Failed to unlock imported vault")
        return False

    print("\nVault imported and unlocked successfully")
    return True


def recover_vault_with_recovery_phrase(cli: Any, known_vaults: list[dict]) -> bool:
    print("\n=== Recover Vault ===\n")

    if known_vaults:
        cli._print_lines(render_known_vault_lines(known_vaults))

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
        cli.service.prepare_existing_vault(vault_path, selected_alias, selected_id)
    except Exception as exc:
        print(str(exc))
        return False

    recovery_input = getpass("Enter recovery phrase: ")
    new_password = prompt_new_password()

    try:
        cli.service.recover_with_recovery_phrase(
            recovery_phrase=recovery_input,
            new_password=new_password,
        )
    except Exception as exc:
        print(f"\nFailed to recover vault: {exc}")
        logger.exception("Failed to recover vault")
        return False

    print("\nVault recovered successfully. Your password has been reset.")
    return True
