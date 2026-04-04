#!/usr/bin/env python3

from __future__ import annotations

import platform
import signal
import sys

from app.services.vault_service import VaultService

from . import browse_actions, conflict_actions, manage_actions, setup_flow


def check_os() -> None:
    if platform.system() != "Windows":
        raise OSError("GlyphWeave currently supports Windows only")


class VaultCLI:
    def __init__(self) -> None:
        self.service = VaultService()

    @staticmethod
    def _print_lines(lines: list[str]) -> None:
        for line in lines:
            print(line)

    def setup_vault(self) -> bool:
        return setup_flow.setup_vault(self)

    def list_files(self) -> None:
        browse_actions.list_files(self)

    def add_file(self) -> None:
        browse_actions.add_file(self)

    def open_file(self) -> None:
        browse_actions.open_file(self)

    def list_unlocked_files(self) -> None:
        browse_actions.list_unlocked_files(self)

    def search_files(self) -> None:
        browse_actions.search_files(self)

    def reindex_supported_files(self) -> None:
        browse_actions.reindex_supported_files(self)

    def show_db_key(self) -> None:
        browse_actions.show_db_key(self)

    def show_recovery_phrase(self) -> None:
        browse_actions.show_recovery_phrase(self)

    def manage_entries(self) -> None:
        manage_actions.manage_entries(self)

    def manage_sync_conflicts(self) -> None:
        conflict_actions.manage_sync_conflicts(self)

    def copy_entry(self) -> None:
        manage_actions.copy_entry(self)

    def move_entries(self) -> None:
        manage_actions.move_entries(self)

    def delete_entries(self) -> None:
        manage_actions.delete_entries(self)

    def rename_entry(self) -> None:
        manage_actions.rename_entry(self)

    def export_entries(self) -> None:
        manage_actions.export_entries(self)

    def vault_menu(self) -> None:
        manage_actions.vault_menu(self)


def run_cli() -> None:
    check_os()
    cli = VaultCLI()
    _install_signal_handlers(cli)
    if not cli.setup_vault():
        sys.exit(1)
    cli.vault_menu()


def _install_signal_handlers(cli: VaultCLI) -> None:
    def _handle_interrupt(signum, frame) -> None:
        del signum, frame
        print("\nInterrupt received. Cleaning up...")
        try:
            cli.service.cleanup()
        finally:
            raise SystemExit(130)

    signal.signal(signal.SIGINT, _handle_interrupt)
