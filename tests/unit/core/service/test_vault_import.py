from pathlib import Path

from app.core.service.models import VaultContext
from app.core.service.registry_service import load_registry, write_vault_metadata
from app.core.service.vault_runtime_service import VaultRuntimeService
from app.core.service.vault_service import VaultService


def test_vault_runtime_service_imports_unregistered_vault(tmp_path: Path) -> None:
    app_data_dir = tmp_path / "app"
    vault_path = tmp_path / "vault"
    vault_path.mkdir(parents=True, exist_ok=True)
    write_vault_metadata(vault_path, "vault-123", "Imported Vault")
    context = VaultContext(app_data_dir=app_data_dir)
    runtime = VaultRuntimeService(context)

    imported = runtime.import_vault(vault_path)

    assert imported == {
        "vault_id": "vault-123",
        "vault_alias": "Imported Vault",
        "path": str(vault_path),
    }
    assert context.vault_id == "vault-123"
    assert context.vault_name == "Imported Vault"
    registry = load_registry(app_data_dir)
    assert len(registry) == 1
    assert registry[0]["vault_id"] == "vault-123"
    assert registry[0]["vault_alias"] == "Imported Vault"
    assert registry[0]["path"] == str(vault_path)
    assert registry[0]["last_opened"]


def test_vault_service_import_vault_delegates_to_runtime(tmp_path: Path, monkeypatch) -> None:
    service = VaultService(app_data_dir=tmp_path)
    expected = {
        "vault_id": "vault-123",
        "vault_alias": "Imported Vault",
        "path": str(tmp_path / "vault"),
    }
    monkeypatch.setattr(
        service.runtime,
        "import_vault",
        lambda vault_path, fallback_alias=None, fallback_vault_id=None: expected,
    )

    assert service.import_vault(tmp_path / "vault") == expected
