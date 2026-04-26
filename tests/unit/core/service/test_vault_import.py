from pathlib import Path
from types import SimpleNamespace

from app.services.models import VaultContext
from app.infrastructure.persistence.registry_service import load_registry, write_vault_metadata
from app.services.runtime.vault_runtime_service import VaultRuntimeService
from app.services.vault_service import VaultService


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


def test_vault_runtime_service_deletes_local_vault_record(tmp_path: Path) -> None:
    app_data_dir = tmp_path / "app"
    vault_path = tmp_path / "vault"
    vault_path.mkdir(parents=True, exist_ok=True)
    write_vault_metadata(vault_path, "vault-123", "Imported Vault")
    context = VaultContext(app_data_dir=app_data_dir)
    runtime = VaultRuntimeService(context)
    runtime.import_vault(vault_path)
    local_data = app_data_dir / "vaults" / "vault-123"
    local_data.mkdir(parents=True, exist_ok=True)
    (local_data / "vault.db").write_text("local-only", encoding="utf-8")

    removed = runtime.delete_local_vault_record("vault-123")

    assert removed is True
    assert load_registry(app_data_dir) == []
    assert not local_data.exists()


def test_vault_service_repair_local_state_rebuilds_for_db_only_issues(
    tmp_path: Path, monkeypatch
) -> None:
    service = VaultService(app_data_dir=tmp_path)
    baseline = SimpleNamespace(
        ok=False,
        issues=[SimpleNamespace(code="db_mismatch", message="db differs")],
    )
    repaired = SimpleNamespace(ok=True, issues=[])
    cleanup_calls: list[bool] = []
    rebuild_calls: list[int] = []
    check_calls = {"count": 0}

    def _check():
        check_calls["count"] += 1
        return baseline if check_calls["count"] == 1 else repaired

    monkeypatch.setattr(service, "check_integrity", _check)
    monkeypatch.setattr(
        service,
        "cleanup",
        lambda *, flush_db_dump=True: cleanup_calls.append(flush_db_dump),
    )
    monkeypatch.setattr(
        service.runtime,
        "rebuild_local_runtime_state",
        lambda: rebuild_calls.append(1),
    )

    result = service.repair_local_state()

    assert result is repaired
    assert cleanup_calls == [False]
    assert rebuild_calls == [1]


def test_vault_service_repair_local_state_refuses_unsafe_issues(
    tmp_path: Path, monkeypatch
) -> None:
    service = VaultService(app_data_dir=tmp_path)
    monkeypatch.setattr(
        service,
        "check_integrity",
        lambda: SimpleNamespace(
            ok=False,
            issues=[SimpleNamespace(code="corrupt_event", message="bad event")],
        ),
    )

    try:
        service.repair_local_state()
    except RuntimeError as exc:
        assert "corrupt_event" in str(exc)
    else:
        raise AssertionError("Expected repair_local_state to refuse unsafe repair")


def test_vault_runtime_service_rebuild_disposes_db_before_removing_local_data(
    tmp_path: Path,
) -> None:
    app_data_dir = tmp_path / "app"
    local_data = app_data_dir / "vaults" / "vault-123"
    local_data.mkdir(parents=True, exist_ok=True)
    marker = local_data / "vault.db"
    marker.write_text("stale", encoding="utf-8")
    disposed: list[bool] = []
    context = VaultContext(
        app_data_dir=app_data_dir,
        vault_id="vault-123",
        local_data_path=local_data,
        db=SimpleNamespace(engine=SimpleNamespace(dispose=lambda: disposed.append(True))),
    )
    runtime = VaultRuntimeService(context)
    runtime._init_services = lambda: None

    runtime.rebuild_local_runtime_state()

    assert disposed == [True]
    assert not marker.exists()
