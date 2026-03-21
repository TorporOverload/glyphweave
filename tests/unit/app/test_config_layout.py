from pathlib import Path

from app.config import ensure_app_data_layout


def test_ensure_app_data_layout_creates_expected_structure(tmp_path: Path) -> None:
    app_data_dir = tmp_path / ".glyphweave"

    ensure_app_data_layout(app_data_dir)

    assert (app_data_dir / "vaults").exists()
    assert (app_data_dir / "logs").exists()
    assert (app_data_dir / "vaults.json").exists()
    assert (app_data_dir / "config.json").exists()
    assert (app_data_dir / "device.json").exists()
