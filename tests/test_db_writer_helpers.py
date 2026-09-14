"""Unit-тести допоміжної поведінки db-writer."""

from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_db_writer_app():
    module_path = Path(__file__).parents[1] / "services" / "db_writer" / "app.py"
    spec = importlib.util.spec_from_file_location("db_writer_app_test", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_do_backup_prunes_to_five_newest_sql_files(tmp_path, monkeypatch):
    app = _load_db_writer_app()
    monkeypatch.setattr(app, "BACKUP_DIR", tmp_path)
    monkeypatch.setattr(app, "BACKUP_RETENTION", 5)
    monkeypatch.setattr(app, "_emit_event", lambda *_args, **_kwargs: None)

    def fake_pg_dump(output_path: str) -> bool:
        Path(output_path).write_text(Path(output_path).name, encoding="utf-8")
        return True

    monkeypatch.setattr(app, "_pg_dump", fake_pg_dump)

    for idx in range(7):
        assert app._do_backup(f"snapshot_{idx}") is True

    assert app._list_snapshots() == [
        "snapshot_2.sql",
        "snapshot_3.sql",
        "snapshot_4.sql",
        "snapshot_5.sql",
        "snapshot_6.sql",
    ]
    assert not (tmp_path / "snapshot_0.sql").exists()
    assert not (tmp_path / "snapshot_1.sql").exists()
