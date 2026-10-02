from __future__ import annotations

from pathlib import Path

import pytest

from headerproof.output import reserve_output_dir


def test_reserve_output_dir_creates_missing_parents(tmp_path: Path) -> None:
    requested = tmp_path / "runs" / "explicit"

    reserved = reserve_output_dir(requested)

    assert reserved == requested
    assert reserved.is_dir()


def test_reserve_output_dir_accepts_an_empty_directory(tmp_path: Path) -> None:
    requested = tmp_path / "empty"
    requested.mkdir()

    assert reserve_output_dir(requested) == requested


def test_reserve_output_dir_rejects_non_empty_directory_without_changing_it(tmp_path: Path) -> None:
    requested = tmp_path / "kept"
    requested.mkdir()
    existing = requested / "results.jsonl"
    existing.write_text('{"url": "https://example.test/"}\n', encoding="utf-8")

    with pytest.raises(FileExistsError, match="output directory is not empty"):
        reserve_output_dir(requested)

    assert existing.read_text(encoding="utf-8") == '{"url": "https://example.test/"}\n'
    assert list(requested.iterdir()) == [existing]


def test_reserve_output_dir_expands_user_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    requested = Path("~/headerproof-run")

    reserved = reserve_output_dir(requested)

    assert reserved == tmp_path / "headerproof-run"
    assert reserved.is_dir()
