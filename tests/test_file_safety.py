from __future__ import annotations

from pathlib import Path

from headerproof.file_safety import atomic_write_text


def test_atomic_write_text_creates_parents_and_replaces_destination(tmp_path: Path) -> None:
    destination = tmp_path / "nested" / "evidence" / "metadata.json"

    atomic_write_text(destination, "first\n")
    atomic_write_text(destination, "second complete\n")

    assert destination.read_text(encoding="utf-8") == "second complete\n"
    assert list(destination.parent.glob("*.tmp")) == []


def test_atomic_write_text_tolerates_fsync_oserror(tmp_path: Path, monkeypatch) -> None:
    destination = tmp_path / "summary.md"
    destination.write_text("previous\n", encoding="utf-8")

    def fail_fsync(_fd: int) -> None:
        raise OSError("fsync unavailable")

    monkeypatch.setattr("headerproof.file_safety.os.fsync", fail_fsync)

    atomic_write_text(destination, "replaced\n")

    assert destination.read_text(encoding="utf-8") == "replaced\n"
    assert not (tmp_path / "summary.md.tmp").exists()
