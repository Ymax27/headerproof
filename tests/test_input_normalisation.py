from __future__ import annotations

from pathlib import Path

from headerproof.input import iter_url_lines, iter_urls, load_urls, normalise_url


def test_normalise_url_accepts_bare_host_and_scheme_relative_targets() -> None:
    assert normalise_url("example.com") == "https://example.com/"
    assert normalise_url("example.com:8443/app") == "https://example.com:8443/app"
    assert normalise_url("//cdn.example/app?x=1#fragment") == "https://cdn.example/app?x=1"
    assert normalise_url("  https://example.com/a/b?q=1#frag extra") == "https://example.com/a/b?q=1"


def test_normalise_url_reads_supported_jsonl_keys_in_priority_order() -> None:
    assert normalise_url('{"target": "https://a.test/t", "url": "https://b.test/u"}') == "https://b.test/u"
    assert normalise_url('{"final_url": "https://c.test/final#x"}') == "https://c.test/final"
    assert normalise_url('{"input": "d.test/from-input"}') == "https://d.test/from-input"
    assert normalise_url('{"target": "https://e.test/only"}') == "https://e.test/only"


def test_normalise_url_skips_invalid_records() -> None:
    assert normalise_url("") is None
    assert normalise_url("   ") is None
    assert normalise_url("# comment") is None
    assert normalise_url("{") is None
    assert normalise_url('{"url": "ftp://files.test/secret"}') is None
    assert normalise_url('{"url": ""}') is None
    assert normalise_url('{"url": 12}') is None
    assert normalise_url('{"ignored": "https://skipped.test/"}') is None
    assert normalise_url("ftp://files.test/a") is None
    assert normalise_url("http://") is None


def test_iter_url_lines_keeps_first_seen_order_and_honors_max_urls() -> None:
    lines = [
        "# skip",
        "example.com",
        "https://example.com/",
        "https://example.com/a?q=1#gone",
        '{"url": "https://example.com/a?q=1"}',
        "other.test/b",
        "ftp://bad.test/x",
        "third.test",
    ]

    assert list(iter_url_lines(iter(lines))) == [
        "https://example.com/",
        "https://example.com/a?q=1",
        "https://other.test/b",
        "https://third.test/",
    ]
    assert list(iter_url_lines(iter(lines), max_urls=2)) == [
        "https://example.com/",
        "https://example.com/a?q=1",
    ]


def test_sqlite_dedup_matches_memory_and_persists_across_reads(tmp_path: Path) -> None:
    source = tmp_path / "urls.txt"
    source.write_text(
        "\n".join(
            [
                "example.com",
                "https://example.com/a?q=1#frag",
                '{"final_url": "https://example.com/a?q=1"}',
                "not-a-scheme://bad",
                '{"url": ""}',
                "other.test/path",
                "example.com",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    expected = [
        "https://example.com/",
        "https://example.com/a?q=1",
        "https://other.test/path",
    ]

    assert load_urls(source) == expected
    assert list(iter_url_lines(iter(source.read_text(encoding="utf-8").splitlines()))) == expected

    database = tmp_path / "dedup" / "seen.sqlite3"
    assert list(iter_urls(source, dedup_db=database)) == expected
    assert list(iter_urls(source, dedup_db=database)) == []
    assert list(iter_urls(source, max_urls=1, dedup_db=tmp_path / "fresh.sqlite3")) == expected[:1]
