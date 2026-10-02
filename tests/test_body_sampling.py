from __future__ import annotations

import hashlib

from headerproof.models import HttpSnapshot
from headerproof.transport import consume_body, decode_body, snapshot_summary


class ChunkedStream:
    def __init__(self, payload: bytes, chunk_size: int) -> None:
        self.payload = payload
        self.chunk_size = chunk_size
        self.offset = 0

    def read(self, size: int = -1) -> bytes:
        if self.offset >= len(self.payload):
            return b""
        step = self.chunk_size if size < 0 else min(size, self.chunk_size)
        chunk = self.payload[self.offset : self.offset + step]
        self.offset += len(chunk)
        return chunk


def test_consume_body_hashes_the_full_response_and_caps_the_sample() -> None:
    payload = b"abcdefghij"
    sample, total, digest, truncated = consume_body(ChunkedStream(payload, 3), 4)

    assert sample == b"abcd"
    assert total == len(payload)
    assert digest == hashlib.sha256(payload).hexdigest()
    assert truncated is True


def test_consume_body_covers_empty_and_exact_limit() -> None:
    empty_sample, empty_total, empty_digest, empty_truncated = consume_body(ChunkedStream(b"", 8), 4)
    exact_sample, exact_total, exact_digest, exact_truncated = consume_body(ChunkedStream(b"wxyz", 2), 4)

    assert (empty_sample, empty_total, empty_truncated) == (b"", 0, False)
    assert empty_digest == hashlib.sha256(b"").hexdigest()
    assert (exact_sample, exact_total, exact_truncated) == (b"wxyz", 4, False)
    assert exact_digest == hashlib.sha256(b"wxyz").hexdigest()


def test_decode_body_falls_back_to_utf8_replacement_for_unknown_charsets() -> None:
    assert decode_body("café".encode("iso-8859-1"), "text/plain; charset=iso-8859-1") == "café"
    assert decode_body("ok".encode("utf-8"), 'text/html; charset="utf-8"') == "ok"
    assert decode_body(b"caf\xe9", "text/plain; charset=not-a-charset") == "caf\ufffd"
    assert decode_body(b"bad\xff", "text/plain") == "bad\ufffd"


def test_snapshot_summary_preserves_full_response_hash_scope() -> None:
    snap = HttpSnapshot(
        request_method="GET",
        request_url="https://example.test/item",
        request_headers={"Accept": "*/*"},
        status=200,
        reason="OK",
        headers={"content-type": ["text/plain"]},
        body_sample="visible-sample",
        body_len=40,
        body_sample_len=14,
        body_truncated=True,
        body_sha256="abc123",
        client_context="baseline",
    )

    hidden = snapshot_summary(snap, save_body=False)
    saved = snapshot_summary(snap, save_body=True)

    assert hidden["response"]["body_sha256"] == "abc123"
    assert hidden["response"]["body_sha256_scope"] == "full_response"
    assert hidden["response"]["body_len"] == 40
    assert hidden["response"]["body_truncated"] is True
    assert "body_sample" not in hidden["response"]
    assert saved["response"]["body_sample"] == "visible-sample"
    assert saved["response"]["body_sha256_scope"] == "full_response"
