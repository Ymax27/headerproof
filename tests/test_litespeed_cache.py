from __future__ import annotations

from headerproof.detectors import (
    analyze_header_probe,
    cache_indicators,
    looks_cacheable,
    shared_cache_hit_markers,
)
from headerproof.models import HttpSnapshot


def snap(
    headers: dict[str, str],
    body: str = "",
    request_headers: dict[str, str] | None = None,
    request_url: str = "http://example.test/demo",
    client_context: str = "test-client",
) -> HttpSnapshot:
    return HttpSnapshot(
        "GET",
        request_url,
        request_headers or {},
        status=200,
        reason="OK",
        headers={name.lower(): [value] for name, value in headers.items()},
        body_sample=body,
        client_context=client_context,
    )


def test_litespeed_family_headers_are_recorded_and_hit_is_exact() -> None:
    indicators = cache_indicators(
        snap(
            {
                "X-LiteSpeed-Cache": "hit",
                "X-LSADC-Cache": "miss",
                "X-QC-Cache": "bypass",
            }
        )
    )

    assert "x-litespeed-cache=hit" in indicators
    assert "x-lsadc-cache=miss" in indicators
    assert "x-qc-cache=bypass" in indicators
    assert looks_cacheable(snap({"X-LiteSpeed-Cache": "hit"}))[0] is False

    markers = shared_cache_hit_markers(
        [
            "x-litespeed-cache=hit",
            "x-litespeed-cache=HIT",
            "x-lsadc-cache=hit",
            "x-qc-cache= hit ",
            "x-litespeed-cache=miss",
            "x-litespeed-cache=bypass",
            "x-lsadc-cache=hitter",
            "x-qc-cache=hit, miss",
            "x-litespeed-cache=notahit",
            "x-cache=HIT",
            "cf-cache-status=MISS",
        ]
    )
    assert markers == [
        "x-litespeed-cache=hit",
        "x-litespeed-cache=HIT",
        "x-lsadc-cache=hit",
        "x-qc-cache= hit ",
        "x-cache=HIT",
    ]


def test_litespeed_hit_satisfies_only_the_cache_hit_checks() -> None:
    canary = "pa-scan-litespeed"
    cache_url = "http://example.test/demo?pa_cb=probe"
    control_url = "http://example.test/demo?pa_cb=probe-control"
    clean_before = snap(
        {"Cache-Control": "public, max-age=120", "X-LiteSpeed-Cache": "miss"},
        body="clean",
        request_url=cache_url,
        client_context="clean-before",
    )
    poison = snap(
        {"Cache-Control": "public, max-age=120", "X-LiteSpeed-Cache": "miss"},
        body=f"poison={canary}",
        request_headers={"X-Forwarded-Host": canary},
        request_url=cache_url,
        client_context="poison",
    )
    fresh_control = snap(
        {"Cache-Control": "public, max-age=120", "X-LiteSpeed-Cache": "miss"},
        body="clean-control",
        request_url=control_url,
        client_context="fresh-control",
    )
    victim_hit = snap(
        {"Cache-Control": "public, max-age=120", "X-LiteSpeed-Cache": "hit"},
        body=f"cached={canary}",
        request_url=cache_url,
        client_context="victim",
    )
    victim_miss = snap(
        {"Cache-Control": "public, max-age=120", "X-LiteSpeed-Cache": "miss"},
        body=f"cached={canary}",
        request_url=cache_url,
        client_context="victim",
    )

    confirmed = analyze_header_probe(
        "X-Forwarded-Host",
        canary,
        "probe-litespeed-hit",
        clean_before,
        poison,
        victim_hit,
        fresh_control,
        False,
    )
    finding = next(item for item in confirmed if item["type"] == "cache_poisoning_shared_cache_confirmed")
    checks = finding["evidence"]["state_machine_checks"]
    assert checks["shared_cache_hit_marker_present"] is True
    assert checks["cache_hit_progressed"] is True
    assert finding["evidence"]["shared_cache_hit_markers"] == ["x-litespeed-cache=hit"]
    assert finding["assessment"]["technical_gate"] == "passed"

    missed = analyze_header_probe(
        "X-Forwarded-Host",
        canary,
        "probe-litespeed-miss",
        clean_before,
        poison,
        victim_miss,
        fresh_control,
        False,
    )
    assert not any(item["type"] == "cache_poisoning_shared_cache_confirmed" for item in missed)
    reproduction = next(item for item in missed if item["type"] == "cache_poisoning_cross_request_reproduction")
    assert reproduction["evidence"]["state_machine_checks"]["shared_cache_hit_marker_present"] is False
    assert reproduction["evidence"]["state_machine_checks"]["cache_hit_progressed"] is False
