from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from headerproof.cli import parse_cli_args
from headerproof.engine import scan_url


class DiscoveryHandler(BaseHTTPRequestHandler):
    cache: dict[str, bytes] = {}

    def log_message(self, _format: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:
        no_cache = "no-cache" in self.headers.get("Cache-Control", "").lower()
        cached = self.cache.get(self.path)
        if cached is not None and not no_cache:
            body = cached
            cache_status = "HIT"
        else:
            scheme = self.headers.get("X-Forwarded-Scheme", "")
            body = (f"scheme={scheme}" if scheme else "scheme=https").encode()
            cache_status = "MISS"
            if not no_cache:
                self.cache[self.path] = body
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Cache-Control", "public, max-age=120")
        self.send_header("X-Cache", cache_status)
        self.end_headers()
        self.wfile.write(body)


def run_fixture(custom_headers: list[str] | None = None) -> dict[str, Any]:
    DiscoveryHandler.cache = {}
    server = ThreadingHTTPServer(("127.0.0.1", 0), DiscoveryHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/vulnerable"
        args = parse_cli_args([url])
        args.enabled_checks = {"cache-poisoning", "header-injection", "content-spoofing"}
        args.header_probe_limit = 5
        args.header = custom_headers or []
        args.per_url_concurrency = 1
        args.concurrency = 1
        args.no_live_alerts = True
        return scan_url(url, args)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)


def test_dynamic_discovery_finds_non_default_header_before_confirmation() -> None:
    result = run_fixture()
    assert result["status"] == "scanned"
    assert result["discovery"]["discovered_headers"] == [
        {"name": "X-Forwarded-Scheme", "reason": "marker_reflected"}
    ]
    confirmed = [
        item
        for item in result["signals"]
        if item["type"] == "cache_poisoning_shared_cache_confirmed"
    ]
    assert len(confirmed) == 1
    assert confirmed[0]["evidence"]["probe_header"] == "X-Forwarded-Scheme"
    discovery_roles = [probe["role"] for probe in result["probes"] if probe["role"].startswith("discovery-")]
    assert discovery_roles.count("discovery-baseline") == 3
    assert "discovery-singleton" in discovery_roles


def test_explicit_header_is_removed_from_discovery_candidates() -> None:
    result = run_fixture(["X-Forwarded-Scheme"])
    assert result["discovery"]["candidate_count"] == 15
    assert result["discovery"]["discovered_headers"] == []
    confirmed = [
        item
        for item in result["signals"]
        if item["type"] == "cache_poisoning_shared_cache_confirmed"
    ]
    assert len(confirmed) == 1
    assert confirmed[0]["evidence"]["probe_header"] == "X-Forwarded-Scheme"
