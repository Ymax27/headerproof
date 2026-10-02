#!/usr/bin/env python3
"""HeaderProof command-line entrypoint."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import sys
import threading
import time
from collections import Counter
from pathlib import Path
from typing import Iterator

from .config import ConfigError, load_config
from .constants import DEFAULT_CHECKS, PRODUCT_NAME, SCHEMA_VERSION, VERSION
from .engine import scan_url
from .input import iter_url_lines, iter_urls, normalise_url
from .metadata import build_metadata
from .output import (
    EvidenceWriter,
    export_findings,
    print_console_summary,
    read_findings,
    reserve_output_dir,
    sarif_payload,
)
from .templates import TemplateError, update_templates
from .transport import HostRateLimiter
from .ui import emit_progress, emit_scan_start

DEFAULT_CONCURRENCY = 16
DEFAULT_TIMEOUT = 2.5
DEFAULT_MAX_BODY = 16384
DEFAULT_PER_URL_CONCURRENCY = 4
DEFAULT_HEADER_PROBE_LIMIT = 5
VALID_SEVERITIES = {"low", "medium", "high", "critical", "info"}

# Stable process contract for shells and CI consumers.
EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_SCAN_ERROR = 2
EXIT_INTERRUPTED = 130


def parse_severity(raw: str) -> set[str]:
    values = {item.strip().lower() for item in raw.split(",") if item.strip()}
    unknown = values - VALID_SEVERITIES
    if unknown:
        raise argparse.ArgumentTypeError(f"unknown severity: {', '.join(sorted(unknown))}")
    return values


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PRODUCT_NAME.lower(),
        description="Evidence-gated scanner for header-driven web security findings.",
    )
    parser.add_argument("--version", action="version", version=f"{PRODUCT_NAME} {VERSION}")
    parser.add_argument("target", nargs="?", help="Single target URL or hostname")
    parser.add_argument("-l", "--list", dest="list_path", help="URL list file; use - for stdin")
    parser.add_argument("-o", "--output", help="Write findings to .json, .jsonl, .md, or .sarif")
    parser.add_argument("-c", "--concurrency", type=int, default=DEFAULT_CONCURRENCY, help="Concurrent URL workers")
    parser.add_argument("-rl", "--rate-limit", type=float, default=0.0, help="Per-host requests per second")
    parser.add_argument("-severity", type=parse_severity, default=set(), help="Comma-separated severity filter")
    parser.add_argument("-silent", action="store_true", help="Only print findings")
    parser.add_argument("-json", action="store_true", help="Print findings as JSONL")
    parser.add_argument("-sarif", action="store_true", help="Print SARIF 2.1.0")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print compact evidence notes")
    parser.add_argument("-timeout", type=float, default=DEFAULT_TIMEOUT, help="Per-request timeout in seconds")
    parser.add_argument("-update-templates", action="store_true", help="Update detector templates")
    parser.add_argument("--no-color", action="store_true", help=argparse.SUPPRESS)
    return parser


def parse_cli_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = build_parser()
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    args = parser.parse_args(raw_argv)

    try:
        config, config_path = load_config()
    except ConfigError as exc:
        parser.error(str(exc))

    def cli_has(*flags: str) -> bool:
        return any(item == flag or item.startswith(flag + "=") for item in raw_argv for flag in flags)

    if "concurrency" in config and not cli_has("-c", "--concurrency"):
        args.concurrency = int(config["concurrency"])
    if "rate_limit" in config and not cli_has("-rl", "--rate-limit"):
        args.rate_limit = float(config["rate_limit"])
    if "timeout" in config and not cli_has("-timeout"):
        args.timeout = float(config["timeout"])
    if "severity" in config and not cli_has("-severity"):
        args.severity = parse_severity(str(config["severity"]))
    args.config_path = str(config_path) if config_path else ""

    if args.target and args.list_path:
        parser.error("target and --list cannot be used together")
    if not args.update_templates and not args.target and not args.list_path and sys.stdin.isatty():
        parser.error("provide a target, --list file, or pipe URLs on stdin")
    if args.json and args.sarif:
        parser.error("-json and -sarif cannot be used together")
    if args.output:
        suffix = Path(args.output).suffix.lower()
        if suffix not in {".json", ".jsonl", ".md", ".sarif"}:
            parser.error("--output must end in .json, .jsonl, .md, or .sarif")

    args.argv = raw_argv
    args.enabled_checks = set(DEFAULT_CHECKS)
    args.fp_mode = "strict"
    args.min_alert_confidence = "medium"
    args.url_timeout = 9.0
    args.max_body = DEFAULT_MAX_BODY
    args.per_url_concurrency = min(DEFAULT_PER_URL_CONCURRENCY, max(1, args.concurrency))
    args.origin_mode = "standard"
    args.header_probe_limit = DEFAULT_HEADER_PROBE_LIMIT
    args.no_preflight = False
    args.no_cache_confirm = False
    args.delay = 0.0

    args.max_urls = 0
    args.follow_redirects = False
    args.save_body_samples = False
    args.no_crlf = False
    args.origin = list(config.get("origins", []))
    args.header = list(config.get("headers", []))
    args.request_headers = dict(config.get("request_headers", {}))
    args.content_param = "pa_reflect"
    args.progress_every = 50
    args.quiet = bool(args.silent or args.json or args.sarif)
    args.no_live_alerts = bool(args.sarif)
    args.severity_filter = set(args.severity)
    args.oob_api = os.environ.get("HEADERPROOF_OOB_API", str(config.get("oob_api", ""))).strip()
    args.oob_domain = os.environ.get(
        "HEADERPROOF_OOB_DOMAIN", str(config.get("oob_domain", ""))
    ).strip(". ")
    args.oob_wait = 0.75

    args.concurrency = max(1, args.concurrency)
    args.per_url_concurrency = max(1, min(args.per_url_concurrency, args.concurrency))
    args.url_timeout = max(0.1, args.url_timeout)
    args.timeout = max(0.05, min(args.timeout, args.url_timeout))
    args.rate_limit = max(0.0, args.rate_limit)
    args.max_body = max(0, args.max_body)
    args.header_probe_limit = max(0, args.header_probe_limit)
    return args


def _input_stream(args: argparse.Namespace, out_dir: Path) -> tuple[Iterator[str], str]:
    if args.target:
        url = normalise_url(args.target)
        if not url:
            raise ValueError(f"invalid target: {args.target}")
        return iter((url,)), args.target

    if args.list_path and args.list_path != "-":
        path = Path(args.list_path).expanduser()
        if not path.exists():
            raise FileNotFoundError(f"input URL file not found: {path}")
        if not path.is_file():
            raise ValueError(f"input path is not a file: {path}")
        return iter(
            iter_urls(
                path,
                max_urls=args.max_urls or None,
                dedup_db=out_dir / "input-dedup.sqlite3",
            )
        ), str(path)

    return iter(iter_url_lines(sys.stdin, max_urls=args.max_urls or None)), "stdin"


def _payload_count(payload: dict[str, object], key: str) -> int:
    value = payload.get(key, 0)
    return value if isinstance(value, int) else 0


def _result_exit_code(payload: dict[str, object], interrupted: bool) -> int:
    if interrupted:
        return EXIT_INTERRUPTED
    if (
        _payload_count(payload, "error")
        or _payload_count(payload, "partial_error")
        or _payload_count(payload, "partial_timeout")
    ):
        return EXIT_SCAN_ERROR
    if _payload_count(payload, "verified_technical_signals"):
        return EXIT_FINDINGS
    return EXIT_CLEAN


def main_from_args(argv: list[str] | None = None) -> int:
    args = parse_cli_args(argv)

    if args.update_templates:
        try:
            count, destination = update_templates()
        except TemplateError as exc:
            print(f"headerproof: {exc}", file=sys.stderr)
            return EXIT_SCAN_ERROR
        print(f"headerproof: updated {count} template file(s) in {destination}", file=sys.stderr)
        return EXIT_CLEAN

    try:
        out_dir = reserve_output_dir()
        url_iter, input_label = _input_stream(args, out_dir)
    except (FileNotFoundError, ValueError, OSError) as exc:
        print(f"headerproof: {exc}", file=sys.stderr)
        return EXIT_SCAN_ERROR

    first_url = next(url_iter, None)
    if not first_url:
        print("headerproof: no usable URLs found", file=sys.stderr)
        return EXIT_SCAN_ERROR

    metadata = build_metadata(args, input_label, 0)
    writer = EvidenceWriter(out_dir, metadata)
    args.request_semaphore = threading.BoundedSemaphore(args.concurrency)
    args.rate_limiter = HostRateLimiter(args.rate_limit)
    emit_scan_start(input_label, "streaming", args, out_dir)

    completed = 0
    submitted = 0
    total_signals = 0
    filtered_signals = 0
    statuses: Counter[str] = Counter()
    started_at = time.monotonic()
    interrupted = False
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency)
    futures: dict[concurrent.futures.Future, str] = {}
    exhausted = False

    def submit_url(item_url: str) -> None:
        nonlocal submitted
        futures[executor.submit(scan_url, item_url, args)] = item_url
        submitted += 1

    try:
        submit_url(first_url)
        while futures:
            while not exhausted and len(futures) < args.concurrency:
                next_url = next(url_iter, None)
                if next_url is None:
                    exhausted = True
                    break
                submit_url(next_url)

            done, _ = concurrent.futures.wait(
                futures,
                return_when=concurrent.futures.FIRST_COMPLETED,
            )
            for future in done:
                url = futures.pop(future)
                try:
                    item = future.result()
                except Exception as exc:  # noqa: BLE001
                    item = {
                        "schema_version": SCHEMA_VERSION,
                        "record_type": "result",
                        "url": url,
                        "status": "error",
                        "baseline": None,

                        "probes": [],
                        "observations": [],
                        "signals": [],
                        "filtered_signals": 0,
                        "duplicate_signals": 0,
                        "errors": [
                            {
                                "error_type": "scan_worker_error",
                                "message": f"{type(exc).__name__}: {exc}",
                            }
                        ],
                        "coverage": [],
                    }

                writer.append_result(item)
                completed += 1
                statuses[item["status"]] += 1
                total_signals += len(item["signals"])
                filtered_signals += int(item.get("filtered_signals", 0))
                if not args.quiet and args.progress_every and completed % args.progress_every == 0:
                    emit_progress(
                        completed,
                        submitted,
                        started_at,
                        statuses,
                        total_signals,
                        filtered_signals,
                    )
    except KeyboardInterrupt:
        interrupted = True
        for future in futures:
            future.cancel()
    finally:
        executor.shutdown(wait=not interrupted, cancel_futures=interrupted)

    metadata["url_count"] = submitted
    payload = writer.finalize()

    if args.output:
        try:
            export_findings(out_dir, Path(args.output).expanduser())
        except (OSError, ValueError) as exc:
            print(f"headerproof: cannot write output: {exc}", file=sys.stderr)
            return EXIT_SCAN_ERROR

    if args.sarif:
        print(json.dumps(sarif_payload(read_findings(out_dir)), indent=2, sort_keys=True))
    elif not args.silent and not args.json:
        print_console_summary(payload, out_dir, False)

    return _result_exit_code(payload, interrupted)


def main() -> int:
    argv = sys.argv[1:]
    if argv and argv[0] == "oob-server":
        from .oob import run_oob_server

        return run_oob_server(argv[1:])
    return main_from_args(argv)
