from __future__ import annotations

import json
from pathlib import Path

from headerproof.cli import (
    EXIT_CLEAN,
    EXIT_FINDINGS,
    EXIT_INTERRUPTED,
    EXIT_SCAN_ERROR,
    _result_exit_code,
)
from headerproof.output import export_findings, sarif_payload


def finding() -> dict[str, object]:
    return {
        "url": "https://example.com/demo",
        "type": "response_splitting_crlf_candidate",
        "check": "header-injection",
        "title": "CRLF query probe influenced response headers",
        "severity": "high",
        "confidence": "high",
        "assessment": {"state": "reproduced"},
    }


def test_sarif_payload_contains_rule_and_location() -> None:
    payload = sarif_payload([finding()])

    run = payload["runs"][0]
    assert payload["version"] == "2.1.0"
    assert run["tool"]["driver"]["name"] == "HeaderProof"
    assert run["results"][0]["ruleId"] == "response_splitting_crlf_candidate"
    assert run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == (
        "https://example.com/demo"
    )


def test_export_sarif_uses_signal_records(tmp_path: Path) -> None:
    out_dir = tmp_path / "run"
    out_dir.mkdir()
    (out_dir / "signals.jsonl").write_text(json.dumps(finding()) + "\n")
    output = tmp_path / "findings.sarif"

    export_findings(out_dir, output)

    payload = json.loads(output.read_text())
    assert payload["runs"][0]["results"][0]["level"] == "error"
    assert payload["runs"][0]["tool"]["driver"]["rules"][0]["id"] == "response_splitting_crlf_candidate"


def test_ci_exit_code_contract_is_stable() -> None:
    clean = {"error": 0, "partial_error": 0, "partial_timeout": 0, "verified_technical_signals": 0}
    findings = {"error": 0, "partial_error": 0, "partial_timeout": 0, "verified_technical_signals": 1}
    error = {"error": 1, "partial_error": 0, "partial_timeout": 0, "verified_technical_signals": 0}
    partial_error = {"error": 0, "partial_error": 1, "partial_timeout": 0, "verified_technical_signals": 1}
    partial_timeout = {"error": 0, "partial_error": 0, "partial_timeout": 1, "verified_technical_signals": 0}
    mixed_timeout = {"error": 0, "partial_error": 0, "partial_timeout": 1, "verified_technical_signals": 2}

    assert _result_exit_code(clean, False) == EXIT_CLEAN == 0
    assert _result_exit_code(findings, False) == EXIT_FINDINGS == 1
    assert _result_exit_code(error, False) == EXIT_SCAN_ERROR == 2
    assert _result_exit_code(partial_error, False) == EXIT_SCAN_ERROR == 2
    assert _result_exit_code(partial_timeout, False) == EXIT_SCAN_ERROR == 2
    assert _result_exit_code(mixed_timeout, False) == EXIT_SCAN_ERROR == 2
    assert _result_exit_code(clean, True) == EXIT_INTERRUPTED == 130
