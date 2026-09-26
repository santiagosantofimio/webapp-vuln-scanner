from __future__ import annotations

import json

from argus import owasp
from argus.models import Finding, Severity
from argus.sarif import build_sarif, to_sarif
from argus.scanner import ScanResult
from conftest import make_page


def _result_with_findings():
    findings = [
        Finding("reflected_xss", "Posible XSS reflejado", Severity.HIGH, owasp.A05,
                "http://localhost:8080/s?q=x", "reflejo sin escapar", "escapa la salida", "GET", "q"),
        Finding("cookies", "Cookie sin HttpOnly", Severity.MEDIUM, owasp.A02,
                "http://localhost:8080/", "sin HttpOnly", "marca HttpOnly"),
        Finding("security_headers", "Falta CSP", Severity.MEDIUM, owasp.A02,
                "http://localhost:8080/", "sin CSP", "define una CSP"),
    ]
    return ScanResult(target="http://localhost:8080", pages=[make_page()], findings=findings)


def test_sarif_shape():
    doc = build_sarif(_result_with_findings())
    assert doc["version"] == "2.1.0"
    assert len(doc["runs"]) == 1
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "Argus Sentinel"
    assert len(run["results"]) == 3


def test_sarif_level_mapping():
    run = build_sarif(_result_with_findings())["runs"][0]
    levels = [r["level"] for r in run["results"]]
    assert "error" in levels
    assert "warning" in levels


def test_sarif_rules_deduped_by_detector():
    run = build_sarif(_result_with_findings())["runs"][0]
    rule_ids = [rule["id"] for rule in run["tool"]["driver"]["rules"]]
    assert sorted(rule_ids) == ["cookies", "reflected_xss", "security_headers"]
    for rule in run["tool"]["driver"]["rules"]:
        assert "security-severity" in rule["properties"]


def test_sarif_rule_index_points_to_correct_rule():
    run = build_sarif(_result_with_findings())["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    for res in run["results"]:
        assert rules[res["ruleIndex"]]["id"] == res["ruleId"]


def test_sarif_is_valid_json_and_has_fingerprints():
    run = json.loads(to_sarif(_result_with_findings()))["runs"][0]
    for res in run["results"]:
        assert res["partialFingerprints"]["argusFindingHash/v1"]


def test_sarif_empty_findings():
    result = ScanResult(target="http://localhost:8081", pages=[make_page()], findings=[])
    run = build_sarif(result)["runs"][0]
    assert run["results"] == []
    assert run["tool"]["driver"]["rules"] == []
