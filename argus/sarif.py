from __future__ import annotations

import hashlib
import json

from . import __version__
from .models import Finding, Severity
from .scanner import ScanResult

SARIF_LEVEL = {
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}

SECURITY_SEVERITY = {
    Severity.HIGH: "8.5",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}

INFORMATION_URI = "https://github.com/santiagosantofimio/webapp-vuln-scanner"
OWASP_HELP_URI = "https://owasp.org/Top10/"


def _fingerprint(finding: Finding) -> str:
    raw = "|".join([finding.detector, finding.title, finding.url, finding.parameter or ""])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _build_rules(findings: list[Finding]) -> tuple[list[dict], dict[str, int]]:
    index: dict[str, int] = {}
    rules: list[dict] = []
    top_severity: dict[str, Severity] = {}
    owasp_tags: dict[str, set[str]] = {}
    descriptions: dict[str, str] = {}

    for finding in findings:
        rule_id = finding.detector
        if rule_id not in index:
            index[rule_id] = len(rules)
            rules.append({})
            top_severity[rule_id] = finding.severity
            owasp_tags[rule_id] = set()
            descriptions[rule_id] = finding.title
        if finding.severity.rank > top_severity[rule_id].rank:
            top_severity[rule_id] = finding.severity
        owasp_tags[rule_id].add(finding.owasp.code)

    for rule_id, position in index.items():
        severity = top_severity[rule_id]
        rules[position] = {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": rule_id.replace("_", " ").title()},
            "fullDescription": {"text": descriptions[rule_id]},
            "helpUri": OWASP_HELP_URI,
            "defaultConfiguration": {"level": SARIF_LEVEL[severity]},
            "properties": {
                "tags": ["security"] + sorted(owasp_tags[rule_id]),
                "security-severity": SECURITY_SEVERITY[severity],
            },
        }

    return rules, index


def _result(finding: Finding, rule_id: str, rule_index: int) -> dict:
    return {
        "ruleId": rule_id,
        "ruleIndex": rule_index,
        "level": SARIF_LEVEL[finding.severity],
        "message": {"text": f"{finding.title}. {finding.evidence}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.url},
                    "region": {"startLine": 1},
                }
            }
        ],
        "partialFingerprints": {"argusFindingHash/v1": _fingerprint(finding)},
        "properties": {
            "owasp": f"{finding.owasp.code} {finding.owasp.name}",
            "severity": finding.severity.value,
            "method": finding.request_method,
            "parameter": finding.parameter,
            "remediation": finding.remediation,
        },
    }


def build_sarif(result: ScanResult) -> dict:
    findings = result.sorted_findings()
    rules, index = _build_rules(findings)
    results = [_result(f, f.detector, index[f.detector]) for f in findings]
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Argus Sentinel",
                        "version": __version__,
                        "informationUri": INFORMATION_URI,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def to_sarif(result: ScanResult) -> str:
    return json.dumps(build_sarif(result), indent=2, ensure_ascii=False)
