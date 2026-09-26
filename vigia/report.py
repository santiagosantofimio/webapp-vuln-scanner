from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .models import Finding, Severity
from .scanner import ScanResult

_TEMPLATE_DIR = Path(__file__).parent / "templates"

SEVERITY_ORDER = [Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

SEVERITY_LABELS = {
    Severity.HIGH: "Alta",
    Severity.MEDIUM: "Media",
    Severity.LOW: "Baja",
    Severity.INFO: "Informativa",
}


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {severity.value: 0 for severity in SEVERITY_ORDER}
    for finding in findings:
        counts[finding.severity.value] += 1
    return counts


def build_summary(result: ScanResult) -> dict:
    findings = result.sorted_findings()
    return {
        "target": result.target,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "pages_crawled": len(result.pages),
        "total_findings": len(findings),
        "counts": severity_counts(findings),
    }


def to_json(result: ScanResult) -> str:
    payload = {
        "summary": build_summary(result),
        "findings": [finding.to_dict() for finding in result.sorted_findings()],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def to_html(result: ScanResult) -> str:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "j2"]),
    )
    template = env.get_template("report.html.j2")
    findings = result.sorted_findings()
    return template.render(
        summary=build_summary(result),
        findings=findings,
        severity_labels=SEVERITY_LABELS,
        severity_order=SEVERITY_ORDER,
    )


def write_reports(result: ScanResult, json_path: str | None, html_path: str | None) -> None:
    if json_path:
        Path(json_path).write_text(to_json(result), encoding="utf-8")
    if html_path:
        Path(html_path).write_text(to_html(result), encoding="utf-8")
