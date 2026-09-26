from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from .authorization import ensure_authorized
from .config import ScanConfig
from .crawler import crawl
from .detectors import DetectorContext, default_detectors
from .http_client import HttpClient
from .models import Finding, Page


@dataclass
class ScanResult:
    target: str
    pages: list[Page]
    findings: list[Finding] = field(default_factory=list)

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.severity.rank, reverse=True)


async def run_scan(config: ScanConfig) -> ScanResult:
    ensure_authorized(config.target, config.allow_external_host, config.authorized_hosts)

    async with HttpClient(config) as client:
        pages = await crawl(client, config)
        ctx = DetectorContext(client=client, config=config, pages=pages)

        detectors = default_detectors()
        results = await asyncio.gather(*(detector.run(ctx) for detector in detectors))

    findings: list[Finding] = []
    for detector_findings in results:
        findings.extend(detector_findings)

    return ScanResult(target=config.target, pages=pages, findings=findings)
