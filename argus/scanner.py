from __future__ import annotations

import asyncio
from contextlib import AsyncExitStack
from dataclasses import dataclass, field

from .auth import login
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
    notes: list[str] = field(default_factory=list)

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.severity.rank, reverse=True)


async def run_scan(config: ScanConfig) -> ScanResult:
    ensure_authorized(config.target, config.allow_external_host, config.authorized_hosts)

    notes: list[str] = []

    async with AsyncExitStack() as stack:
        client = await stack.enter_async_context(HttpClient(config))

        login_pages: list[Page] = []
        if config.credentials is not None:
            result = await login(client, config, config.credentials)
            notes.append(result.message)
            if result.page is not None:
                login_pages.append(result.page)

        second_client = None
        if config.second_credentials is not None:
            second_client = await stack.enter_async_context(HttpClient(config))
            result = await login(second_client, config, config.second_credentials)
            notes.append(f"Segunda sesion: {result.message}")

        pages = login_pages + await crawl(client, config)
        ctx = DetectorContext(
            client=client,
            config=config,
            pages=pages,
            second_client=second_client,
        )

        detectors = default_detectors()
        results = await asyncio.gather(*(detector.run(ctx) for detector in detectors))

    findings: list[Finding] = []
    for detector_findings in results:
        findings.extend(detector_findings)

    return ScanResult(target=config.target, pages=pages, findings=findings, notes=notes)
