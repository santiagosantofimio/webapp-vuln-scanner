from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Protocol, runtime_checkable

from ..config import ScanConfig
from ..http_client import HttpClient
from ..models import Finding, Page


@dataclass
class DetectorContext:
    client: HttpClient
    config: ScanConfig
    pages: list[Page]
    second_client: Optional[HttpClient] = None

    @property
    def target(self) -> str:
        return self.config.target


@runtime_checkable
class Detector(Protocol):
    name: str

    async def run(self, ctx: DetectorContext) -> list[Finding]: ...
