from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ScanConfig:
    target: str
    max_depth: int = 2
    max_pages: int = 50
    delay: float = 0.2
    concurrency: int = 5
    timeout: float = 10.0
    request_delay: float = 0.2
    user_agent: str = "Vigia/0.1 (defensive scanner)"
    allow_external_host: bool = False
    verify_tls: bool = True
    authorized_hosts: list[str] = field(default_factory=list)
