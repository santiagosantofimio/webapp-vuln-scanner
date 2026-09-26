from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Credentials:
    username: str
    password: str


@dataclass
class ScanConfig:
    target: str
    max_depth: int = 2
    max_pages: int = 50
    delay: float = 0.2
    concurrency: int = 5
    timeout: float = 10.0
    request_delay: float = 0.2
    user_agent: str = "Argus Sentinel/0.1 (defensive scanner)"
    allow_external_host: bool = False
    verify_tls: bool = True
    authorized_hosts: list[str] = field(default_factory=list)
    login_url: Optional[str] = None
    username_field: str = "username"
    password_field: str = "password"
    credentials: Optional[Credentials] = None
    second_credentials: Optional[Credentials] = None
    check_rate_limit: bool = False
    rate_limit_requests: int = 15
