from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Optional


class Severity(enum.Enum):
    INFO = "info"
    LOW = "baja"
    MEDIUM = "media"
    HIGH = "alta"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
}


@dataclass(frozen=True)
class OwaspCategory:
    code: str
    name: str


@dataclass
class Finding:
    detector: str
    title: str
    severity: Severity
    owasp: OwaspCategory
    url: str
    evidence: str
    remediation: str
    request_method: str = "GET"
    parameter: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "detector": self.detector,
            "title": self.title,
            "severity": self.severity.value,
            "owasp": {"code": self.owasp.code, "name": self.owasp.name},
            "url": self.url,
            "method": self.request_method,
            "parameter": self.parameter,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


@dataclass
class FormField:
    name: str
    field_type: str
    value: str = ""


@dataclass
class HtmlForm:
    action: str
    method: str
    fields: list[FormField] = field(default_factory=list)

    def has_field_matching(self, needle: str) -> bool:
        needle = needle.lower()
        return any(needle in f.name.lower() for f in self.fields)


@dataclass
class Page:
    url: str
    status_code: int
    headers: dict[str, str]
    body: str
    content_type: str
    forms: list[HtmlForm] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    query_params: dict[str, str] = field(default_factory=dict)
