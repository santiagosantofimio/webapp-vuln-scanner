from __future__ import annotations

from .base import Detector, DetectorContext
from .cookies import CookiesDetector
from .csrf import CsrfDetector
from .info_leak import InfoLeakDetector
from .reflected_xss import ReflectedXssDetector
from .security_headers import SecurityHeadersDetector
from .sensitive_paths import SensitivePathsDetector
from .sql_injection import SqlInjectionDetector
from .transport import TransportDetector


def default_detectors() -> list[Detector]:
    return [
        SecurityHeadersDetector(),
        CookiesDetector(),
        TransportDetector(),
        ReflectedXssDetector(),
        SqlInjectionDetector(),
        CsrfDetector(),
        SensitivePathsDetector(),
        InfoLeakDetector(),
    ]


__all__ = ["Detector", "DetectorContext", "default_detectors"]
