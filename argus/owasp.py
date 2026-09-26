from __future__ import annotations

from .models import OwaspCategory

A01 = OwaspCategory("A01:2025", "Broken Access Control")
A02 = OwaspCategory("A02:2025", "Security Misconfiguration")
A03 = OwaspCategory("A03:2025", "Software Supply Chain Failures")
A04 = OwaspCategory("A04:2025", "Cryptographic Failures")
A05 = OwaspCategory("A05:2025", "Injection")
A06 = OwaspCategory("A06:2025", "Insecure Design")
A07 = OwaspCategory("A07:2025", "Authentication Failures")
A08 = OwaspCategory("A08:2025", "Software or Data Integrity Failures")
A09 = OwaspCategory("A09:2025", "Logging and Alerting Failures")
A10 = OwaspCategory("A10:2025", "Mishandling of Exceptional Conditions")

ALL = [A01, A02, A03, A04, A05, A06, A07, A08, A09, A10]
