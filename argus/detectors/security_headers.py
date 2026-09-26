from __future__ import annotations

from urllib.parse import urlparse

from .. import owasp
from ..models import Finding, Severity
from .base import DetectorContext


REQUIRED_HEADERS = {
    "content-security-policy": (
        Severity.MEDIUM,
        "Define una Content-Security-Policy restrictiva, por ejemplo "
        "\"default-src 'self'\", para limitar el origen de scripts y recursos.",
    ),
    "x-frame-options": (
        Severity.LOW,
        "Agrega 'X-Frame-Options: DENY' o una directiva 'frame-ancestors' en la CSP "
        "para evitar clickjacking.",
    ),
    "x-content-type-options": (
        Severity.LOW,
        "Agrega 'X-Content-Type-Options: nosniff' para impedir el MIME sniffing.",
    ),
    "referrer-policy": (
        Severity.LOW,
        "Agrega 'Referrer-Policy: no-referrer' o 'strict-origin-when-cross-origin'.",
    ),
    "permissions-policy": (
        Severity.INFO,
        "Agrega 'Permissions-Policy' para restringir APIs del navegador (camara, "
        "microfono, geolocalizacion).",
    ),
}


class SecurityHeadersDetector:
    name = "security_headers"

    async def run(self, ctx: DetectorContext) -> list[Finding]:
        findings: list[Finding] = []
        page = _root_page(ctx)
        if page is None:
            return findings

        is_https = urlparse(page.url).scheme == "https"

        for header, (severity, remediation) in REQUIRED_HEADERS.items():
            if header not in page.headers:
                findings.append(
                    Finding(
                        detector=self.name,
                        title=f"Falta la cabecera '{header}'",
                        severity=severity,
                        owasp=owasp.A02,
                        url=page.url,
                        evidence=f"La respuesta no incluye la cabecera '{header}'.",
                        remediation=remediation,
                    )
                )

        hsts = page.headers.get("strict-transport-security")
        if is_https and hsts is None:
            findings.append(
                Finding(
                    detector=self.name,
                    title="Falta la cabecera 'Strict-Transport-Security'",
                    severity=Severity.MEDIUM,
                    owasp=owasp.A02,
                    url=page.url,
                    evidence="El sitio usa HTTPS pero no envia HSTS.",
                    remediation="Agrega 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
                )
            )
        elif is_https and hsts is not None and "max-age=0" in hsts.replace(" ", ""):
            findings.append(
                Finding(
                    detector=self.name,
                    title="'Strict-Transport-Security' con max-age=0",
                    severity=Severity.MEDIUM,
                    owasp=owasp.A02,
                    url=page.url,
                    evidence=f"Cabecera HSTS con valor debil: {hsts}",
                    remediation="Usa un max-age alto (>= 31536000) en HSTS.",
                )
            )

        return findings


def _root_page(ctx: DetectorContext):
    for page in ctx.pages:
        if page.url.rstrip("/") == ctx.config.target.rstrip("/"):
            return page
    return ctx.pages[0] if ctx.pages else None
