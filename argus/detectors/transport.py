from __future__ import annotations

from urllib.parse import urlparse, urlunparse

from .. import owasp
from ..models import Finding, Severity
from .base import DetectorContext


class TransportDetector:
    name = "transport"

    async def run(self, ctx: DetectorContext) -> list[Finding]:
        findings: list[Finding] = []
        parsed = urlparse(ctx.config.target)

        if parsed.scheme == "http":
            findings.append(
                Finding(
                    detector=self.name,
                    title="El sitio se sirve por HTTP sin cifrar",
                    severity=Severity.MEDIUM,
                    owasp=owasp.A04,
                    url=ctx.config.target,
                    evidence=f"El objetivo usa el esquema '{parsed.scheme}'.",
                    remediation="Sirve el sitio por HTTPS con un certificado valido.",
                )
            )
            findings.extend(await self._check_redirect(ctx, parsed))

        return findings

    async def _check_redirect(self, ctx: DetectorContext, parsed) -> list[Finding]:
        response = await ctx.client.get(urlunparse(parsed))
        if response is None:
            return []

        location = response.headers.get("location", "")
        redirects_to_https = (
            response.status_code in (301, 302, 307, 308)
            and location.lower().startswith("https://")
        )
        if redirects_to_https:
            return []

        return [
            Finding(
                detector=self.name,
                title="HTTP no redirige a HTTPS",
                severity=Severity.MEDIUM,
                owasp=owasp.A04,
                url=urlunparse(parsed),
                evidence=(
                    f"La respuesta HTTP fue {response.status_code} "
                    f"con Location='{location or 'ausente'}'."
                ),
                remediation="Redirige todo el trafico HTTP a HTTPS con un 301.",
            )
        ]
