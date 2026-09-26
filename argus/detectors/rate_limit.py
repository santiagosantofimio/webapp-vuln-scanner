from __future__ import annotations

import asyncio
from urllib.parse import urljoin

from .. import owasp
from ..models import Finding, Severity
from .base import DetectorContext


class RateLimitDetector:
    name = "rate_limit"

    async def run(self, ctx: DetectorContext) -> list[Finding]:
        if not ctx.config.check_rate_limit:
            return []

        count = max(1, ctx.config.rate_limit_requests)
        if ctx.config.login_url:
            probe_url = ctx.config.login_url
            category = owasp.A07
            surface = "el endpoint de autenticacion"
        else:
            probe_url = urljoin(ctx.config.target, "/")
            category = owasp.A06
            surface = "el objetivo"

        responses = await asyncio.gather(*(ctx.client.get(probe_url) for _ in range(count)))
        received = [r for r in responses if r is not None]
        if not received:
            return []

        limited = any(
            r.status_code == 429 or "retry-after" in {k.lower() for k in r.headers}
            for r in received
        )
        if limited:
            return []

        statuses = sorted({r.status_code for r in received})
        return [
            Finding(
                detector=self.name,
                title="Sin limitacion de tasa aparente",
                severity=Severity.LOW,
                owasp=category,
                url=probe_url,
                evidence=(
                    f"Tras {len(received)} peticiones a {surface} no se observo respuesta 429 ni "
                    f"cabecera Retry-After (codigos observados: {statuses})."
                ),
                remediation=(
                    "Aplica limitacion de tasa y bloqueo progresivo, especialmente en login y "
                    "endpoints sensibles, para mitigar fuerza bruta y abuso."
                ),
            )
        ]
