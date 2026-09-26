from __future__ import annotations

import secrets

from .. import owasp
from ..models import Finding, Severity
from ._params import injectable_targets, path_key, with_param
from .base import DetectorContext


class ReflectedXssDetector:
    name = "reflected_xss"

    async def run(self, ctx: DetectorContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()

        for target_url, param, method in injectable_targets(ctx.pages):
            key = (path_key(target_url), param)
            if key in seen:
                continue
            seen.add(key)
            finding = await self._probe(ctx, target_url, param, method)
            if finding is not None:
                findings.append(finding)

        return findings

    async def _probe(self, ctx: DetectorContext, target_url, param, method):
        token = secrets.token_hex(4)
        payload = f'"><vgx{token}>'
        request_url = with_param(target_url, param, payload)

        response = await ctx.client.get(request_url)
        if response is None:
            return None

        if payload in response.text:
            return Finding(
                detector=self.name,
                title="Posible XSS reflejado",
                severity=Severity.HIGH,
                owasp=owasp.A05,
                url=request_url,
                evidence=(
                    f"El parametro '{param}' se refleja sin escapar. "
                    f"La marca '{payload}' aparece intacta en la respuesta."
                ),
                remediation=(
                    "Escapa la salida segun su contexto (HTML, atributo, JS). "
                    "En plantillas de servidor usa escape por defecto y aplica una CSP restrictiva."
                ),
                request_method=method,
                parameter=param,
            )
        return None
