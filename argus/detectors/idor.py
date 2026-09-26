from __future__ import annotations

from urllib.parse import urlsplit

from .. import owasp
from ..models import Finding, Severity
from .base import DetectorContext

MAX_PROBES = 12
MIN_BODY = 200


class IdorDetector:
    name = "idor"

    async def run(self, ctx: DetectorContext) -> list[Finding]:
        if ctx.second_client is None:
            return []

        findings: list[Finding] = []
        login_path = urlsplit(ctx.config.login_url).path if ctx.config.login_url else "/login"
        probed = 0

        for page in ctx.pages:
            if probed >= MAX_PROBES:
                break
            if page.status_code != 200:
                continue
            if not _has_id_segment(page.url):
                continue

            probed += 1
            other = await ctx.second_client.get(page.url, follow_redirects=True)
            if other is None or other.status_code != 200:
                continue
            if urlsplit(str(other.url)).path == login_path:
                continue
            if len(other.text) < MIN_BODY:
                continue

            findings.append(
                Finding(
                    detector=self.name,
                    title="Posible IDOR (acceso a recurso por id desde otra sesion)",
                    severity=Severity.MEDIUM,
                    owasp=owasp.A01,
                    url=page.url,
                    evidence=(
                        "Un recurso identificado por id, accesible en la primera sesion, tambien "
                        "respondio 200 a una segunda sesion distinta. Requiere confirmacion manual: "
                        "verifica si el recurso deberia ser privado de la primera cuenta."
                    ),
                    remediation=(
                        "Verifica la propiedad del recurso en el servidor: cada peticion por id debe "
                        "comprobar que el recurso pertenece al usuario autenticado, no solo que hay sesion."
                    ),
                )
            )

        return findings


def _has_id_segment(url: str) -> bool:
    return any(segment.isdigit() for segment in urlsplit(url).path.split("/"))
