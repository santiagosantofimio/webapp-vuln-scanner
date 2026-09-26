from __future__ import annotations

from .. import owasp
from ..models import Finding, Severity
from .base import DetectorContext


TOKEN_HINTS = ("csrf", "xsrf", "_token", "authenticity", "nonce", "anti-forgery", "requestverificationtoken")


class CsrfDetector:
    name = "csrf"

    async def run(self, ctx: DetectorContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for page in ctx.pages:
            for form in page.forms:
                if form.method != "POST":
                    continue
                if form.action in seen:
                    continue
                seen.add(form.action)
                if not self._has_token(form):
                    findings.append(
                        Finding(
                            detector=self.name,
                            title="Formulario POST sin token anti-CSRF",
                            severity=Severity.MEDIUM,
                            owasp=owasp.A01,
                            url=page.url,
                            evidence=(
                                f"El formulario que envia a '{form.action}' no incluye "
                                "ningun campo de token anti-CSRF."
                            ),
                            remediation=(
                                "Incluye un token anti-CSRF por sesion en cada formulario que "
                                "modifique estado y validalo en el servidor. Complementa con "
                                "cookies SameSite."
                            ),
                            request_method="POST",
                        )
                    )

        return findings

    def _has_token(self, form) -> bool:
        return any(hint in field.name.lower() for field in form.fields for hint in TOKEN_HINTS)
