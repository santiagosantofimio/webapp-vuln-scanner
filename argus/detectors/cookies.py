from __future__ import annotations

from http.cookies import SimpleCookie
from urllib.parse import urlparse

from .. import owasp
from ..models import Finding, Severity
from .base import DetectorContext


class CookiesDetector:
    name = "cookies"

    async def run(self, ctx: DetectorContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for page in ctx.pages:
            raw = page.headers.get("set-cookie")
            if not raw:
                continue
            is_https = urlparse(page.url).scheme == "https"
            for cookie_name, attrs in _parse_cookies(raw):
                if cookie_name in seen:
                    continue
                seen.add(cookie_name)
                findings.extend(self._check_cookie(page.url, cookie_name, attrs, is_https))

        return findings

    def _check_cookie(self, url, cookie_name, attrs, is_https) -> list[Finding]:
        findings: list[Finding] = []
        lower = {k.lower(): v for k, v in attrs.items()}

        if "httponly" not in lower:
            findings.append(
                Finding(
                    detector=self.name,
                    title=f"Cookie '{cookie_name}' sin HttpOnly",
                    severity=Severity.MEDIUM,
                    owasp=owasp.A02,
                    url=url,
                    evidence=f"Set-Cookie de '{cookie_name}' sin la bandera HttpOnly.",
                    remediation="Marca la cookie como HttpOnly para que no sea legible por JavaScript.",
                )
            )

        if "secure" not in lower and is_https:
            findings.append(
                Finding(
                    detector=self.name,
                    title=f"Cookie '{cookie_name}' sin Secure",
                    severity=Severity.MEDIUM,
                    owasp=owasp.A02,
                    url=url,
                    evidence=f"Set-Cookie de '{cookie_name}' sin la bandera Secure en un sitio HTTPS.",
                    remediation="Marca la cookie como Secure para que solo viaje por HTTPS.",
                )
            )

        samesite = lower.get("samesite")
        if samesite is None:
            findings.append(
                Finding(
                    detector=self.name,
                    title=f"Cookie '{cookie_name}' sin SameSite",
                    severity=Severity.LOW,
                    owasp=owasp.A02,
                    url=url,
                    evidence=f"Set-Cookie de '{cookie_name}' sin atributo SameSite.",
                    remediation="Agrega 'SameSite=Lax' o 'SameSite=Strict' para mitigar CSRF.",
                )
            )
        elif samesite.lower() == "none" and "secure" not in lower:
            findings.append(
                Finding(
                    detector=self.name,
                    title=f"Cookie '{cookie_name}' con SameSite=None sin Secure",
                    severity=Severity.MEDIUM,
                    owasp=owasp.A02,
                    url=url,
                    evidence=f"'{cookie_name}' usa SameSite=None pero no es Secure.",
                    remediation="SameSite=None obliga a marcar la cookie como Secure.",
                )
            )

        return findings


def _parse_cookies(raw: str):
    result = []
    for chunk in raw.split("\n"):
        chunk = chunk.strip()
        if not chunk:
            continue
        jar = SimpleCookie()
        try:
            jar.load(chunk)
        except Exception:
            continue
        for name, morsel in jar.items():
            attrs = {k: v for k, v in morsel.items() if v != ""}
            if morsel["httponly"]:
                attrs["httponly"] = True
            if morsel["secure"]:
                attrs["secure"] = True
            result.append((name, attrs))
    return result
