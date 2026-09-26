from __future__ import annotations

import re
import secrets
from urllib.parse import urljoin, urlsplit, urlunsplit

from .. import owasp
from ..models import Finding, Severity
from .base import DetectorContext


TRACE_SIGNATURES = [
    r"Exception:",
    r"\bat [\w.$]+\([\w.]+\.java:\d+\)",
    r"Traceback \(most recent call last\)",
    r"org\.springframework\.",
    r"java\.lang\.\w+Exception",
    r'"trace"\s*:',
    r"NumberFormatException",
]

SERVER_VERSION = re.compile(r"\d+\.\d+")


class InfoLeakDetector:
    name = "info_leak"

    async def run(self, ctx: DetectorContext) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._server_headers(ctx))
        findings.extend(await self._error_pages(ctx))
        return findings

    def _server_headers(self, ctx: DetectorContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for page in ctx.pages:
            server = page.headers.get("server")
            powered = page.headers.get("x-powered-by")
            for header_name, value in (("Server", server), ("X-Powered-By", powered)):
                if not value or value in seen:
                    continue
                if header_name == "Server" and not SERVER_VERSION.search(value):
                    continue
                seen.add(value)
                findings.append(
                    Finding(
                        detector=self.name,
                        title=f"La cabecera '{header_name}' revela software y version",
                        severity=Severity.LOW,
                        owasp=owasp.A02,
                        url=page.url,
                        evidence=f"{header_name}: {value}",
                        remediation=(
                            f"Oculta la version en la cabecera '{header_name}' para no facilitar "
                            "el reconocimiento de vulnerabilidades conocidas."
                        ),
                    )
                )
        return findings

    async def _error_pages(self, ctx: DetectorContext) -> list[Finding]:
        findings: list[Finding] = []
        marker = secrets.token_hex(3)
        candidates = self._error_candidates(ctx, marker)
        for url in candidates:
            response = await ctx.client.get(url)
            if response is None:
                continue
            signature = _find_trace(response.text)
            if signature:
                findings.append(
                    Finding(
                        detector=self.name,
                        title="Pagina de error con traza completa",
                        severity=Severity.MEDIUM,
                        owasp=owasp.A02,
                        url=url,
                        evidence=(
                            f"La respuesta de error expone detalles internos "
                            f"(coincidencia con '{signature}')."
                        ),
                        remediation=(
                            "Devuelve paginas de error genericas. No incluyas mensaje, excepcion "
                            "ni stack trace en la respuesta al cliente."
                        ),
                    )
                )
                break
        return findings

    def _error_candidates(self, ctx: DetectorContext, marker: str) -> list[str]:
        urls: list[str] = []
        seen: set[str] = set()
        for page in ctx.pages:
            parts = urlsplit(page.url)
            segments = parts.path.split("/")
            for index, segment in enumerate(segments):
                if not segment.isdigit():
                    continue
                mutated = list(segments)
                mutated[index] = f"vg{marker}"
                candidate = urlunsplit((parts.scheme, parts.netloc, "/".join(mutated), "", ""))
                if candidate not in seen:
                    seen.add(candidate)
                    urls.append(candidate)
        fallback = urljoin(ctx.config.target, f"/vg-{marker}-not-found")
        if fallback not in seen:
            urls.append(fallback)
        return urls[:6]


def _find_trace(text: str):
    for pattern in TRACE_SIGNATURES:
        if re.search(pattern, text):
            return pattern
    return None
