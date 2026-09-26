from __future__ import annotations

import re

from .. import owasp
from ..models import Finding, Severity
from ._params import injectable_targets, path_key, with_param
from .base import DetectorContext


ERROR_SIGNATURES = [
    r"SQL syntax.*MySQL",
    r"Warning.*\bmysqli?_",
    r"org\.h2\.jdbc",
    r"org\.postgresql\.util\.PSQLException",
    r"ORA-\d{5}",
    r"Microsoft OLE DB Provider for SQL Server",
    r"Unclosed quotation mark after the character string",
    r"SQLite/JDBCDriver",
    r"java\.sql\.SQLException",
    r"JdbcSQLSyntaxErrorException",
    r"Syntax error in SQL statement",
    r"quoted string not properly terminated",
]

TRUE_PAYLOAD = "' OR '1'='1"
FALSE_PAYLOAD = "' AND '1'='2"
QUOTE_PAYLOAD = "'"


class SqlInjectionDetector:
    name = "sql_injection"

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
        quote_response = await ctx.client.get(with_param(target_url, param, QUOTE_PAYLOAD))
        if quote_response is not None:
            signature = _find_signature(quote_response.text)
            if signature:
                return Finding(
                    detector=self.name,
                    title="Posible inyeccion SQL (error de base de datos)",
                    severity=Severity.HIGH,
                    owasp=owasp.A05,
                    url=with_param(target_url, param, QUOTE_PAYLOAD),
                    evidence=(
                        f"Al inyectar una comilla en '{param}' la respuesta revela "
                        f"un error SQL: coincidencia con '{signature}'."
                    ),
                    remediation=(
                        "Usa consultas parametrizadas (prepared statements). Nunca concatenes "
                        "entrada del usuario dentro del SQL."
                    ),
                    request_method=method,
                    parameter=param,
                )

        return await self._boolean_probe(ctx, target_url, param, method)

    async def _boolean_probe(self, ctx: DetectorContext, target_url, param, method):
        true_response = await ctx.client.get(with_param(target_url, param, TRUE_PAYLOAD))
        false_response = await ctx.client.get(with_param(target_url, param, FALSE_PAYLOAD))
        if true_response is None or false_response is None:
            return None
        if true_response.status_code != 200 or false_response.status_code != 200:
            return None

        true_len = len(true_response.text)
        false_len = len(false_response.text)
        if true_len == 0:
            return None

        difference = abs(true_len - false_len) / max(true_len, 1)
        if true_len > false_len and difference >= 0.30:
            return Finding(
                detector=self.name,
                title="Posible inyeccion SQL basada en booleanos",
                severity=Severity.MEDIUM,
                owasp=owasp.A05,
                url=with_param(target_url, param, TRUE_PAYLOAD),
                evidence=(
                    f"El parametro '{param}' cambia el tamano de la respuesta segun una "
                    f"condicion booleana: verdadera={true_len} bytes, falsa={false_len} bytes."
                ),
                remediation=(
                    "Usa consultas parametrizadas (prepared statements). Nunca concatenes "
                    "entrada del usuario dentro del SQL."
                ),
                request_method=method,
                parameter=param,
            )
        return None


def _find_signature(text: str):
    for pattern in ERROR_SIGNATURES:
        if re.search(pattern, text, re.IGNORECASE):
            return pattern
    return None
