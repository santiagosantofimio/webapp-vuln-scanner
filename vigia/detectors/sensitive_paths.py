from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Optional
from urllib.parse import urljoin

from .. import owasp
from ..models import Finding, OwaspCategory, Severity
from .base import DetectorContext


@dataclass
class PathProbe:
    path: str
    owasp: OwaspCategory
    severity: Severity
    title: str
    remediation: str
    signature: Callable[[object], Optional[str]]
    display: Optional[str] = None
    follow_redirects: bool = False


def _actuator_env(response) -> Optional[str]:
    if response.status_code == 200 and re.search(r'"(activeProfiles|propertySources)"', response.text):
        return "El endpoint devuelve variables de entorno y configuracion."
    return None


def _actuator_beans(response) -> Optional[str]:
    if response.status_code == 200 and re.search(r'"(beans|contexts)"', response.text):
        return "El endpoint describe todos los beans de la aplicacion."
    return None


def _h2_console(response) -> Optional[str]:
    if response.status_code == 200 and re.search(r"H2 Console|login\.jsp|webAllowOthers", response.text, re.IGNORECASE):
        return "La consola H2 responde y es accesible."
    return None


def _git_head(response) -> Optional[str]:
    if response.status_code == 200 and re.match(r"ref:\s+refs/", response.text.strip()):
        return "El repositorio Git es accesible: /.git/HEAD expone la rama actual."
    return None


def _dotenv(response) -> Optional[str]:
    if response.status_code != 200:
        return None
    if "html" in response.headers.get("content-type", "").lower():
        return None
    if re.search(r"(?m)^[A-Z0-9_]+=", response.text) or re.search(r"(SECRET|API_KEY|PASSWORD|TOKEN)", response.text):
        return "El archivo .env es accesible y expone variables sensibles."
    return None


def _admin_open(response) -> Optional[str]:
    if response.status_code == 200 and not re.search(r"login|iniciar sesion|password|contrase", response.text, re.IGNORECASE):
        return "El panel /admin responde 200 sin exigir autenticacion."
    return None


PROBES = [
    PathProbe(
        "/actuator/env", owasp.A02, Severity.HIGH,
        "Endpoint de Actuator '/actuator/env' expuesto",
        "Restringe los endpoints de Actuator: expone solo '/actuator/health' y protege el resto con autenticacion.",
        _actuator_env,
    ),
    PathProbe(
        "/actuator/beans", owasp.A02, Severity.MEDIUM,
        "Endpoint de Actuator '/actuator/beans' expuesto",
        "Restringe los endpoints de Actuator: no expongas la estructura interna de la aplicacion.",
        _actuator_beans,
    ),
    PathProbe(
        "/h2-console", owasp.A02, Severity.HIGH,
        "Consola H2 accesible",
        "Deshabilita la consola H2 en produccion (spring.h2.console.enabled=false).",
        _h2_console, follow_redirects=True,
    ),
    PathProbe(
        "/.git/HEAD", owasp.A02, Severity.HIGH,
        "Repositorio Git expuesto",
        "No publiques el directorio .git; bloquea su acceso en el servidor web.",
        _git_head, display="/.git/",
    ),
    PathProbe(
        "/.env", owasp.A02, Severity.HIGH,
        "Archivo .env expuesto",
        "No sirvas archivos de configuracion como .env; muevelos fuera de la raiz web.",
        _dotenv,
    ),
    PathProbe(
        "/admin", owasp.A01, Severity.HIGH,
        "Panel de administracion accesible sin autenticacion",
        "Exige autenticacion y autorizacion por rol en las rutas administrativas.",
        _admin_open,
    ),
]


class SensitivePathsDetector:
    name = "sensitive_paths"

    async def run(self, ctx: DetectorContext) -> list[Finding]:
        findings: list[Finding] = []
        base = ctx.config.target

        for probe in PROBES:
            url = urljoin(base, probe.path)
            response = await ctx.client.get(url, follow_redirects=probe.follow_redirects)
            if response is None:
                continue
            evidence = probe.signature(response)
            if evidence is None:
                continue
            findings.append(
                Finding(
                    detector=self.name,
                    title=probe.title,
                    severity=probe.severity,
                    owasp=probe.owasp,
                    url=urljoin(base, probe.display or probe.path),
                    evidence=evidence,
                    remediation=probe.remediation,
                )
            )

        return findings
