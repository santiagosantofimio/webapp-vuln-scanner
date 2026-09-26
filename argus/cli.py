from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from .authorization import AuthorizationError
from .config import Credentials, ScanConfig
from .models import Severity
from .report import SEVERITY_LABELS, SEVERITY_ORDER, severity_counts, write_reports
from .scanner import ScanResult, run_scan

SEVERITY_BY_NAME = {
    "info": Severity.INFO,
    "baja": Severity.LOW,
    "media": Severity.MEDIUM,
    "alta": Severity.HIGH,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="argus",
        description="Argus Sentinel: escáner de vulnerabilidades web defensivo y no destructivo.",
    )
    parser.add_argument("target", help="URL objetivo, por ejemplo http://localhost:8080")
    parser.add_argument("--max-depth", type=int, default=2, help="Profundidad máxima del rastreo")
    parser.add_argument("--max-pages", type=int, default=50, help="Número máximo de páginas a rastrear")
    parser.add_argument("--delay", type=float, default=0.2, help="Retardo entre peticiones en segundos")
    parser.add_argument("--concurrency", type=int, default=5, help="Peticiones concurrentes máximas")
    parser.add_argument("--timeout", type=float, default=10.0, help="Timeout por petición en segundos")
    parser.add_argument("--json", dest="json_path", help="Ruta para el reporte JSON")
    parser.add_argument("--html", dest="html_path", help="Ruta para el reporte HTML")
    parser.add_argument("--sarif", dest="sarif_path", help="Ruta para el reporte SARIF 2.1.0 (GitHub code scanning)")
    parser.add_argument(
        "--i-own-this",
        action="store_true",
        help="Confirma que eres dueño del objetivo o tienes autorización escrita (necesario para hosts no locales)",
    )
    parser.add_argument(
        "--authorized-hosts",
        help="Ruta a un archivo con hosts autorizados, uno por línea",
    )
    parser.add_argument(
        "--no-verify-tls",
        action="store_true",
        help="No verificar certificados TLS (solo para laboratorios locales)",
    )
    parser.add_argument(
        "--fail-on",
        choices=list(SEVERITY_BY_NAME.keys()),
        default="info",
        help="Severidad mínima que hace fallar el proceso (código de salida distinto de 0)",
    )
    auth = parser.add_argument_group("escaneo autenticado")
    auth.add_argument("--login-url", help="URL del formulario de login (por defecto <objetivo>/login)")
    auth.add_argument("--username", help="Usuario para iniciar sesión y escanear zonas privadas")
    auth.add_argument("--password", help="Contraseña de la sesión")
    auth.add_argument("--username-field", default="username", help="Nombre del campo de usuario en el formulario")
    auth.add_argument("--password-field", default="password", help="Nombre del campo de contraseña en el formulario")
    auth.add_argument("--second-username", help="Segundo usuario, para la comprobación asistida de IDOR")
    auth.add_argument("--second-password", help="Contraseña del segundo usuario")
    parser.add_argument(
        "--check-rate-limit",
        action="store_true",
        help="Envía un número acotado y suave de peticiones para detectar ausencia de limitación de tasa",
    )
    parser.add_argument(
        "--rate-limit-requests",
        type=int,
        default=15,
        help="Número de peticiones para la comprobación de rate limiting (por defecto 15)",
    )
    return parser


def _load_authorized_hosts(path: str | None) -> list[str]:
    if not path:
        return []
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    return [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]


def _config_from_args(args: argparse.Namespace) -> ScanConfig:
    credentials = None
    if args.username and args.password:
        credentials = Credentials(username=args.username, password=args.password)

    second_credentials = None
    if args.second_username and args.second_password:
        second_credentials = Credentials(username=args.second_username, password=args.second_password)

    return ScanConfig(
        target=args.target,
        max_depth=args.max_depth,
        max_pages=args.max_pages,
        delay=args.delay,
        request_delay=args.delay,
        concurrency=args.concurrency,
        timeout=args.timeout,
        allow_external_host=args.i_own_this,
        verify_tls=not args.no_verify_tls,
        authorized_hosts=_load_authorized_hosts(args.authorized_hosts),
        login_url=args.login_url,
        username_field=args.username_field,
        password_field=args.password_field,
        credentials=credentials,
        second_credentials=second_credentials,
        check_rate_limit=args.check_rate_limit,
        rate_limit_requests=args.rate_limit_requests,
    )


def _print_console(result: ScanResult) -> None:
    findings = result.sorted_findings()
    counts = severity_counts(findings)
    print()
    print(f"Objetivo:  {result.target}")
    for note in result.notes:
        print(f"Sesión:    {note}")
    print(f"Páginas:   {len(result.pages)} rastreadas")
    print(
        "Hallazgos: "
        + ", ".join(f"{counts[sev.value]} {SEVERITY_LABELS[sev].lower()}" for sev in SEVERITY_ORDER)
    )
    print()

    if not findings:
        print("Sin hallazgos. El objetivo superó todas las comprobaciones.")
        return

    for finding in findings:
        label = SEVERITY_LABELS[finding.severity].upper()
        print(f"[{label}] {finding.title}")
        print(f"    OWASP:      {finding.owasp.code} {finding.owasp.name}")
        location = f"{finding.request_method} {finding.url}"
        if finding.parameter:
            location += f" (parámetro: {finding.parameter})"
        print(f"    Ubicación:  {location}")
        print(f"    Evidencia:  {finding.evidence}")
        print(f"    Remediación:{finding.remediation}")
        print()


def _exit_code(result: ScanResult, fail_on: str) -> int:
    threshold = SEVERITY_BY_NAME[fail_on].rank
    for finding in result.findings:
        if finding.severity.rank >= threshold:
            return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config = _config_from_args(args)

    try:
        result = asyncio.run(run_scan(config))
    except AuthorizationError as error:
        print(f"Autorización denegada: {error}", file=sys.stderr)
        return 2

    _print_console(result)
    write_reports(result, args.json_path, args.html_path, args.sarif_path)
    if args.json_path:
        print(f"Reporte JSON:  {args.json_path}")
    if args.html_path:
        print(f"Reporte HTML:  {args.html_path}")
    if args.sarif_path:
        print(f"Reporte SARIF: {args.sarif_path}")

    return _exit_code(result, args.fail_on)
