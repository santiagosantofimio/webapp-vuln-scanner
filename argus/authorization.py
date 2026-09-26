from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

LOCAL_HOSTNAMES = {"localhost", "ip6-localhost"}


class AuthorizationError(Exception):
    pass


def host_of(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.hostname:
        raise AuthorizationError(f"URL sin host valido: {url}")
    return parsed.hostname


def is_loopback(hostname: str) -> bool:
    if hostname.lower() in LOCAL_HOSTNAMES:
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def ensure_authorized(url: str, allow_external_host: bool, authorized_hosts: list[str]) -> None:
    hostname = host_of(url)
    if is_loopback(hostname):
        return
    if hostname in authorized_hosts:
        return
    if allow_external_host:
        return
    raise AuthorizationError(
        f"El objetivo '{hostname}' no es local. Escanear un sistema ajeno sin permiso es ilegal. "
        "Usa --i-own-this o agrega el host a un archivo de blancos autorizados (--authorized-hosts) "
        "solo si el sistema es tuyo o cuentas con autorizacion escrita."
    )
