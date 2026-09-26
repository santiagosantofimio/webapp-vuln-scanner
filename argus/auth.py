from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

from .config import Credentials, ScanConfig
from .http_client import HttpClient


@dataclass
class LoginResult:
    success: bool
    message: str


def _extract_login_form(html: str, login_url: str, password_field: str) -> tuple[str, dict[str, str]]:
    soup = BeautifulSoup(html, "html.parser")
    forms = soup.find_all("form")
    chosen = None
    for form in forms:
        inputs = form.find_all("input")
        if any((i.get("type") or "").lower() == "password" for i in inputs):
            chosen = form
            break
        if any((i.get("name") or "") == password_field for i in inputs):
            chosen = form
            break
    if chosen is None:
        return login_url, {}

    action = urljoin(login_url, chosen.get("action") or login_url)
    data: dict[str, str] = {}
    for control in chosen.find_all(["input", "textarea", "select"]):
        name = control.get("name")
        if not name:
            continue
        data[name] = control.get("value") or ""
    return action, data


async def login(client: HttpClient, config: ScanConfig, credentials: Credentials) -> LoginResult:
    login_url = config.login_url or urljoin(config.target, "/login")

    page = await client.get(login_url, follow_redirects=True)
    action = login_url
    data: dict[str, str] = {}
    if page is not None and "html" in page.headers.get("content-type", "").lower():
        action, data = _extract_login_form(page.text, login_url, config.password_field)

    data[config.username_field] = credentials.username
    data[config.password_field] = credentials.password

    response = await client.post(action, data=data, follow_redirects=True)
    if response is None:
        return LoginResult(False, f"No hubo respuesta al enviar el login a {action}")

    login_path = urlsplit(login_url).path
    final_path = urlsplit(str(response.url)).path
    bounced = final_path == login_path and response.status_code == 200

    if response.status_code >= 400:
        return LoginResult(False, f"El login respondio {response.status_code}")
    if bounced:
        return LoginResult(False, "El login no parece haber funcionado (se volvio al formulario)")

    return LoginResult(True, f"Sesion iniciada como '{credentials.username}'")
