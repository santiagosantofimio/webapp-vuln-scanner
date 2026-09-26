from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

from .config import Credentials, ScanConfig
from .crawler import build_page
from .http_client import HttpClient
from .models import Page


@dataclass
class LoginResult:
    success: bool
    message: str
    page: Optional[Page] = None


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

    response = await client.post(action, data=data, follow_redirects=False)
    if response is None:
        return LoginResult(False, f"No hubo respuesta al enviar el login a {action}")

    login_page = build_page(action, response)

    verify = await client.get(config.target, follow_redirects=True)
    login_path = urlsplit(login_url).path
    authenticated = (
        verify is not None
        and verify.status_code == 200
        and urlsplit(str(verify.url)).path != login_path
    )

    if not authenticated:
        return LoginResult(
            False,
            "El login no parece haber funcionado (el objetivo sigue exigiendo sesion)",
            login_page,
        )

    return LoginResult(True, f"Sesion iniciada como '{credentials.username}'", login_page)
