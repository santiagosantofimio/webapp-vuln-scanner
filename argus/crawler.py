from __future__ import annotations

from collections import deque
from urllib.parse import urljoin, urlparse, urlsplit, urlunsplit, parse_qs

import httpx
from bs4 import BeautifulSoup

from .config import ScanConfig
from .http_client import HttpClient
from .models import FormField, HtmlForm, Page


def same_origin(base: str, candidate: str) -> bool:
    a = urlparse(base)
    b = urlparse(candidate)
    return (a.scheme, a.hostname, a.port) == (b.scheme, b.hostname, b.port)


def normalize(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))


def _parse_forms(soup: BeautifulSoup, page_url: str) -> list[HtmlForm]:
    forms: list[HtmlForm] = []
    for element in soup.find_all("form"):
        action = urljoin(page_url, element.get("action") or page_url)
        method = (element.get("method") or "get").upper()
        fields: list[FormField] = []
        for control in element.find_all(["input", "textarea", "select"]):
            name = control.get("name")
            if not name:
                continue
            field_type = control.get("type") or control.name
            value = control.get("value") or ""
            fields.append(FormField(name=name, field_type=field_type, value=value))
        forms.append(HtmlForm(action=action, method=method, fields=fields))
    return forms


def _parse_links(soup: BeautifulSoup, page_url: str) -> list[str]:
    links: list[str] = []
    for anchor in soup.find_all("a", href=True):
        href = anchor["href"].strip()
        if href.startswith(("mailto:", "tel:", "javascript:", "#")):
            continue
        links.append(urljoin(page_url, href))
    return links


def _collect_headers(response: httpx.Response) -> dict[str, str]:
    headers = response.headers
    items = headers.multi_items() if hasattr(headers, "multi_items") else headers.items()
    collected: dict[str, list[str]] = {}
    for key, value in items:
        collected.setdefault(key.lower(), []).append(value)
    return {key: "\n".join(values) for key, values in collected.items()}


def build_page(url: str, response: httpx.Response) -> Page:
    content_type = response.headers.get("content-type", "")
    is_html = "html" in content_type.lower()
    body = response.text if is_html else ""
    forms: list[HtmlForm] = []
    links: list[str] = []
    if is_html:
        soup = BeautifulSoup(body, "html.parser")
        forms = _parse_forms(soup, url)
        links = _parse_links(soup, url)
    query_params = {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}
    return Page(
        url=url,
        status_code=response.status_code,
        headers=_collect_headers(response),
        body=body,
        content_type=content_type,
        forms=forms,
        links=links,
        query_params=query_params,
    )


async def crawl(client: HttpClient, config: ScanConfig) -> list[Page]:
    root = normalize(config.target)
    visited: set[str] = set()
    pages: list[Page] = []
    queue: deque[tuple[str, int]] = deque([(root, 0)])

    while queue and len(pages) < config.max_pages:
        url, depth = queue.popleft()
        url = normalize(url)
        if url in visited:
            continue
        visited.add(url)

        response = await client.get(url)
        if response is None:
            continue

        page = build_page(url, response)
        pages.append(page)

        if depth >= config.max_depth:
            continue

        for link in page.links:
            candidate = normalize(link)
            if candidate in visited:
                continue
            if not same_origin(root, candidate):
                continue
            queue.append((candidate, depth + 1))

    return pages
