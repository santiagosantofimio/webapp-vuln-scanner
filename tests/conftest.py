from __future__ import annotations

from vigia.config import ScanConfig
from vigia.detectors.base import DetectorContext
from vigia.models import Page


class FakeResponse:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


class FakeClient:
    def __init__(self, routes=None, default=None):
        self.routes = routes or {}
        self.default = default if default is not None else FakeResponse(status_code=404)
        self.calls = []

    async def get(self, url, **kwargs):
        self.calls.append(url)
        for needle, response in self.routes.items():
            if needle in url:
                return response
        return self.default

    async def post(self, url, **kwargs):
        self.calls.append(url)
        return self.default


def make_page(url="http://localhost:8080/", status_code=200, headers=None, body="", forms=None, links=None, query_params=None):
    return Page(
        url=url,
        status_code=status_code,
        headers=headers or {},
        body=body,
        content_type=(headers or {}).get("content-type", "text/html"),
        forms=forms or [],
        links=links or [],
        query_params=query_params or {},
    )


def make_context(pages, client=None, target="http://localhost:8080"):
    config = ScanConfig(target=target)
    return DetectorContext(client=client or FakeClient(), config=config, pages=pages)
