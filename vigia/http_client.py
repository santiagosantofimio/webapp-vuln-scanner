from __future__ import annotations

import asyncio
from typing import Optional

import httpx

from .config import ScanConfig


class HttpClient:
    def __init__(self, config: ScanConfig):
        self._config = config
        self._semaphore = asyncio.Semaphore(config.concurrency)
        self._client = httpx.AsyncClient(
            headers={"User-Agent": config.user_agent},
            timeout=config.timeout,
            follow_redirects=False,
            verify=config.verify_tls,
            cookies=httpx.Cookies(),
        )

    async def __aenter__(self) -> "HttpClient":
        return self

    async def __aexit__(self, *exc_info) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def request(
        self,
        method: str,
        url: str,
        *,
        params: Optional[dict] = None,
        data: Optional[dict] = None,
        follow_redirects: bool = False,
    ) -> Optional[httpx.Response]:
        async with self._semaphore:
            try:
                response = await self._client.request(
                    method,
                    url,
                    params=params,
                    data=data,
                    follow_redirects=follow_redirects,
                )
            except httpx.HTTPError:
                await asyncio.sleep(self._config.request_delay)
                return None
            await asyncio.sleep(self._config.request_delay)
            return response

    async def get(self, url: str, **kwargs) -> Optional[httpx.Response]:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> Optional[httpx.Response]:
        return await self.request("POST", url, **kwargs)
