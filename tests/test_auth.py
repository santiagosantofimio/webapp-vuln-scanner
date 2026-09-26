from __future__ import annotations

from argus.auth import _extract_login_form, login
from argus.config import Credentials, ScanConfig
from conftest import FakeClient, FakeResponse

LOGIN_HTML = """
<html><body>
<form method="post" action="/login">
  <input type="hidden" name="_csrf" value="tok-123"/>
  <input name="username"/>
  <input name="password" type="password"/>
</form>
</body></html>
"""


class LoginClient(FakeClient):
    def __init__(self, verify_response, post_response):
        super().__init__(post_response=post_response)
        self._verify = verify_response

    async def get(self, url, **kwargs):
        self.calls.append(url)
        if "/login" in url:
            return FakeResponse(text=LOGIN_HTML, headers={"content-type": "text/html"}, url=url)
        return self._verify


def test_extract_login_form_keeps_hidden_fields():
    action, data = _extract_login_form(LOGIN_HTML, "http://localhost:8080/login", "password")
    assert action == "http://localhost:8080/login"
    assert data["_csrf"] == "tok-123"
    assert "username" in data and "password" in data


async def test_login_success_when_target_reachable():
    client = LoginClient(
        verify_response=FakeResponse(status_code=200, text="dashboard", url="http://localhost:8080/"),
        post_response=FakeResponse(status_code=302, headers={"set-cookie": "SESSION=x; Path=/"}, url=""),
    )
    config = ScanConfig(target="http://localhost:8080", login_url="http://localhost:8080/login")
    result = await login(client, config, Credentials("santiago", "santiago123"))
    assert result.success
    assert client.posts[0][1]["username"] == "santiago"
    assert client.posts[0][1]["_csrf"] == "tok-123"
    assert result.page is not None
    assert "set-cookie" in result.page.headers


async def test_login_fails_when_target_still_requires_session():
    client = LoginClient(
        verify_response=FakeResponse(status_code=200, text="login", url="http://localhost:8080/login"),
        post_response=FakeResponse(status_code=200, url="http://localhost:8080/login"),
    )
    config = ScanConfig(target="http://localhost:8080", login_url="http://localhost:8080/login")
    result = await login(client, config, Credentials("santiago", "wrong"))
    assert not result.success
