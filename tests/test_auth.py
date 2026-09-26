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


def test_extract_login_form_keeps_hidden_fields():
    action, data = _extract_login_form(LOGIN_HTML, "http://localhost:8080/login", "password")
    assert action == "http://localhost:8080/login"
    assert data["_csrf"] == "tok-123"
    assert "username" in data and "password" in data


async def test_login_success_when_not_bounced():
    client = FakeClient(
        default=FakeResponse(text=LOGIN_HTML, headers={"content-type": "text/html"}),
        post_response=FakeResponse(status_code=200, url="http://localhost:8080/"),
    )
    config = ScanConfig(target="http://localhost:8080", login_url="http://localhost:8080/login")
    result = await login(client, config, Credentials("santiago", "santiago123"))
    assert result.success
    posted_data = client.posts[0][1]
    assert posted_data["username"] == "santiago"
    assert posted_data["_csrf"] == "tok-123"


async def test_login_fails_when_bounced_to_form():
    client = FakeClient(
        default=FakeResponse(text=LOGIN_HTML, headers={"content-type": "text/html"}),
        post_response=FakeResponse(status_code=200, url="http://localhost:8080/login"),
    )
    config = ScanConfig(target="http://localhost:8080", login_url="http://localhost:8080/login")
    result = await login(client, config, Credentials("santiago", "wrong"))
    assert not result.success
