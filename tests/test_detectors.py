from __future__ import annotations

from argus.detectors.cookies import CookiesDetector
from argus.detectors.csrf import CsrfDetector
from argus.detectors.info_leak import InfoLeakDetector
from argus.detectors.reflected_xss import ReflectedXssDetector
from argus.detectors.security_headers import SecurityHeadersDetector
from argus.detectors.sensitive_paths import SensitivePathsDetector
from argus.detectors.sql_injection import SqlInjectionDetector
from argus.models import FormField, HtmlForm, Severity
from conftest import FakeClient, FakeResponse, make_context, make_page


async def test_security_headers_flag_missing():
    page = make_page(headers={})
    findings = await SecurityHeadersDetector().run(make_context([page]))
    titles = [f.title for f in findings]
    assert any("content-security-policy" in t.lower() for t in titles)
    assert any("x-content-type-options" in t.lower() for t in titles)


async def test_security_headers_present_no_findings():
    headers = {
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "permissions-policy": "geolocation=()",
    }
    page = make_page(headers=headers)
    findings = await SecurityHeadersDetector().run(make_context([page]))
    assert findings == []


async def test_cookies_missing_flags():
    page = make_page(headers={"set-cookie": "SESSION=abc; Path=/"})
    findings = await CookiesDetector().run(make_context([page]))
    titles = [f.title for f in findings]
    assert any("HttpOnly" in t for t in titles)
    assert any("SameSite" in t for t in titles)


async def test_cookies_hardened_no_findings():
    page = make_page(
        url="https://localhost:8081/",
        headers={"set-cookie": "SESSION=abc; Path=/; HttpOnly; Secure; SameSite=Lax"},
    )
    findings = await CookiesDetector().run(make_context([page], target="https://localhost:8081"))
    assert findings == []


async def test_csrf_post_form_without_token():
    form = HtmlForm(action="http://localhost:8080/notes", method="POST", fields=[FormField("title", "text")])
    page = make_page(forms=[form])
    findings = await CsrfDetector().run(make_context([page]))
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


async def test_csrf_post_form_with_token_ok():
    form = HtmlForm(
        action="http://localhost:8080/notes",
        method="POST",
        fields=[FormField("title", "text"), FormField("_csrf", "hidden")],
    )
    page = make_page(forms=[form])
    findings = await CsrfDetector().run(make_context([page]))
    assert findings == []


async def test_reflected_xss_detected():
    class EchoClient(FakeClient):
        async def get(self, url, **kwargs):
            from urllib.parse import unquote
            return FakeResponse(text=unquote(url))

    page = make_page(url="http://localhost:8080/notes/search?q=x", query_params={"q": "x"})
    findings = await ReflectedXssDetector().run(make_context([page], client=EchoClient()))
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


async def test_reflected_xss_escaped_not_flagged():
    class EscapingClient(FakeClient):
        async def get(self, url, **kwargs):
            return FakeResponse(text=url.replace("<", "&lt;").replace(">", "&gt;"))

    page = make_page(url="http://localhost:8080/notes/search?q=x", query_params={"q": "x"})
    findings = await ReflectedXssDetector().run(make_context([page], client=EscapingClient()))
    assert findings == []


async def test_sql_injection_error_signature():
    class ErrorClient(FakeClient):
        async def get(self, url, **kwargs):
            if "%27" in url or "'" in url:
                return FakeResponse(text="org.h2.jdbc.JdbcSQLSyntaxErrorException: syntax error")
            return FakeResponse(text="ok")

    page = make_page(url="http://localhost:8080/notes/search?q=x", query_params={"q": "x"})
    findings = await SqlInjectionDetector().run(make_context([page], client=ErrorClient()))
    assert any(f.severity == Severity.HIGH for f in findings)


async def test_sensitive_paths_actuator_env():
    routes = {
        "/actuator/env": FakeResponse(text='{"activeProfiles":[],"propertySources":[]}'),
    }
    client = FakeClient(routes=routes, default=FakeResponse(status_code=404, text="not found"))
    findings = await SensitivePathsDetector().run(make_context([make_page()], client=client))
    titles = [f.title for f in findings]
    assert any("actuator/env" in t for t in titles)


async def test_info_leak_server_header_version():
    page = make_page(headers={"server": "Apache/2.4.41"})
    client = FakeClient(default=FakeResponse(status_code=404, text="not found"))
    findings = await InfoLeakDetector().run(make_context([page], client=client))
    assert any("Server" in f.title for f in findings)
