from __future__ import annotations

from argus.detectors.idor import IdorDetector
from argus.detectors.rate_limit import RateLimitDetector
from argus.models import Severity
from conftest import FakeClient, FakeResponse, make_context, make_page


async def test_idor_flags_cross_session_access():
    page = make_page(url="http://localhost:8080/profile/7", status_code=200)
    second = FakeClient(default=FakeResponse(status_code=200, text="x" * 500, url="http://localhost:8080/profile/7"))
    ctx = make_context([page], client=FakeClient())
    ctx.second_client = second
    ctx.config.login_url = "http://localhost:8080/login"
    findings = await IdorDetector().run(ctx)
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


async def test_idor_ignores_when_second_session_bounced_to_login():
    page = make_page(url="http://localhost:8080/profile/7", status_code=200)
    second = FakeClient(default=FakeResponse(status_code=200, text="x" * 500, url="http://localhost:8080/login"))
    ctx = make_context([page], client=FakeClient())
    ctx.second_client = second
    ctx.config.login_url = "http://localhost:8080/login"
    findings = await IdorDetector().run(ctx)
    assert findings == []


async def test_idor_disabled_without_second_client():
    page = make_page(url="http://localhost:8080/profile/7", status_code=200)
    findings = await IdorDetector().run(make_context([page]))
    assert findings == []


async def test_rate_limit_flags_absence():
    ctx = make_context([make_page()], client=FakeClient(default=FakeResponse(status_code=200, text="ok")))
    ctx.config.check_rate_limit = True
    ctx.config.rate_limit_requests = 8
    findings = await RateLimitDetector().run(ctx)
    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW


async def test_rate_limit_no_finding_when_429_seen():
    ctx = make_context([make_page()], client=FakeClient(default=FakeResponse(status_code=429, text="slow down")))
    ctx.config.check_rate_limit = True
    findings = await RateLimitDetector().run(ctx)
    assert findings == []


async def test_rate_limit_disabled_by_default():
    ctx = make_context([make_page()])
    findings = await RateLimitDetector().run(ctx)
    assert findings == []
