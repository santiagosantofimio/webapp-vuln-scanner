from __future__ import annotations

import pytest

from argus.authorization import AuthorizationError, ensure_authorized, is_loopback


def test_loopback_hosts():
    assert is_loopback("localhost")
    assert is_loopback("127.0.0.1")
    assert is_loopback("::1")
    assert not is_loopback("example.com")


def test_localhost_is_authorized_by_default():
    ensure_authorized("http://localhost:8080", allow_external_host=False, authorized_hosts=[])


def test_external_host_blocked_without_flag():
    with pytest.raises(AuthorizationError):
        ensure_authorized("https://example.com", allow_external_host=False, authorized_hosts=[])


def test_external_host_allowed_with_flag():
    ensure_authorized("https://example.com", allow_external_host=True, authorized_hosts=[])


def test_external_host_allowed_when_listed():
    ensure_authorized("https://example.com", allow_external_host=False, authorized_hosts=["example.com"])
