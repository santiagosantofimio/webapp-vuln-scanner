from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def with_param(url: str, param: str, value: str) -> str:
    parts = urlsplit(url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query[param] = value
    new_query = urlencode(query)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))


def path_key(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def injectable_targets(pages):
    for page in pages:
        for param in page.query_params:
            yield page.url, param, "GET"
        for form in page.forms:
            if form.method != "GET":
                continue
            for field in form.fields:
                if field.field_type in ("hidden", "submit", "button", "checkbox", "radio"):
                    continue
                yield form.action, field.name, "GET"
