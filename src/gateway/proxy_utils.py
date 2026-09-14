"""Допоміжні функції безпечного HTTP-проксіювання."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping, Sequence

from fastapi import Request

HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}

REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def normalize_request_id(raw_value: str, fallback: str) -> str:
    """Повертає безпечний request ID або резервне значення."""

    candidate = raw_value.strip()

    if candidate and REQUEST_ID_PATTERN.fullmatch(candidate):
        return candidate

    return fallback


def resolve_client_identity(
    request: Request,
    configured_header: str,
) -> str:
    """Визначає IP клієнта без довіри до довільного X-Forwarded-For."""

    fallback = (
        request.client.host
        if request.client is not None
        else "unknown"
    )

    if not configured_header:
        return fallback

    raw_value = request.headers.get(configured_header, "")
    candidate = raw_value.split(",", maxsplit=1)[0].strip()

    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return fallback


def matches_prefix(
    path: str,
    prefixes: Sequence[str],
) -> bool:
    """Перевіряє належність HTTP-шляху до одного з префіксів."""

    for prefix in prefixes:
        normalized = prefix.rstrip("/") or "/"

        if path == normalized:
            return True

        if normalized != "/" and path.startswith(f"{normalized}/"):
            return True

    return False


def build_upstream_url(
    base_url: str,
    path: str,
    query: str,
) -> str:
    """Формує URL upstream без можливості змінити його hostname."""

    normalized_path = path if path.startswith("/") else f"/{path}"
    url = f"{base_url.rstrip('/')}{normalized_path}"

    if query:
        url = f"{url}?{query}"

    return url


def build_request_headers(
    request: Request,
    *,
    client_identity: str,
    correlation_id: str,
) -> dict[str, str]:
    """Готує заголовки запиту для передачі до upstream."""

    headers: dict[str, str] = {}

    for name, value in request.headers.items():
        normalized_name = name.lower()

        if normalized_name in HOP_BY_HOP_HEADERS:
            continue

        if normalized_name in {
            "host",
            "content-length",
            "x-forwarded-for",
            "x-forwarded-host",
            "x-forwarded-proto",
            "x-request-id",
            "accept-encoding",
        }:
            continue

        headers[name] = value

    headers["Accept-Encoding"] = "identity"
    headers["X-Forwarded-For"] = client_identity
    headers["X-Forwarded-Host"] = request.headers.get("host", "")
    headers["X-Forwarded-Proto"] = request.url.scheme
    headers["X-Request-ID"] = correlation_id

    return headers


def build_response_headers(
    upstream_headers: Mapping[str, str],
    *,
    correlation_id: str,
    service_id: str,
) -> dict[str, str]:
    """Відбирає безпечні заголовки відповіді upstream."""

    headers: dict[str, str] = {}

    for name, value in upstream_headers.items():
        normalized_name = name.lower()

        if normalized_name in HOP_BY_HOP_HEADERS:
            continue

        if normalized_name in {
            "content-length",
            "content-encoding",
        }:
            continue

        headers[name] = value

    headers["X-Request-ID"] = correlation_id
    headers["X-Cybersecurity-Gateway"] = service_id

    return headers


def cache_key(path: str, query: str) -> str:
    """Формує стабільний ключ кешу для GET-запиту."""

    if query:
        return f"GET:{path}?{query}"

    return f"GET:{path}"


def request_may_use_cache(
    request: Request,
    *,
    path: str,
    cacheable_prefixes: Sequence[str],
) -> bool:
    """Перевіряє, чи дозволено кешувати відповідь на запит."""

    if request.method.upper() != "GET":
        return False

    if not matches_prefix(path, cacheable_prefixes):
        return False

    if request.headers.get("authorization"):
        return False

    if request.headers.get("cookie"):
        return False

    return True


def response_may_be_cached(
    headers: Mapping[str, str],
) -> bool:
    """Перевіряє, чи дозволяють заголовки кешувати відповідь."""

    if headers.get("set-cookie"):
        return False

    cache_control = headers.get("cache-control", "").lower()

    return (
        "no-store" not in cache_control
        and "private" not in cache_control
    )