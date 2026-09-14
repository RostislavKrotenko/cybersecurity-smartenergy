"""Обмежений кеш останніх коректних відповідей upstream."""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CachedResponse:
    """Збережена HTTP-відповідь із інформацією про її вік."""

    status_code: int
    headers: dict[str, str]
    body: bytes
    age_sec: float


@dataclass(slots=True)
class _CacheEntry:
    status_code: int
    headers: dict[str, str]
    body: bytes
    stored_at: float


class LastKnownGoodCache:
    """Зберігає останню успішну відповідь для безпечних GET-запитів.

    Кеш використовується лише для контрольованої деградації. Відповідь із
    кешу обов’язково має позначатися заголовками `X-Cybersecurity-Stale`
    та `X-Cybersecurity-Cache-Age`.
    """

    def __init__(
        self,
        *,
        ttl_sec: float,
        max_body_bytes: int,
        max_entries: int = 256,
        clock: Callable[[], float] = time.monotonic,
    ):
        """Створює кеш із обмеженням часу, розміру та кількості записів."""

        if ttl_sec < 0:
            raise ValueError("TTL кешу не може бути від’ємним")

        if max_body_bytes < 1:
            raise ValueError(
                "Максимальний розмір відповіді має бути не менше 1"
            )

        if max_entries < 1:
            raise ValueError(
                "Максимальна кількість записів має бути не менше 1"
            )

        self._ttl_sec = ttl_sec
        self._max_body_bytes = max_body_bytes
        self._max_entries = max_entries
        self._clock = clock

        self._entries: OrderedDict[str, _CacheEntry] = OrderedDict()
        self._lock = threading.RLock()

    def put(
        self,
        key: str,
        *,
        status_code: int,
        headers: Mapping[str, str],
        body: bytes,
    ) -> bool:
        """Зберігає успішну відповідь та повертає ознаку запису."""

        if self._ttl_sec == 0:
            return False

        if not key:
            return False

        if not 200 <= status_code < 300:
            return False

        if len(body) > self._max_body_bytes:
            return False

        safe_headers = self._select_safe_headers(headers)
        entry = _CacheEntry(
            status_code=status_code,
            headers=safe_headers,
            body=bytes(body),
            stored_at=self._clock(),
        )

        with self._lock:
            self._entries.pop(key, None)
            self._entries[key] = entry
            self._entries.move_to_end(key)

            while len(self._entries) > self._max_entries:
                self._entries.popitem(last=False)

        return True

    def get(self, key: str) -> CachedResponse | None:
        """Повертає актуальну кешовану відповідь або `None`."""

        if self._ttl_sec == 0:
            return None

        now = self._clock()

        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None

            age_sec = max(0.0, now - entry.stored_at)

            if age_sec > self._ttl_sec:
                self._entries.pop(key, None)
                return None

            self._entries.move_to_end(key)

            return CachedResponse(
                status_code=entry.status_code,
                headers=dict(entry.headers),
                body=entry.body,
                age_sec=age_sec,
            )

    def invalidate(self, key: str | None = None) -> None:
        """Видаляє один запис або повністю очищає кеш."""

        with self._lock:
            if key is None:
                self._entries.clear()
                return

            self._entries.pop(key, None)

    def snapshot(self) -> dict[str, object]:
        """Повертає агрегований стан кешу."""

        now = self._clock()

        with self._lock:
            expired = [
                key
                for key, entry in self._entries.items()
                if now - entry.stored_at > self._ttl_sec
            ]

            for key in expired:
                self._entries.pop(key, None)

            return {
                "ttlSec": self._ttl_sec,
                "maxBodyBytes": self._max_body_bytes,
                "maxEntries": self._max_entries,
                "entries": len(self._entries),
            }

    @staticmethod
    def _select_safe_headers(
        headers: Mapping[str, str],
    ) -> dict[str, str]:
        allowed_headers = {
            "content-type",
            "content-language",
            "etag",
            "last-modified",
        }

        return {
            name.lower(): value
            for name, value in headers.items()
            if name.lower() in allowed_headers
        }