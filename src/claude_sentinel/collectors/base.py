"""Shared HTTP, cache and source helpers for collectors."""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from claude_sentinel.models import Confidence, Source, SourceKind

DEFAULT_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
)


class Http:
    """Thin httpx wrapper that keeps timeouts and redirects predictable."""

    def __init__(
        self,
        proxy: str | None = None,
        timeout: float = 8.0,
        transport: httpx.BaseTransport | None = None,
        user_agent: str = DEFAULT_UA,
        retries: int = 2,
    ) -> None:
        kwargs: dict[str, Any] = {
            "timeout": httpx.Timeout(timeout, connect=min(5.0, timeout)),
            "follow_redirects": False,
            "headers": {
                "User-Agent": user_agent,
                "Accept-Language": "en-US,en;q=0.9,zh-CN;q=0.8",
            },
        }
        if proxy:
            kwargs["proxy"] = proxy
        if transport is not None:
            kwargs["transport"] = transport
        self.client = httpx.Client(**kwargs)
        self.timeout = timeout
        self.retries = retries

    def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.client.get(url, **kwargs)

    def fetch(self, url: str, retries: int | None = None, **kwargs: Any) -> httpx.Response:
        """GET with retries for transport errors.

        A single dropped TLS handshake is routine behind a busy proxy or a
        loaded TUN. Without a retry one blip drops an entire data source, and
        the verdict degrades to "无法判断" for reasons the user cannot act on.
        Only transport-level failures are retried; HTTP error statuses are
        returned as-is because retrying them would not change the answer.
        """
        attempts = self.retries if retries is None else retries
        last: Exception | None = None
        for attempt in range(attempts + 1):
            try:
                return self.client.get(url, **kwargs)
            except (httpx.TransportError, httpx.HTTPError) as exc:
                last = exc
                if attempt >= attempts:
                    break
                time.sleep(0.35 * (attempt + 1))
        assert last is not None
        raise last

    def close(self) -> None:
        self.client.close()

    def __enter__(self) -> Http:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def now() -> datetime:
    return datetime.now(timezone.utc)


def source_from_response(
    name: str,
    kind: SourceKind,
    url: str,
    resp: httpx.Response | None = None,
    confidence: Confidence = Confidence.high,
    note: str | None = None,
) -> Source:
    return Source(
        name=name,
        kind=kind,
        url=url,
        retrieved_at=now(),
        http_status=resp.status_code if resp is not None else None,
        confidence=confidence,
        note=note,
    )


def cache_path(cache_dir: Path, key: str) -> Path:
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:20]
    return cache_dir / f"{digest}.json"


def cache_read(cache_dir: Path, key: str, ttl_seconds: int | None = None) -> Any | None:
    path = cache_path(cache_dir, key)
    if not path.exists():
        return None
    if ttl_seconds is not None and time.time() - path.stat().st_mtime > ttl_seconds:
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def cache_write(cache_dir: Path, key: str, value: Any) -> None:
    cache_dir.mkdir(parents=True, exist_ok=True)
    path = cache_path(cache_dir, key)
    # Unique temp name: the IP-intel lookups for primary/v4/v6 run in parallel
    # and a shared ".tmp" let one writer steal the other's file.
    tmp = path.with_suffix(f".{os.getpid()}.{threading.get_ident()}.tmp")
    try:
        tmp.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
        try:
            tmp.chmod(0o600)
        except OSError:
            pass
        tmp.replace(path)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def parse_json(resp: httpx.Response) -> Any | None:
    try:
        return resp.json()
    except (ValueError, json.JSONDecodeError):
        return None
