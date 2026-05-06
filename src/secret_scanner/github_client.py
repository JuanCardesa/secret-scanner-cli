"""Async GitHub REST API client wrapper.

All GitHub HTTP access for the scanner should go through this module.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import os
import time
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import quote

import httpx

from secret_scanner.models import GitHubRepo, GitTree, GitTreeItem

GITHUB_API_BASE_URL = "https://api.github.com"
GITHUB_API_VERSION = "2022-11-28"
DEFAULT_TIMEOUT = 30.0
DEFAULT_PER_PAGE = 100

SleepCallable = Callable[[float], Awaitable[None]]
ClockCallable = Callable[[], float]


class GitHubClientError(RuntimeError):
    """Raised when GitHub API communication fails."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        endpoint: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.endpoint = endpoint


class GitHubClient:
    """Small async wrapper around the GitHub REST API."""

    def __init__(
        self,
        *,
        token: str | None = None,
        base_url: str = GITHUB_API_BASE_URL,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        sleep: SleepCallable = asyncio.sleep,
        clock: ClockCallable = time.time,
        max_retries: int = 3,
    ) -> None:
        token_value = token if token is not None else os.getenv("GITHUB_TOKEN")
        self._sleep = sleep
        self._clock = clock
        self._max_retries = max_retries
        self._rate_limited_until: float | None = None

        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
        }
        if token_value:
            headers["Authorization"] = f"Bearer {token_value}"

        self._client = httpx.AsyncClient(
            base_url=base_url,
            headers=headers,
            timeout=timeout,
            transport=transport,
        )

    async def __aenter__(self) -> GitHubClient:
        return self

    async def __aexit__(self, *_exc_info: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def list_org_repos(self, org: str) -> list[GitHubRepo]:
        payload = await self._get_paginated(
            f"/orgs/{_url_part(org)}/repos",
            params={"type": "public", "per_page": DEFAULT_PER_PAGE},
        )

        return [
            GitHubRepo(
                id=int(item["id"]),
                name=str(item["name"]),
                full_name=str(item["full_name"]),
                default_branch=str(item.get("default_branch", "")),
                html_url=str(item.get("html_url", "")),
                private=bool(item.get("private", False)),
            )
            for item in payload
        ]

    async def get_branch_sha(self, owner: str, repo: str, branch: str) -> str:
        response = await self._request(
            "GET",
            f"/repos/{_url_part(owner)}/{_url_part(repo)}/branches/{_url_part(branch)}",
        )
        payload = _json_object(response)

        try:
            return str(payload["commit"]["sha"])
        except (KeyError, TypeError) as exc:
            raise GitHubClientError(
                "GitHub branch response did not include commit sha",
                status_code=response.status_code,
                endpoint=str(response.request.url),
            ) from exc

    async def get_tree(
        self,
        owner: str,
        repo: str,
        sha: str,
        *,
        recursive: bool = True,
    ) -> GitTree:
        params = {"recursive": "1"} if recursive else None
        response = await self._request(
            "GET",
            f"/repos/{_url_part(owner)}/{_url_part(repo)}/git/trees/{_url_part(sha)}",
            params=params,
        )
        payload = _json_object(response)

        raw_items = payload.get("tree", [])
        if not isinstance(raw_items, list):
            raise GitHubClientError(
                "GitHub tree response did not include a valid tree list",
                status_code=response.status_code,
                endpoint=str(response.request.url),
            )

        return GitTree(
            sha=str(payload.get("sha", sha)),
            truncated=bool(payload.get("truncated", False)),
            tree=[
                GitTreeItem(
                    path=str(item["path"]),
                    mode=str(item["mode"]),
                    type=str(item["type"]),
                    sha=str(item["sha"]),
                    size=_optional_int(item.get("size")),
                    url=str(item["url"]) if item.get("url") else None,
                )
                for item in raw_items
                if isinstance(item, dict)
            ],
        )

    async def get_blob(self, owner: str, repo: str, blob_sha: str) -> str | None:
        response = await self._request(
            "GET",
            (
                f"/repos/{_url_part(owner)}/{_url_part(repo)}"
                f"/git/blobs/{_url_part(blob_sha)}"
            ),
        )
        payload = _json_object(response)

        if payload.get("encoding") != "base64":
            return None

        content = payload.get("content")
        if not isinstance(content, str):
            return None

        try:
            compact_content = "".join(content.split())
            raw = base64.b64decode(compact_content, validate=True)
            return raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            return None

    async def _get_paginated(
        self,
        path: str,
        *,
        params: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        next_url: str | None = path
        next_params = params

        while next_url:
            response = await self._request("GET", next_url, params=next_params)
            payload = response.json()
            if not isinstance(payload, list):
                raise GitHubClientError(
                    "GitHub paginated response was not a list",
                    status_code=response.status_code,
                    endpoint=str(response.request.url),
                )

            results.extend(item for item in payload if isinstance(item, dict))
            next_url = _next_link(response.headers.get("Link"))
            next_params = None

        return results

    async def _request(
        self,
        method: str,
        path_or_url: str,
        *,
        params: dict[str, Any] | None = None,
    ) -> httpx.Response:
        for attempt in range(self._max_retries + 1):
            await self._respect_rate_limit()

            try:
                response = await self._client.request(
                    method,
                    path_or_url,
                    params=params,
                )
            except httpx.HTTPError as exc:
                raise GitHubClientError(
                    f"GitHub request failed: {exc.__class__.__name__}",
                    endpoint=path_or_url,
                ) from exc

            self._update_rate_limit_state(response.headers)

            if response.status_code in {403, 429} and _is_rate_limited(response):
                if attempt >= self._max_retries:
                    raise _http_error(response)

                await self._sleep(_retry_delay(response.headers, self._clock))
                self._rate_limited_until = None
                continue

            if response.status_code >= 400:
                raise _http_error(response)

            return response

        raise GitHubClientError(
            "GitHub request failed after retries",
            endpoint=path_or_url,
        )

    async def _respect_rate_limit(self) -> None:
        if self._rate_limited_until is None:
            return

        delay = self._rate_limited_until - self._clock()
        if delay > 0:
            await self._sleep(delay)

        self._rate_limited_until = None

    def _update_rate_limit_state(self, headers: httpx.Headers) -> None:
        if headers.get("X-RateLimit-Remaining") != "0":
            return

        reset_at = _header_float(headers, "X-RateLimit-Reset")
        if reset_at is not None and reset_at > self._clock():
            self._rate_limited_until = reset_at


def _url_part(value: str) -> str:
    return quote(value, safe="")


def _json_object(response: httpx.Response) -> dict[str, Any]:
    payload = response.json()
    if not isinstance(payload, dict):
        raise GitHubClientError(
            "GitHub response was not a JSON object",
            status_code=response.status_code,
            endpoint=str(response.request.url),
        )
    return payload


def _optional_int(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if not isinstance(value, str):
        return None

    try:
        return int(value)
    except ValueError:
        return None


def _next_link(link_header: str | None) -> str | None:
    if not link_header:
        return None

    for part in link_header.split(","):
        url_part, *params = part.strip().split(";")
        rel_values = {param.strip() for param in params}
        if (
            'rel="next"' in rel_values
            and url_part.startswith("<")
            and url_part.endswith(">")
        ):
            return url_part[1:-1]

    return None


def _is_rate_limited(response: httpx.Response) -> bool:
    if response.headers.get("X-RateLimit-Remaining") == "0":
        return True

    retry_after = response.headers.get("Retry-After")
    if retry_after is not None:
        return True

    try:
        payload = response.json()
    except ValueError:
        return False

    message = (
        str(payload.get("message", "")).lower() if isinstance(payload, dict) else ""
    )
    return "rate limit" in message or "secondary rate limit" in message


def _retry_delay(headers: httpx.Headers, clock: ClockCallable) -> float:
    retry_after = _header_float(headers, "Retry-After")
    if retry_after is not None:
        return max(0.0, retry_after)

    reset_at = _header_float(headers, "X-RateLimit-Reset")
    if reset_at is not None:
        return max(0.0, reset_at - clock())

    return 1.0


def _header_float(headers: httpx.Headers, name: str) -> float | None:
    value = headers.get(name)
    if value is None:
        return None

    try:
        return float(value)
    except ValueError:
        return None


def _http_error(response: httpx.Response) -> GitHubClientError:
    message = f"GitHub API returned HTTP {response.status_code}"

    try:
        payload = response.json()
    except ValueError:
        payload = None

    if isinstance(payload, dict) and payload.get("message"):
        message = f"{message}: {payload['message']}"

    return GitHubClientError(
        message,
        status_code=response.status_code,
        endpoint=str(response.request.url),
    )
