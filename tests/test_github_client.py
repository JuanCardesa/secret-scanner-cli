from __future__ import annotations

import asyncio
import base64

import httpx
import pytest

from secret_scanner.github_client import GitHubClient, GitHubClientError

pytestmark = pytest.mark.asyncio


def json_response(
    request: httpx.Request,
    status_code: int,
    payload: object,
    *,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    return httpx.Response(
        status_code,
        json=payload,
        headers=headers,
        request=request,
    )


async def test_client_sends_standard_and_auth_headers() -> None:
    seen_headers: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen_headers.update(request.headers)
        return json_response(request, 200, {"commit": {"sha": "branch-sha"}})

    async with GitHubClient(
        token="test-token",
        transport=httpx.MockTransport(handler),
    ) as client:
        branch_sha = await client.get_branch_sha("owner", "repo", "main")

    assert branch_sha == "branch-sha"
    assert seen_headers["accept"] == "application/vnd.github+json"
    assert seen_headers["x-github-api-version"] == "2022-11-28"
    assert seen_headers["authorization"] == "Bearer test-token"


async def test_client_reads_token_from_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "env-token")
    seen_headers: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen_headers.update(request.headers)
        return json_response(request, 200, {"commit": {"sha": "branch-sha"}})

    async with GitHubClient(transport=httpx.MockTransport(handler)) as client:
        await client.get_branch_sha("owner", "repo", "main")

    assert seen_headers["authorization"] == "Bearer env-token"


async def test_client_omits_auth_header_when_no_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    seen_headers: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen_headers.update(request.headers)
        return json_response(request, 200, {"commit": {"sha": "branch-sha"}})

    async with GitHubClient(transport=httpx.MockTransport(handler)) as client:
        await client.get_branch_sha("owner", "repo", "main")

    assert "authorization" not in seen_headers


async def test_list_org_repos_follows_link_pagination() -> None:
    requested_urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_urls.append(str(request.url))
        if "page=2" in str(request.url):
            return json_response(
                request,
                200,
                [
                    {
                        "id": 2,
                        "name": "repo-two",
                        "full_name": "org/repo-two",
                        "default_branch": "develop",
                        "html_url": "https://github.com/org/repo-two",
                        "private": False,
                    }
                ],
            )

        return json_response(
            request,
            200,
            [
                {
                    "id": 1,
                    "name": "repo-one",
                    "full_name": "org/repo-one",
                    "default_branch": "main",
                    "html_url": "https://github.com/org/repo-one",
                    "private": False,
                }
            ],
            headers={
                "Link": (
                    "<https://api.github.com/orgs/org/repos?type=public"
                    '&per_page=100&page=2>; rel="next", '
                    "<https://api.github.com/orgs/org/repos?type=public"
                    '&per_page=100&page=2>; rel="last"'
                )
            },
        )

    async with GitHubClient(transport=httpx.MockTransport(handler)) as client:
        repos = await client.list_org_repos("org")

    assert [repo.full_name for repo in repos] == ["org/repo-one", "org/repo-two"]
    assert len(requested_urls) == 2
    assert requested_urls[0].startswith("https://api.github.com/orgs/org/repos")
    assert requested_urls[1].endswith("page=2")


async def test_rate_limit_response_backs_off_and_retries() -> None:
    calls = 0
    sleep_delays: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return json_response(
                request,
                403,
                {"message": "API rate limit exceeded"},
                headers={
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": "110",
                },
            )
        return json_response(request, 200, {"commit": {"sha": "branch-sha"}})

    async def fake_sleep(delay: float) -> None:
        sleep_delays.append(delay)

    async with GitHubClient(
        transport=httpx.MockTransport(handler),
        sleep=fake_sleep,
        clock=lambda: 100.0,
    ) as client:
        branch_sha = await client.get_branch_sha("owner", "repo", "main")

    assert branch_sha == "branch-sha"
    assert calls == 2
    assert sleep_delays == [10.0]


async def test_successful_zero_remaining_response_delays_next_request() -> None:
    calls = 0
    sleep_delays: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return json_response(
            request,
            200,
            {"commit": {"sha": f"sha-{calls}"}},
            headers={
                "X-RateLimit-Remaining": "0" if calls == 1 else "10",
                "X-RateLimit-Reset": "105",
            },
        )

    async def fake_sleep(delay: float) -> None:
        sleep_delays.append(delay)

    async with GitHubClient(
        transport=httpx.MockTransport(handler),
        sleep=fake_sleep,
        clock=lambda: 100.0,
    ) as client:
        first_sha = await client.get_branch_sha("owner", "repo", "main")
        second_sha = await client.get_branch_sha("owner", "repo", "develop")

    assert [first_sha, second_sha] == ["sha-1", "sha-2"]
    assert sleep_delays == [5.0]


async def test_unrelated_requests_run_concurrently() -> None:
    calls = 0
    first_request_started = asyncio.Event()
    release_first_request = asyncio.Event()

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1

        if calls == 1:
            first_request_started.set()
            await release_first_request.wait()
            return json_response(
                request,
                200,
                {"commit": {"sha": "sha-1"}},
                headers={"X-RateLimit-Remaining": "10"},
            )

        return json_response(
            request,
            200,
            {"commit": {"sha": "sha-2"}},
            headers={"X-RateLimit-Remaining": "10"},
        )

    async with GitHubClient(
        transport=httpx.MockTransport(handler),
        clock=lambda: 100.0,
    ) as client:
        first_task = asyncio.create_task(client.get_branch_sha("owner", "repo", "main"))
        await first_request_started.wait()

        second_task = asyncio.create_task(
            client.get_branch_sha("owner", "repo", "develop")
        )
        await asyncio.sleep(0)
        # The second request must reach the transport while the first is still
        # in flight: requests are not serialized behind a single client-wide lock.
        assert calls == 2

        release_first_request.set()
        first_sha, second_sha = await asyncio.gather(first_task, second_task)

    assert [first_sha, second_sha] == ["sha-1", "sha-2"]


async def test_concurrent_requests_share_rate_limit_state_safely() -> None:
    calls = 0
    sleep_delays: list[float] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1

        if calls == 1:
            return json_response(
                request,
                200,
                {"commit": {"sha": "sha-1"}},
                headers={
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": "105",
                },
            )

        return json_response(
            request,
            200,
            {"commit": {"sha": f"sha-{calls}"}},
            headers={"X-RateLimit-Remaining": "10"},
        )

    async def fake_sleep(delay: float) -> None:
        sleep_delays.append(delay)

    async with GitHubClient(
        transport=httpx.MockTransport(handler),
        sleep=fake_sleep,
        clock=lambda: 100.0,
    ) as client:
        # First request observes the rate limit and records it as shared state.
        first_sha = await client.get_branch_sha("owner", "repo", "main")

        # Both of these see the shared rate-limited state concurrently and must
        # each wait out the limit without corrupting `_rate_limited_until` or
        # double-counting the delay.
        second_sha, third_sha = await asyncio.gather(
            client.get_branch_sha("owner", "repo", "develop"),
            client.get_branch_sha("owner", "repo", "release"),
        )

    assert first_sha == "sha-1"
    assert {second_sha, third_sha} == {"sha-2", "sha-3"}
    # Exactly how many coroutines observe the limit before it is cleared depends
    # on scheduling, but every observed delay must reflect the real reset time.
    assert sleep_delays
    assert all(delay == 5.0 for delay in sleep_delays)


async def test_negative_max_retries_is_rejected() -> None:
    with pytest.raises(ValueError, match="max_retries must be >= 0"):
        GitHubClient(max_retries=-1)


async def test_get_tree_parses_tree_items() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["recursive"] == "1"
        return json_response(
            request,
            200,
            {
                "sha": "tree-sha",
                "truncated": False,
                "tree": [
                    {
                        "path": "src/app.py",
                        "mode": "100644",
                        "type": "blob",
                        "sha": "blob-sha",
                        "size": 32,
                        "url": "https://api.github.com/blob",
                    }
                ],
            },
        )

    async with GitHubClient(transport=httpx.MockTransport(handler)) as client:
        tree = await client.get_tree("owner", "repo", "branch-sha")

    assert tree.sha == "tree-sha"
    assert tree.tree[0].path == "src/app.py"
    assert tree.tree[0].size == 32


async def test_get_blob_decodes_base64_text() -> None:
    expected = "print('hello')\n"
    encoded = base64.b64encode(expected.encode("utf-8")).decode("ascii")

    def handler(request: httpx.Request) -> httpx.Response:
        return json_response(
            request,
            200,
            {
                "sha": "blob-sha",
                "encoding": "base64",
                "content": encoded,
            },
        )

    async with GitHubClient(transport=httpx.MockTransport(handler)) as client:
        content = await client.get_blob("owner", "repo", "blob-sha")

    assert content == expected


async def test_get_blob_returns_none_for_binary_content() -> None:
    encoded = base64.b64encode(b"\xff\xfe\x00\x00").decode("ascii")

    def handler(request: httpx.Request) -> httpx.Response:
        return json_response(
            request,
            200,
            {
                "sha": "blob-sha",
                "encoding": "base64",
                "content": encoded,
            },
        )

    async with GitHubClient(transport=httpx.MockTransport(handler)) as client:
        content = await client.get_blob("owner", "repo", "blob-sha")

    assert content is None


async def test_http_errors_are_wrapped_without_token_in_message() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return json_response(request, 404, {"message": "Not Found"})

    async with GitHubClient(
        token="sensitive-token",
        transport=httpx.MockTransport(handler),
    ) as client:
        with pytest.raises(GitHubClientError) as exc_info:
            await client.get_branch_sha("owner", "repo", "missing")

    error = exc_info.value
    assert error.status_code == 404
    assert "Not Found" in str(error)
    assert "sensitive-token" not in str(error)


async def test_invalid_blob_payload_returns_none() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return json_response(
            request,
            200,
            {
                "sha": "blob-sha",
                "encoding": "base64",
                "content": "not valid base64",
            },
        )

    async with GitHubClient(transport=httpx.MockTransport(handler)) as client:
        content = await client.get_blob("owner", "repo", "blob-sha")

    assert content is None
