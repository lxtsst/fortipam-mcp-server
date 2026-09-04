from __future__ import annotations

import asyncio

import pytest

from fortipam_mcp.rest import _bounded_content, FortiPamRequestError, MAX_RESPONSE_BYTES


class _FakeResponse:
    def __init__(self, chunks: list[bytes], content_length: str | None = None) -> None:
        self._chunks = chunks
        self.headers = {}
        if content_length is not None:
            self.headers["content-length"] = content_length

    async def aiter_bytes(self):
        for chunk in self._chunks:
            yield chunk


def test_rejects_declared_oversized_response_before_reading() -> None:
    response = _FakeResponse([], str(MAX_RESPONSE_BYTES + 1))

    with pytest.raises(FortiPamRequestError, match="1 MiB"):
        asyncio.run(_bounded_content(response))


def test_rejects_stream_that_crosses_response_limit() -> None:
    response = _FakeResponse([b"a" * MAX_RESPONSE_BYTES, b"b"])

    with pytest.raises(FortiPamRequestError, match="1 MiB"):
        asyncio.run(_bounded_content(response))
