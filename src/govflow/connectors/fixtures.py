"""Serve recorded GitHub API responses so the real connector code runs offline."""

from __future__ import annotations

import base64
from collections.abc import Mapping
from typing import Any

import httpx


def fixture_transport(routes: Mapping[str, Mapping[str, Any]]) -> httpx.MockTransport:
    """Routes are keyed by "METHOD /path"; query strings are ignored."""

    def handler(request: httpx.Request) -> httpx.Response:
        route = routes.get(f"{request.method} {request.url.path}")
        if route is None:
            return httpx.Response(404, json={"message": "Not Found"})
        status = int(route.get("status", 200))
        if "file" in route:
            content = base64.b64encode(str(route["file"]).encode("utf-8")).decode("ascii")
            path = request.url.path.split("/contents/", 1)[-1]
            return httpx.Response(
                status,
                json={"type": "file", "encoding": "base64", "path": path, "content": content},
            )
        if "json" in route:
            return httpx.Response(status, json=route["json"])
        return httpx.Response(status)

    return httpx.MockTransport(handler)
