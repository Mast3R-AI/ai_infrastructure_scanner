from __future__ import annotations

import json
from typing import Any

import httpx

from models import Indicator, ProbeResult, RequestLogEntry

HTTPS_PORTS = {443, 8443, 9443}


def _preferred_scheme(port: int) -> str:
    return "https" if port in HTTPS_PORTS else "http"


def _build_url(host: str, port: int, path: str, scheme: str) -> str:
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        return f"{scheme}://{host}{path}"
    return f"{scheme}://{host}:{port}{path}"


def _parse_json(body: str) -> dict[str, Any] | list[Any] | None:
    try:
        return json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return None


def _append_request_log(
    request_log: list[RequestLogEntry] | None,
    method: str,
    url: str,
    result: ProbeResult,
) -> None:
    if request_log is None:
        return
    request_log.append(
        RequestLogEntry(
            method=method.upper(),
            url=url,
            status_code=result.status_code,
            error=result.error,
        )
    )


def _do_request(
    url: str,
    method: str,
    timeout: float,
    request_log: list[RequestLogEntry] | None = None,
) -> ProbeResult:
    try:
        with httpx.Client(verify=False, timeout=timeout, follow_redirects=True) as client:
            response = client.request(method.upper(), url)
            headers = {k.lower(): v for k, v in response.headers.items()}
            body = response.text
            result = ProbeResult(
                method=method.upper(),
                path=url,
                status_code=response.status_code,
                headers=headers,
                body=body,
                json_data=_parse_json(body),
            )
    except httpx.HTTPError as exc:
        result = ProbeResult(
            method=method.upper(),
            path=url,
            status_code=None,
            headers={},
            body="",
            json_data=None,
            error=str(exc),
        )
    _append_request_log(request_log, method, url, result)
    return result


def probe_endpoint(
    host: str,
    port: int,
    indicator: Indicator,
    timeout: float = 2.0,
    request_log: list[RequestLogEntry] | None = None,
) -> ProbeResult:
    primary = _preferred_scheme(port)
    fallback = "https" if primary == "http" else "http"
    path = indicator.path

    for scheme in (primary, fallback):
        url = _build_url(host, port, path, scheme)
        result = _do_request(url, indicator.method, timeout, request_log)
        if result.ok:
            result.path = path
            return result

    result = _do_request(_build_url(host, port, path, primary), indicator.method, timeout, request_log)
    result.path = path
    return result


def probe_for_header(
    host: str,
    port: int,
    timeout: float = 2.0,
    request_log: list[RequestLogEntry] | None = None,
) -> ProbeResult:
    """Lightweight probe to collect response headers for header-type indicators."""
    for path in ("/", "/v2/health/ready", "/api/tags"):
        indicator = Indicator(id="_probe", type="endpoint", method="GET", path=path)
        result = probe_endpoint(host, port, indicator, timeout, request_log)
        if result.ok:
            return result
    return ProbeResult(
        method="GET",
        path="/",
        status_code=None,
        headers={},
        body="",
        json_data=None,
        error="no response",
    )
