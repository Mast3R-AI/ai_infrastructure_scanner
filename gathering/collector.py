from __future__ import annotations

from gathering.http_probe import probe_endpoint, probe_for_header
from models import GatheredData, Indicator, ProbeResult, ServiceDefinition


def _needs_endpoint_probe(indicator: Indicator) -> bool:
    return indicator.type in ("endpoint", "error_response")


def _needs_header_probe(indicators: list[Indicator]) -> bool:
    return any(i.type == "header" for i in indicators)


def _unique_endpoint_indicators(indicators: list[Indicator]) -> list[Indicator]:
    seen: set[tuple[str, str, str]] = set()
    unique: list[Indicator] = []
    for ind in indicators:
        if not _needs_endpoint_probe(ind):
            continue
        key = (ind.type, ind.method, ind.path)
        if key not in seen:
            seen.add(key)
            unique.append(ind)
    return unique


def collect(host: str, port: int, service: ServiceDefinition, timeout: float = 2.0) -> GatheredData:
    scheme = "https" if port in {443, 8443, 9443} else "http"
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        base_url = f"{scheme}://{host}"
    else:
        base_url = f"{scheme}://{host}:{port}"

    gathered = GatheredData(host=host, port=port, base_url=base_url)

    for indicator in _unique_endpoint_indicators(service.indicators):
        key = f"{indicator.method.upper()}:{indicator.path}"
        gathered.probes[key] = probe_endpoint(
            host, port, indicator, timeout, request_log=gathered.request_log
        )
        gathered.probes[indicator.id] = gathered.probes[key]

    if _needs_header_probe(service.indicators):
        gathered.probes["_header_probe"] = probe_for_header(
            host, port, timeout, request_log=gathered.request_log
        )

    return gathered
