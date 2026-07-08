from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ProbeResult:
    method: str
    path: str
    status_code: int | None
    headers: dict[str, str]
    body: str
    json_data: dict[str, Any] | list[Any] | None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.status_code is not None


@dataclass
class UnlessGuard:
    header: str
    contains: str | None = None
    must_exist: bool = False


@dataclass
class Indicator:
    id: str
    type: str
    method: str = "GET"
    path: str = "/"
    expected_status: list[int] = field(default_factory=lambda: [200])
    header: str | None = None
    must_exist: bool = False
    contains: str | None = None
    required_keys: list[str] = field(default_factory=list)
    unless: list[UnlessGuard] = field(default_factory=list)
    body_contains: list[str] = field(default_factory=list)


@dataclass
class ServiceDefinition:
    id: str
    name: str
    description: str = ""
    version: str = ""
    port_hints: list[int] = field(default_factory=list)
    indicators: list[Indicator] = field(default_factory=list)


@dataclass
class RequestLogEntry:
    method: str
    url: str
    status_code: int | None = None
    error: str | None = None


@dataclass
class GatheredData:
    host: str
    port: int
    base_url: str
    probes: dict[str, ProbeResult] = field(default_factory=dict)
    request_log: list[RequestLogEntry] = field(default_factory=list)


@dataclass
class IndicatorResult:
    indicator_id: str
    matched: bool
    reason: str


@dataclass
class MatchResult:
    identified: bool
    matched_indicator: str | None = None
    reason: str = ""
    indicator_results: list[IndicatorResult] = field(default_factory=list)

    @property
    def verified_results(self) -> list[IndicatorResult]:
        return [r for r in self.indicator_results if r.matched]


@dataclass
class PortScanResult:
    port: int
    state: str
    service_id: str | None = None
    service_name: str | None = None
    description: str = ""
    version: str = ""
    matched_indicator: str | None = None
    match_reason: str = ""
    suspected: str | None = None
    indicator_results: list[IndicatorResult] = field(default_factory=list)
    request_logs: list[RequestLogEntry] = field(default_factory=list)

    @property
    def verified_results(self) -> list[IndicatorResult]:
        return [r for r in self.indicator_results if r.matched]
