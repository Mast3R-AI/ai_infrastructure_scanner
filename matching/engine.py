from __future__ import annotations

from gathering.collector import collect
from matching.loader import load_hierarchy, load_port_hints, load_service
from matching.rules import evaluate_service
from models import IndicatorResult, PortScanResult, RequestLogEntry, ServiceDefinition


class ScanEngine:
    def __init__(self, timeout: float = 2.0):
        self.timeout = timeout
        self.hierarchy = load_hierarchy()
        self.port_hints = load_port_hints()
        self._services: dict[str, ServiceDefinition] = {}

    def _get_service(self, service_id: str) -> ServiceDefinition:
        if service_id not in self._services:
            self._services[service_id] = load_service(service_id)
        return self._services[service_id]

    def _suspect(self, port: int) -> str | None:
        return self.port_hints.get(port)

    def identify_port(
        self, host: str, port: int, aggressive: bool = False, port_state: str = "open"
    ) -> list[PortScanResult]:
        all_indicator_results: list[IndicatorResult] = []
        all_request_logs: list[RequestLogEntry] = []
        matches: list[PortScanResult] = []

        for service_id in self.hierarchy:
            service = self._get_service(service_id)
            gathered = collect(host, port, service, self.timeout)
            all_request_logs.extend(gathered.request_log)
            match = evaluate_service(gathered, service.indicators)
            if match.identified:
                result = PortScanResult(
                    port=port,
                    state=port_state,
                    service_id=service.id,
                    service_name=service.name,
                    description=service.description,
                    version=service.version,
                    matched_indicator=match.matched_indicator,
                    match_reason=match.reason,
                    indicator_results=match.indicator_results,
                    request_logs=list(gathered.request_log),
                )
                if aggressive:
                    matches.append(result)
                    continue
                return [result]
            all_indicator_results.extend(match.indicator_results)

        if matches:
            return matches

        return [
            PortScanResult(
                port=port,
                state=port_state,
                service_id=None,
                service_name=None,
                suspected=self._suspect(port),
                indicator_results=all_indicator_results,
                request_logs=all_request_logs,
            )
        ]

    def scan_host(
        self,
        host: str,
        ports: list[int],
        aggressive: bool = False,
        port_states: dict[int, str] | None = None,
    ) -> list[PortScanResult]:
        results: list[PortScanResult] = []
        for port in ports:
            state = (port_states or {}).get(port, "open")
            results.extend(
                self.identify_port(host, port, aggressive=aggressive, port_state=state)
            )
        return results
