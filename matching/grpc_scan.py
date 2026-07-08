from __future__ import annotations

from gathering.grpc_probe import GrpcProbeResult, probe_grpc
from matching.loader import load_service
from models import IndicatorResult, PortScanResult, ServiceDefinition


def _grpc_port_result(
    hit: GrpcProbeResult,
    port_state: str,
    service: ServiceDefinition,
) -> PortScanResult:
    return PortScanResult(
        port=hit.port,
        state=port_state,
        service_id=service.id,
        service_name=service.name,
        description=service.description,
        version=service.version,
        matched_indicator="grpc_probe",
        match_reason=hit.indicator,
        indicator_results=[
            IndicatorResult(
                indicator_id="grpc_probe",
                matched=True,
                reason=f"gRPC probe: {hit.indicator}",
            )
        ],
    )


def _grpc_target_ports(
    results: list[PortScanResult],
    ports: list[int],
    port_states: dict[int, str],
    *,
    grpc_all: bool,
    aggressive: bool,
) -> list[int]:
    if grpc_all:
        candidates = list(ports)
    else:
        candidates = sorted({r.port for r in results if r.service_id is None})

    if not aggressive:
        candidates = [p for p in candidates if port_states.get(p) == "open"]

    return candidates


def apply_grpc_scan(
    host: str,
    results: list[PortScanResult],
    ports: list[int],
    port_states: dict[int, str],
    *,
    grpc_all: bool,
    aggressive: bool,
    timeout: float,
) -> list[PortScanResult]:
    """Merge gRPC probe results into HTTP scan results.

    Default: probe unknown ports only (open unless -a).
    -g: probe every port in the scan list.
    -a: include closed ports in gRPC probes.
    """
    target_ports = _grpc_target_ports(
        results, ports, port_states, grpc_all=grpc_all, aggressive=aggressive
    )
    if not target_ports:
        return results

    grpc_service = load_service("grpc")
    hits: dict[int, GrpcProbeResult] = {}
    for port in target_ports:
        hit = probe_grpc(host, port, timeout)
        if hit.is_grpc:
            hits[port] = hit

    if not hits:
        return results

    merged: list[PortScanResult] = []
    grpc_added_for_port: set[int] = set()

    for result in results:
        if result.service_id is None and result.port in hits:
            state = port_states.get(result.port, result.state)
            merged.append(_grpc_port_result(hits[result.port], state, grpc_service))
            grpc_added_for_port.add(result.port)
        else:
            merged.append(result)
            if grpc_all and result.service_id and result.port in hits:
                if result.port not in grpc_added_for_port:
                    state = port_states.get(result.port, result.state)
                    merged.append(_grpc_port_result(hits[result.port], state, grpc_service))
                    grpc_added_for_port.add(result.port)

    for port, hit in sorted(hits.items()):
        if port in grpc_added_for_port:
            continue
        state = port_states.get(port, "closed")
        merged.append(_grpc_port_result(hit, state, grpc_service))

    merged.sort(key=lambda r: (r.port, 0 if r.service_id == "grpc" else 1, r.service_id or ""))
    return merged
