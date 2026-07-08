from __future__ import annotations

import sys

from matching.output.consolidate import consolidate_not_verified, consolidate_verified
from matching.output.explanations import (
    format_description,
    format_not_verified_line,
    format_request_log_entry,
    format_verified_line,
    format_version,
)
from models import PortScanResult

_PORT_WIDTH = 12
_STATE_WIDTH = 6
_SERVICE_WIDTH = 18
_VERSION_WIDTH = 10


def _service_name(result: PortScanResult) -> str:
    if result.service_id:
        return result.service_id
    return "unknown"


def _format_port_row(result: PortScanResult) -> str:
    port_line = f"{result.port}/tcp"
    service = _service_name(result)
    version = format_version(result.version)
    description = format_description(result)
    return (
        f"{port_line:<{_PORT_WIDTH}}"
        f"{result.state:<{_STATE_WIDTH + 2}}"
        f"{service:<{_SERVICE_WIDTH}}"
        f"{version:<{_VERSION_WIDTH}}"
        f"{description}"
    )


def _format_indicator_trees(result: PortScanResult, verbosity: int) -> list[str]:
    if verbosity < 1 or not result.service_id:
        return []

    lines: list[str] = []

    if verbosity >= 1:
        for reason in consolidate_verified(result.indicator_results):
            lines.append(format_verified_line(reason))

    if verbosity >= 2:
        for reason in consolidate_not_verified(result.indicator_results):
            lines.append(format_not_verified_line(reason))

    return lines


def _format_request_logs(results: list[PortScanResult]) -> list[str]:
    lines: list[str] = []
    for result in results:
        for entry in result.request_logs:
            lines.append(format_request_log_entry(entry))
    return lines


def format_results(host: str, results: list[PortScanResult], verbosity: int = 0) -> str:
    lines = [f"Scanning {host} ..."]

    if verbosity >= 3:
        request_lines = _format_request_logs(results)
        if request_lines:
            lines.append("")
            lines.extend(request_lines)

    lines.extend(
        [
            "",
            f"{'PORT':<{_PORT_WIDTH}}"
            f"{'STATE':<{_STATE_WIDTH + 2}}"
            f"{'SERVICE':<{_SERVICE_WIDTH}}"
            f"{'VERSION':<{_VERSION_WIDTH}}"
            f"DESCRIPTION",
        ]
    )

    for result in results:
        lines.append(_format_port_row(result))
        lines.extend(_format_indicator_trees(result, verbosity))

    return "\n".join(lines)


def print_results(host: str, results: list[PortScanResult], verbosity: int = 0) -> None:
    output = format_results(host, results, verbosity)
    print(output, file=sys.stdout)
