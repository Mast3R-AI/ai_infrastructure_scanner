from __future__ import annotations

from matching.output.consolidate import consolidate_not_verified, consolidate_verified
from models import IndicatorResult, PortScanResult, RequestLogEntry


def format_verified_line(reason: str) -> str:
    return f"  |- Verified: {reason}"


def format_not_verified_line(reason: str) -> str:
    return f"  |- Not verified: {reason}"


def format_verified(indicator: IndicatorResult) -> str:
    return format_verified_line(indicator.reason)


def format_not_verified(indicator: IndicatorResult) -> str:
    return format_not_verified_line(indicator.reason)


def format_description(result: PortScanResult) -> str:
    if result.service_id:
        return " ".join(result.description.split())
    if result.suspected:
        return f"(suspected: {result.suspected})"
    return ""


def format_version(version: str) -> str:
    return version if version else "-"


def format_request_log_entry(entry: RequestLogEntry) -> str:
    if entry.error:
        return f"{entry.method} {entry.url} -> {entry.error}"
    return f"{entry.method} {entry.url} -> {entry.status_code}"
