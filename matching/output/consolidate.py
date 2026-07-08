from __future__ import annotations

import re
from collections import defaultdict

from models import IndicatorResult

_ENDPOINT_OK = re.compile(r"^(GET|POST) (\S+) -> 200 OK(?:, (.+))?$")
_BODY_MISSING = re.compile(r"^(GET|POST) (\S+) -> body missing '([^']+)'$")
_JSON_KEYS = re.compile(r"^JSON key\(s\): (.+)$")
_BODY_CONTAINS = re.compile(r"^body contains '([^']+)'(?: \(\+\d+ more\))?$")
_GRPC_PROBE = re.compile(r"^gRPC probe: (.+)$")


def _parse_endpoint_extra(tail: str, json_keys: set[str], body_hits: set[str]) -> None:
    if not tail:
        return
    json_match = _JSON_KEYS.match(tail)
    if json_match:
        json_keys.update(k.strip() for k in json_match.group(1).split(","))
        return
    body_match = _BODY_CONTAINS.match(tail)
    if body_match:
        body_hits.add(body_match.group(1))


def _format_endpoint_verified(
    method: str,
    path: str,
    json_keys: set[str],
    body_hits: set[str],
) -> str:
    line = f"{method} {path} -> 200 OK"
    extras: list[str] = []
    if json_keys:
        extras.append(f"JSON key(s): {', '.join(sorted(json_keys))}")
    if body_hits:
        quoted = ", ".join(f"'{b}'" for b in sorted(body_hits))
        extras.append(f"body: {quoted}")
    if extras:
        line += " [" + ", ".join(extras) + "]"
    return line


def consolidate_verified(indicators: list[IndicatorResult]) -> list[str]:
    endpoint_groups: dict[tuple[str, str], dict[str, set[str]]] = defaultdict(
        lambda: {"json": set(), "body": set()}
    )
    other_lines: list[str] = []

    for ind in indicators:
        if not ind.matched:
            continue

        grpc = _GRPC_PROBE.match(ind.reason)
        if grpc:
            other_lines.append(f"gRPC probe: {grpc.group(1)}")
            continue

        endpoint = _ENDPOINT_OK.match(ind.reason)
        if endpoint:
            method, path, tail = endpoint.group(1), endpoint.group(2), endpoint.group(3)
            group = endpoint_groups[(method, path)]
            _parse_endpoint_extra(tail or "", group["json"], group["body"])
            continue

        other_lines.append(ind.reason)

    merged: list[str] = []
    for (method, path) in sorted(endpoint_groups.keys()):
        group = endpoint_groups[(method, path)]
        merged.append(_format_endpoint_verified(method, path, group["json"], group["body"]))

    merged.extend(other_lines)
    return merged


def consolidate_not_verified(indicators: list[IndicatorResult]) -> list[str]:
    missing_groups: dict[tuple[str, str], set[str]] = defaultdict(set)
    other_lines: list[str] = []

    for ind in indicators:
        if ind.matched:
            continue

        missing = _BODY_MISSING.match(ind.reason)
        if missing:
            method, path, keyword = missing.group(1), missing.group(2), missing.group(3)
            missing_groups[(method, path)].add(keyword)
            continue

        other_lines.append(ind.reason)

    merged: list[str] = []
    for (method, path) in sorted(missing_groups.keys()):
        keywords = sorted(missing_groups[(method, path)])
        quoted = ", ".join(f"'{k}'" for k in keywords)
        merged.append(f"{method} {path} -> body missing {quoted}")

    merged.extend(other_lines)
    return merged
