from __future__ import annotations

from models import GatheredData, Indicator, IndicatorResult, MatchResult, ProbeResult, UnlessGuard


def _probe_key(method: str, path: str) -> str:
    return f"{method.upper()}:{path}"


def _get_probe(gathered: GatheredData, indicator: Indicator) -> ProbeResult | None:
    key = _probe_key(indicator.method, indicator.path)
    if key in gathered.probes:
        return gathered.probes[key]
    if indicator.id in gathered.probes:
        return gathered.probes[indicator.id]
    return gathered.probes.get("_header_probe")


def _header_value(headers: dict[str, str], name: str) -> str | None:
    return headers.get(name.lower())


def _unless_triggered(headers: dict[str, str], guards: list[UnlessGuard]) -> bool:
    for guard in guards:
        value = _header_value(headers, guard.header)
        if guard.must_exist and value is None:
            return True
        if guard.contains and value and guard.contains.lower() in value.lower():
            return True
    return False


def _json_has_keys(data: dict | list | None, keys: list[str]) -> bool:
    if not isinstance(data, dict):
        return False
    return all(key in data for key in keys)


def _evaluate_endpoint(indicator: Indicator, probe: ProbeResult | None) -> IndicatorResult:
    if probe is None or not probe.ok:
        err = probe.error if probe else "no probe data"
        return IndicatorResult(
            indicator_id=indicator.id,
            matched=False,
            reason=f"GET {indicator.path} -> {err or 'no response'}",
        )

    if probe.status_code not in indicator.expected_status:
        return IndicatorResult(
            indicator_id=indicator.id,
            matched=False,
            reason=f"GET {indicator.path} -> {probe.status_code}",
        )

    if indicator.required_keys and not _json_has_keys(probe.json_data, indicator.required_keys):
        missing = [k for k in indicator.required_keys if not _json_has_keys(probe.json_data, [k])]
        return IndicatorResult(
            indicator_id=indicator.id,
            matched=False,
            reason=f"GET {indicator.path} -> 200 but JSON missing keys: {', '.join(missing)}",
        )

    if indicator.body_contains:
        for keyword in indicator.body_contains:
            if keyword not in probe.body:
                return IndicatorResult(
                    indicator_id=indicator.id,
                    matched=False,
                    reason=f"GET {indicator.path} -> body missing '{keyword}'",
                )

    if indicator.required_keys:
        return IndicatorResult(
            indicator_id=indicator.id,
            matched=True,
            reason=f"GET {indicator.path} -> 200 OK, JSON key(s): {', '.join(indicator.required_keys)}",
        )
    if indicator.body_contains:
        return IndicatorResult(
            indicator_id=indicator.id,
            matched=True,
            reason=f"GET {indicator.path} -> 200 OK, body contains '{indicator.body_contains[0]}'"
            + (f" (+{len(indicator.body_contains) - 1} more)" if len(indicator.body_contains) > 1 else ""),
        )
    return IndicatorResult(
        indicator_id=indicator.id,
        matched=True,
        reason=f"GET {indicator.path} -> 200 OK",
    )


def _evaluate_header(indicator: Indicator, gathered: GatheredData) -> IndicatorResult:
    headers: dict[str, str] = {}
    for probe in gathered.probes.values():
        headers.update(probe.headers)

    if not headers:
        return IndicatorResult(
            indicator_id=indicator.id,
            matched=False,
            reason=f"header {indicator.header} not found",
        )

    if _unless_triggered(headers, indicator.unless):
        return IndicatorResult(
            indicator_id=indicator.id,
            matched=False,
            reason=f"header {indicator.header} disqualified by unless guard",
        )

    value = _header_value(headers, indicator.header or "")
    if indicator.must_exist and value is None:
        return IndicatorResult(
            indicator_id=indicator.id,
            matched=False,
            reason=f"header {indicator.header} not found",
        )

    if indicator.contains:
        if value is None or indicator.contains.lower() not in value.lower():
            return IndicatorResult(
                indicator_id=indicator.id,
                matched=False,
                reason=f"header {indicator.header} does not contain '{indicator.contains}'",
            )
        return IndicatorResult(
            indicator_id=indicator.id,
            matched=True,
            reason=f"header {indicator.header} contains '{indicator.contains}'",
        )

    if indicator.must_exist and value is not None:
        return IndicatorResult(
            indicator_id=indicator.id,
            matched=True,
            reason=f"header {indicator.header} present",
        )

    return IndicatorResult(
        indicator_id=indicator.id,
        matched=False,
        reason=f"header {indicator.header} not matched",
    )


def _evaluate_error_response(indicator: Indicator, probe: ProbeResult | None) -> IndicatorResult:
    if probe is None or not probe.ok:
        err = probe.error if probe else "no probe data"
        return IndicatorResult(
            indicator_id=indicator.id,
            matched=False,
            reason=f"{indicator.method} {indicator.path} -> {err or 'no response'}",
        )

    if probe.status_code not in indicator.expected_status:
        return IndicatorResult(
            indicator_id=indicator.id,
            matched=False,
            reason=f"{indicator.method} {indicator.path} -> {probe.status_code}",
        )

    for keyword in indicator.body_contains:
        if keyword not in probe.body:
            return IndicatorResult(
                indicator_id=indicator.id,
                matched=False,
                reason=f"{indicator.method} {indicator.path} -> body missing '{keyword}'",
            )

    return IndicatorResult(
        indicator_id=indicator.id,
        matched=True,
        reason=f"{indicator.method} {indicator.path} -> {probe.status_code}",
    )


def evaluate_indicator(indicator: Indicator, gathered: GatheredData) -> IndicatorResult:
    if indicator.type == "header":
        return _evaluate_header(indicator, gathered)
    probe = _get_probe(gathered, indicator)
    if indicator.type == "error_response":
        return _evaluate_error_response(indicator, probe)
    return _evaluate_endpoint(indicator, probe)


def evaluate_service(gathered: GatheredData, indicators: list[Indicator]) -> MatchResult:
    results: list[IndicatorResult] = []
    for indicator in indicators:
        results.append(evaluate_indicator(indicator, gathered))

    verified = [r for r in results if r.matched]
    first = verified[0] if verified else None
    return MatchResult(
        identified=bool(verified),
        matched_indicator=first.indicator_id if first else None,
        reason=first.reason if first else "",
        indicator_results=results,
    )
