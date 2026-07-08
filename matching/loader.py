from __future__ import annotations

from pathlib import Path

import yaml

from models import Indicator, ServiceDefinition, UnlessGuard

SERVICES_DIR = Path(__file__).resolve().parent.parent / "services"
CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"


def _parse_unless(raw: list[dict] | None) -> list[UnlessGuard]:
    if not raw:
        return []
    guards = []
    for item in raw:
        guards.append(
            UnlessGuard(
                header=item["header"],
                contains=item.get("contains"),
                must_exist=item.get("must_exist", False),
            )
        )
    return guards


def _parse_indicator(raw: dict) -> Indicator:
    json_block = raw.get("json") or {}
    return Indicator(
        id=raw["id"],
        type=raw["type"],
        method=raw.get("method", "GET"),
        path=raw.get("path", "/"),
        expected_status=raw.get("expected_status", [200]),
        header=raw.get("header"),
        must_exist=raw.get("must_exist", False),
        contains=raw.get("contains"),
        required_keys=json_block.get("required_keys", []),
        unless=_parse_unless(raw.get("unless")),
        body_contains=raw.get("body_contains", []),
    )


def load_service(service_id: str) -> ServiceDefinition:
    path = SERVICES_DIR / f"{service_id}.yaml"
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return ServiceDefinition(
        id=data["id"],
        name=data["name"],
        description=data.get("description", ""),
        version=data.get("version", ""),
        port_hints=data.get("port_hints", []),
        indicators=[_parse_indicator(i) for i in data.get("indicators", [])],
    )


def load_hierarchy() -> list[str]:
    path = SERVICES_DIR / "hierarchy.yaml"
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data["services"]


def load_port_hints() -> dict[int, str]:
    path = SERVICES_DIR / "port_hints.yaml"
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return {int(k): v for k, v in data.get("hints", {}).items()}


def load_default_ports() -> list[int]:
    path = CONFIG_DIR / "default_ports.yaml"
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data["ports"]
