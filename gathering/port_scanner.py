from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


def parse_ports(port_spec: str | None, all_ports: bool, default_ports: list[int]) -> list[int]:
    if all_ports:
        return list(range(1, 65536))
    if port_spec is None:
        return default_ports

    ports: set[int] = set()
    for part in port_spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start, end = int(start_s), int(end_s)
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def _port_connect_state(host: str, port: int, timeout: float) -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        if sock.connect_ex((host, port)) == 0:
            return "open"
    except OSError:
        pass
    finally:
        sock.close()
    return "closed"


def _check_port(host: str, port: int, timeout: float) -> int | None:
    if _port_connect_state(host, port, timeout) == "open":
        return port
    return None


def scan_ports(host: str, ports: list[int], timeout: float = 2.0, threads: int = 100) -> list[int]:
    open_ports: list[int] = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(_check_port, host, port, timeout): port for port in ports}
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                open_ports.append(result)
    return sorted(open_ports)


def scan_port_states(
    host: str, ports: list[int], timeout: float = 2.0, threads: int = 100
) -> dict[int, str]:
    states: dict[int, str] = {}
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(_port_connect_state, host, port, timeout): port for port in ports}
        for future in as_completed(futures):
            port = futures[future]
            states[port] = future.result()
    return states
