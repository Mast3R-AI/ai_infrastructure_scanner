#!/usr/bin/env python3
"""
Fast gRPC / HTTP/2 (h2c) detector using nmap-style TCP probes.

Technique (nmap HTTP2ClientMagic / RFC 7540):
  1. HTTP/1.0 GET — classic service probe; gRPC stacks often reject HTTP/1.x
     with messages mentioning grpc or HTTP/2.
  2. HTTP/2 connection preface — send client magic:
       PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n
     Match server SETTINGS frame (nmap: m/^.{3}\\x04\\x00{5}/) or GOAWAY.

Stdlib only; no full gRPC handshake.
"""
from __future__ import annotations

import argparse
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

# RFC 7540 HTTP/2 connection preface (client magic)
HTTP2_CLIENT_MAGIC = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
HTTP2_PREFACE_LEN = len(HTTP2_CLIENT_MAGIC)

# nmap http2 probe: SETTINGS frame header at response start
HTTP2_SETTINGS_AT_START = re.compile(rb"^.{3}\x04\x00{5}", re.DOTALL)

HTTP10_GET = b"GET / HTTP/1.0\r\n\r\n"

# Text/binary hints in cleartext responses
GRPC_BYTE_HINTS: tuple[tuple[bytes, str], ...] = (
    (b"application/grpc", "application/grpc"),
    (b"grpc-status", "grpc-status"),
    (b"grpc-message", "grpc-message"),
    (b"invalid grpc request", "invalid gRPC request"),
    (b"transport:", "gRPC transport error"),
    (b"HTTP/2", "HTTP/2"),
    (b"http2", "http2"),
    (b"h2 ", "h2 protocol"),
    (b"PRI * HTTP/2.0", "HTTP/2 connection preface"),
)

# HTTP/2 frame types that indicate an HTTP/2 stack answered
_HTTP2_FRAME_TYPES = {
    0x00: "HTTP/2 DATA frame",
    0x04: "HTTP/2 SETTINGS frame",
    0x07: "HTTP/2 GOAWAY frame",
}


@dataclass
class GrpcProbeResult:
    host: str
    port: int
    is_grpc: bool
    indicator: str = ""
    raw_response_preview: str = ""
    error: str | None = None


def _preview(data: bytes, limit: int = 120) -> str:
    if not data:
        return ""
    printable = "".join(chr(b) if 32 <= b < 127 else "." for b in data[:limit])
    hex_head = data[:32].hex()
    return f"{printable!r} | hex:{hex_head}"


def _http2_frame_indicator(data: bytes) -> str | None:
    if HTTP2_SETTINGS_AT_START.match(data):
        return "HTTP/2 SETTINGS frame after connection preface"

    # Server may echo the 24-byte preface before its SETTINGS frame.
    for offset in (0, HTTP2_PREFACE_LEN):
        if offset >= len(data):
            continue
        chunk = data[offset:]
        if len(chunk) < 9:
            continue
        frame_type = chunk[3]
        if frame_type in _HTTP2_FRAME_TYPES:
            return _HTTP2_FRAME_TYPES[frame_type]

    return None


def grpc_indicator(data: bytes) -> str | None:
    """Return a short label when *data* looks like a gRPC/HTTP/2 response."""
    if not data:
        return None

    frame_hit = _http2_frame_indicator(data)
    if frame_hit:
        return frame_hit

    lower = data.lower()
    for needle, label in GRPC_BYTE_HINTS:
        if needle.lower() in lower:
            return label

    # HTTP/1.x status line + body insisting on HTTP/2 (common on gRPC ports)
    if data.startswith(b"HTTP/1") and (b"HTTP/2" in data or b"http2" in lower):
        return "HTTP/1.x rejected, HTTP/2 required"

    return None


def is_grpc_response(data: bytes) -> bool:
    return grpc_indicator(data) is not None


def _tcp_exchange(host: str, port: int, payload: bytes, timeout: float) -> tuple[bytes, str | None]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        sock.sendall(payload)
        chunks: list[bytes] = []
        total = 0
        while total < 4096:
            try:
                block = sock.recv(4096)
                if not block:
                    break
                chunks.append(block)
                total += len(block)
            except socket.timeout:
                break
        return b"".join(chunks), None
    except OSError as exc:
        return b"", str(exc)
    finally:
        sock.close()


def probe_grpc(host: str, port: int, timeout: float = 2.0) -> GrpcProbeResult:
    if not 1 <= port <= 65535:
        return GrpcProbeResult(host=host, port=port, is_grpc=False, error="invalid port")

    probes = (
        ("HTTP/1.0 GET", HTTP10_GET),
        ("HTTP/2 connection preface", HTTP2_CLIENT_MAGIC),
    )

    last_data = b""
    last_error: str | None = None

    for _probe_name, payload in probes:
        data, error = _tcp_exchange(host, port, payload, timeout)
        last_data = data
        last_error = error

        if error and not data:
            continue

        indicator = grpc_indicator(data)
        if indicator:
            return GrpcProbeResult(
                host=host,
                port=port,
                is_grpc=True,
                indicator=indicator,
                raw_response_preview=_preview(data),
            )

    return GrpcProbeResult(
        host=host,
        port=port,
        is_grpc=False,
        raw_response_preview=_preview(last_data),
        error=last_error,
    )


def scan_ports_for_grpc(
    host: str,
    ports: list[int],
    timeout: float = 2.0,
    threads: int = 100,
) -> list[GrpcProbeResult]:
    results: list[GrpcProbeResult] = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(probe_grpc, host, port, timeout): port for port in ports}
        for future in as_completed(futures):
            result = future.result()
            if result.is_grpc:
                results.append(result)
    return sorted(results, key=lambda r: r.port)


def _parse_ports(port_spec: str) -> list[int]:
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


def _print_results(host: str, results: list[GrpcProbeResult], verbose: bool) -> None:
    print(f"gRPC scan {host} ...\n")
    if not results:
        print("No gRPC/HTTP/2 endpoints found.")
        return
    print(f"{'PORT':<12}{'STATE':<8}{'INDICATOR'}")
    for r in results:
        print(f"{r.port}/tcp{'':<4}{'open':<8}{r.indicator}")
        if verbose:
            print(f"  raw: {r.raw_response_preview}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="grpc_probe",
        description="Fast gRPC detector (nmap-style HTTP/1.0 + HTTP/2 preface probes).",
    )
    parser.add_argument("host", help="Target host")
    parser.add_argument(
        "-p",
        dest="ports",
        default="50051,9090,50052",
        metavar="PORTS",
        help="Ports to probe (default: 50051,9090,50052)",
    )
    parser.add_argument("--timeout", type=float, default=2.0, help="Timeout per probe (seconds)")
    parser.add_argument("--threads", type=int, default=100, help="Concurrent probes")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show raw response preview")
    args = parser.parse_args(argv)

    ports = _parse_ports(args.ports)
    results = scan_ports_for_grpc(args.host, ports, timeout=args.timeout, threads=args.threads)
    _print_results(args.host, results, verbose=args.verbose)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
