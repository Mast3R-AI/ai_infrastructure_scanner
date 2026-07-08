#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys

from gathering.port_scanner import parse_ports, scan_port_states, scan_ports
from matching.engine import ScanEngine
from matching.grpc_scan import apply_grpc_scan
from matching.loader import load_default_ports
from matching.output.formatter import print_results


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ai_scanner",
        description="AI service scanner — identify ML/AI services by HTTP fingerprints (nmap-style ports).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  ai_scanner 192.168.1.10
  ai_scanner 192.168.1.10 -p 80,11434
  ai_scanner 192.168.1.10 -p 1-1024
  ai_scanner 192.168.1.10 -p-
  ai_scanner 192.168.1.10 -v
  ai_scanner 192.168.1.10 -p 80 -a
  ai_scanner 192.168.1.10 -p 50051 -g""",
        add_help=True,
    )
    parser.add_argument("host", nargs="?", help="Target host (IP or hostname)")
    port_group = parser.add_mutually_exclusive_group()
    port_group.add_argument(
        "-p",
        dest="ports",
        metavar="PORTS",
        help="Ports to scan (e.g. 80,443 or 1-1024)",
    )
    port_group.add_argument(
        "-p-",
        dest="all_ports",
        action="store_true",
        help="Scan all ports (1-65535)",
    )
    parser.add_argument("--timeout", type=float, default=2.0, help="Timeout per port/probe in seconds")
    parser.add_argument("--threads", type=int, default=100, help="Concurrent threads for port scan")
    parser.add_argument(
        "-v",
        action="count",
        default=0,
        help="Increase verbosity: -v verified indicators, -vv all indicators, -vvv request log",
    )
    parser.add_argument(
        "-a",
        "--aggressive",
        action="store_true",
        help="Probe all ports regardless of TCP state; test every service (no early exit)",
    )
    parser.add_argument(
        "-g",
        "--grpc",
        action="store_true",
        help="Run gRPC probe on every port (-a includes closed ports)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.host is None:
        parser.print_help()
        return 0

    default_ports = load_default_ports()
    ports = parse_ports(args.ports, args.all_ports, default_ports)

    engine = ScanEngine(timeout=args.timeout)
    need_states = args.aggressive or args.grpc
    port_states = (
        scan_port_states(args.host, ports, timeout=args.timeout, threads=args.threads)
        if need_states
        else {}
    )

    if args.aggressive:
        results = engine.scan_host(
            args.host, ports, aggressive=True, port_states=port_states
        )
    else:
        open_ports = scan_ports(args.host, ports, timeout=args.timeout, threads=args.threads)
        if not open_ports and not args.grpc:
            print(f"Scanning {args.host} ...", file=sys.stdout)
            print("\nNo open ports found.", file=sys.stdout)
            return 0
        if not port_states and open_ports:
            port_states = {p: "open" for p in open_ports}
        results = engine.scan_host(args.host, open_ports, port_states=port_states)

    results = apply_grpc_scan(
        args.host,
        results,
        ports,
        port_states,
        grpc_all=args.grpc,
        aggressive=args.aggressive,
        timeout=args.timeout,
    )

    print_results(args.host, results, verbosity=args.v)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
