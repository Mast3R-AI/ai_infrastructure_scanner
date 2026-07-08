"""Smoke test: mock Ollama and Triton servers, then run scanner."""
from __future__ import annotations

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


class OllamaHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/api/tags":
            body = json.dumps({"models": []}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        pass


class PrometheusHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/metrics":
            body = (
                "# HELP nv_inference_request_success Number of successful inference requests\n"
                "# TYPE nv_inference_request_success counter\n"
                "nv_inference_request_success{model=\"test\",version=\"1\"} 42\n"
                "# HELP nv_gpu_utilization GPU utilization rate\n"
                "# TYPE nv_gpu_utilization gauge\n"
                "nv_gpu_utilization{gpu_uuid=\"GPU-0\"} 0.15\n"
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        pass


class TritonHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/v2/health/ready":
            self.send_response(200)
            self.send_header("NV-Status", "READY")
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        pass


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run_smoke_test() -> None:
    ollama_port = free_port()
    triton_port = free_port()
    prometheus_port = free_port()

    ollama_srv = HTTPServer(("127.0.0.1", ollama_port), OllamaHandler)
    triton_srv = HTTPServer(("127.0.0.1", triton_port), TritonHandler)
    prometheus_srv = HTTPServer(("127.0.0.1", prometheus_port), PrometheusHandler)

    t1 = threading.Thread(target=ollama_srv.serve_forever, daemon=True)
    t2 = threading.Thread(target=triton_srv.serve_forever, daemon=True)
    t3 = threading.Thread(target=prometheus_srv.serve_forever, daemon=True)
    t1.start()
    t2.start()
    t3.start()

    from ai_scanner import main

    print("=== Ollama mock (default) ===")
    main(["127.0.0.1", "-p", str(ollama_port)])
    print()
    print("=== Ollama mock (-v) ===")
    main(["127.0.0.1", "-p", str(ollama_port), "-v"])
    print()
    print("=== Triton mock ===")
    main(["127.0.0.1", "-p", str(triton_port), "-v"])
    print()
    print("=== NVIDIA Prometheus mock ===")
    main(["127.0.0.1", "-p", str(prometheus_port), "-v"])
    print()
    print("=== Aggressive mode (open port) ===")
    main(["127.0.0.1", "-p", str(ollama_port), "-a", "-v"])
    print()
    print("=== Aggressive mode (closed port) ===")
    main(["127.0.0.1", "-p", "1", "-a"])

    ollama_srv.shutdown()
    triton_srv.shutdown()
    prometheus_srv.shutdown()


if __name__ == "__main__":
    run_smoke_test()
