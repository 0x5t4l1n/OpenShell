# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES.
# SPDX-License-Identifier: Apache-2.0

"""Test HTTP/WebSockets through one proxy endpoint; no application dependencies."""

import argparse
import base64
import http.client
import json
import os
import socket
import ssl
import time


def request(host, path="/", authority=None):
    stream = context.wrap_socket(socket.create_connection((args.proxy_host, args.proxy_port), 5), server_hostname=host)
    stream.sendall(f"GET {path} HTTP/1.1\r\nHost: {authority or host}\r\nConnection: close\r\n\r\n".encode())
    response = http.client.HTTPResponse(stream)
    response.begin()
    result = response.status, response.read()
    stream.close()
    return result


def websocket(host):
    stream = context.wrap_socket(socket.create_connection((args.proxy_host, args.proxy_port), 5), server_hostname=host)
    key = base64.b64encode(os.urandom(16)).decode()
    stream.sendall(f"GET /ws HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n\r\n".encode())
    headers = bytearray()
    while not headers.endswith(b"\r\n\r\n"):
        byte = stream.recv(1)
        if not byte:
            raise AssertionError("WebSocket handshake closed")
        headers.extend(byte)
    assert headers.startswith(b"HTTP/1.1 101"), headers
    payload, mask = b"proxy-routing-echo", os.urandom(4)
    stream.sendall(bytes([0x81, 0x80 | len(payload)]) + mask + bytes(value ^ mask[index % 4] for index, value in enumerate(payload)))
    with stream.makefile("rb") as reader:
        header = reader.read(2)
        assert header == bytes([0x81, len(payload)]), header
        assert reader.read(len(payload)) == payload
    stream.close()


parser = argparse.ArgumentParser()
parser.add_argument("--ca", required=True)
parser.add_argument("--proxy-host", default="127.0.0.1")
parser.add_argument("--proxy-port", type=int, default=25443)
parser.add_argument("--prefix", default="proxy-poc")
parser.add_argument("--domain", default="svc.openshell.internal")
args = parser.parse_args()
context = ssl.create_default_context(cafile=args.ca)

for suffix, service, port in [("a", "web", 8080), ("b", "web", 8080), ("b", "portal", 9090), ("c", "web", 8080)]:
    sandbox = f"{args.prefix}-{suffix}"
    hostname = f"default--{sandbox}--{service}.{args.domain}"
    deadline = time.monotonic() + 40
    while True:
        try:
            status, body = request(hostname)
            assert status == 200, (status, body)
            decoded = json.loads(body)
            assert (decoded["sandbox"], decoded["port"]) == (sandbox, port), decoded
            assert decoded["authorization"] is None
            websocket(hostname)
            print(f"PASS HTTPS/WebSocket {hostname} -> {sandbox}:{port}", flush=True)
            break
        except (OSError, http.client.HTTPException):
            if time.monotonic() >= deadline:
                raise
            time.sleep(1)

host = f"default--{args.prefix}-a--web.{args.domain}"
assert request(host, authority=f"default--{args.prefix}-b--web.{args.domain}")[0] == 421
print("PASS cross-sandbox Host mismatch rejected", flush=True)
try:
    request(f"default--{args.prefix}-a--undeclared.{args.domain}")
except (OSError, http.client.HTTPException):
    print("PASS undeclared SNI rejected", flush=True)
else:
    raise AssertionError("undeclared SNI was accepted")
