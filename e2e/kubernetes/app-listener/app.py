# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES.
# SPDX-License-Identifier: Apache-2.0

"""Dependency-free HTTP/WebSocket fixture with distinct sandbox and port replies."""

import argparse
import base64
import hashlib
import http.server
import json
import struct
import threading


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.headers.get("Upgrade", "").lower() == "websocket":
            key = self.headers["Sec-WebSocket-Key"]
            accept = base64.b64encode(
                hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
            ).decode()
            self.send_response(101)
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", accept)
            self.end_headers()
            while True:
                header = self.rfile.read(2)
                if len(header) != 2:
                    return
                opcode, length = header[0] & 15, header[1] & 127
                if opcode == 8:
                    return
                if length >= 126 or not header[1] & 128:
                    return
                mask = self.rfile.read(4)
                data = self.rfile.read(length)
                payload = bytes(value ^ mask[index % 4] for index, value in enumerate(data))
                self.wfile.write(bytes([0x80 | opcode, len(payload)]) + payload)
                self.wfile.flush()
        else:
            body = json.dumps(
                {"sandbox": identity, "port": self.server.server_port,
                 "authorization": self.headers.get("Authorization"), "host": self.headers.get("Host")}
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--identity", required=True)
    args = parser.parse_args()
    identity = args.identity
    for port in (8080, 9090):
        server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
    threading.Event().wait()
