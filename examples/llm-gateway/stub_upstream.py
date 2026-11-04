"""Stand-in OpenAI-compatible upstream (stdlib only) for the LLM-gateway proof.

Plays NVIDIA NIM ("external") or a self-hosted vLLM ("local") so the gateway can be
proven without a real key. NOT used in production: there CHAT_PRIMARY_BASE points at
https://integrate.api.nvidia.com/v1 and LOCAL_LLM_BASE at your vLLM/NIM service.

Env:
  STUB_NAME  label echoed in every answer, so the caller sees WHICH upstream answered
  STUB_FAIL  "1" -> chat returns 503 (simulates NIM free-tier throttling / cold start)
  STUB_DIM   embedding vector size (default 1024 = qdrant_dense_size)

GET /last returns the last request body this upstream RECEIVED from the gateway, so the
proof can check what the gateway forwarded (e.g. NIM's input_type / truncate).
"""
from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

NAME = os.environ.get("STUB_NAME", "stub")
FAIL = os.environ.get("STUB_FAIL") == "1"
DIM = int(os.environ.get("STUB_DIM", "1024"))
_last: dict = {}


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path.endswith("/last"):
            self._send(200, _last)
        else:
            self._send(200, {"ok": True, "name": NAME})

    def do_POST(self) -> None:  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        _last.clear()
        _last.update({"path": self.path, "body": body})
        if self.path.endswith("/chat/completions"):
            if FAIL:
                self._send(503, {"error": {"message": f"{NAME} unavailable", "type": "overloaded"}})
                return
            self._send(200, {
                "id": "chatcmpl-stub", "object": "chat.completion", "created": 0,
                "model": body.get("model", ""),
                "choices": [{"index": 0, "finish_reason": "stop",
                             "message": {"role": "assistant", "content": f"[{NAME}] ok"}}],
                "usage": {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7},
            })
        elif self.path.endswith("/embeddings"):
            inputs = body.get("input", [])
            inputs = inputs if isinstance(inputs, list) else [inputs]
            self._send(200, {
                "object": "list", "model": body.get("model", ""),
                "data": [{"object": "embedding", "index": i, "embedding": [0.01] * DIM}
                         for i in range(len(inputs))],
                "usage": {"prompt_tokens": len(inputs), "total_tokens": len(inputs)},
            })
        else:
            self._send(404, {"error": {"message": f"no route {self.path}"}})

    def log_message(self, *_: object) -> None:
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
