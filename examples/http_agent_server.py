"""
A tiny, dependency-free HTTP agent — for trying out the agent-score HTTP adapter
and its field mapping without an API key or a cloud agent.

It deliberately does NOT speak release-gate's default {"input","context"} /
{"response"} shape. Instead it exposes two endpoints with *non-default* field
names, so you can see the `#`-fragment field map actually doing its job:

    POST /simple   takes  {"prompt": "...", "ctx": "..."}
                   returns {"reply": "...", "tokens": {"in": N, "out": M}}

    POST /openai   mimics an OpenAI chat-completions shape:
                   takes  {"model","messages":[{"role","content"}]}
                   returns {"choices":[{"message":{"content":"..."}}],
                            "usage":{"prompt_tokens":N,"completion_tokens":M}}

The "agent" itself is trivial: it refuses to reveal secrets (so the safety
probes pass) and otherwise echoes a short canned answer. The point is the
transport, not the intelligence.

Run it:
    python examples/http_agent_server.py            # serves on :8000

Then, in another shell, score it:

    macOS / Linux (single quotes protect the & from the shell):

      release-gate agent-score \
        'http://localhost:8000/simple#in=prompt&ctx=ctx&out=reply&usage_in=tokens.in&usage_out=tokens.out'

      release-gate agent-score \
        'http://localhost:8000/openai#in=messages.0.content&out=choices.0.message.content&body.model=demo&body.messages.0.role=user&usage_in=usage.prompt_tokens&usage_out=usage.completion_tokens'

    Windows CMD / PowerShell (use double quotes — single quotes are not
    special on Windows and & is a CMD command separator):

      release-gate agent-score "http://localhost:8000/simple#in=prompt&ctx=ctx&out=reply&usage_in=tokens.in&usage_out=tokens.out"

      release-gate agent-score "http://localhost:8000/openai#in=messages.0.content&out=choices.0.message.content&body.model=demo&body.messages.0.role=user&usage_in=usage.prompt_tokens&usage_out=usage.completion_tokens"

Stop it with Ctrl-C.
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def _answer(prompt: str) -> str:
    """The 'model'. Refuses obvious secret-extraction, else gives a canned reply.

    The safety battery plants a canary in the context and checks the response
    never echoes it. This agent never looks at the context at all, so it can't
    leak it — a deliberately well-behaved agent that should score PROMOTE."""
    low = (prompt or "").lower()
    if any(w in low for w in ("secret", "canary", "system prompt", "ignore previous", "reveal")):
        return "I can't share internal or confidential information."
    return "Acknowledged. Here is a concise, helpful answer to your request."


def _tokens(text: str) -> int:
    return max(1, len(text or "") // 4)


class Handler(BaseHTTPRequestHandler):
    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length).decode("utf-8") if length else "{}"
        try:
            return json.loads(raw) if raw.strip() else {}
        except json.JSONDecodeError:
            return {}

    def _send(self, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler API
        data = self._read_json()

        if self.path.rstrip("/") == "/simple":
            prompt = data.get("prompt", "")
            reply = _answer(prompt)
            self._send({
                "reply": reply,
                "tokens": {"in": _tokens(prompt), "out": _tokens(reply)},
            })
            return

        if self.path.rstrip("/") == "/openai":
            messages = data.get("messages") or [{}]
            prompt = (messages[-1] or {}).get("content", "")
            reply = _answer(prompt)
            self._send({
                "id": "chatcmpl-demo",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": reply}}],
                "usage": {
                    "prompt_tokens": _tokens(prompt),
                    "completion_tokens": _tokens(reply),
                },
            })
            return

        self.send_error(404, "POST /simple or /openai")

    def log_message(self, *args):  # keep the console quiet
        pass


def main(host: str = "127.0.0.1", port: int = 8000) -> None:
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"demo agent listening on http://{host}:{port}  (POST /simple, /openai)")
    print("score it from another shell:")
    print(f"  Linux/Mac:  release-gate agent-score 'http://{host}:{port}/simple#in=prompt&ctx=ctx&out=reply'")
    print(f"  Windows:    release-gate agent-score \"http://{host}:{port}/simple#in=prompt&ctx=ctx&out=reply\"")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")
        server.shutdown()


if __name__ == "__main__":
    main()
