"""KeyRelay test relying party: a local web page that registers and signs in with a
security key and shows every verification check.

Run:  uv run server.py
Then open the printed address in a browser on the same machine.

Settings (environment variables):
  KEYRELAY_RP_HOST   address to listen on       (default 127.0.0.1)
  KEYRELAY_RP_PORT   port to listen on          (default 8765)
  KEYRELAY_RP_ID     WebAuthn RP ID             (default localhost)
  KEYRELAY_RP_ORIGIN expected browser origin    (default http://localhost:<port>)
  KEYRELAY_RP_DATA   credential store file      (default data/credentials.json)
"""

from __future__ import annotations

import json
import os
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from verifier import RelyingParty, Result, b64url_decode

HERE = Path(__file__).resolve().parent
DATA_FILE = Path(os.environ.get("KEYRELAY_RP_DATA", HERE / "data" / "credentials.json"))
INDEX = HERE / "static" / "index.html"

HOST = os.environ.get("KEYRELAY_RP_HOST", "127.0.0.1")
PORT = int(os.environ.get("KEYRELAY_RP_PORT", "8765"))
RP_ID = os.environ.get("KEYRELAY_RP_ID", "localhost")
ORIGIN = os.environ.get("KEYRELAY_RP_ORIGIN", f"http://localhost:{PORT}")

rp = RelyingParty(RP_ID, ORIGIN)
lock = threading.Lock()
last_finish: dict[str, dict] = {}  # most recent browser response per ceremony, for replay tests

if DATA_FILE.exists():
    rp.load_credentials(json.loads(DATA_FILE.read_text()))


def save() -> None:
    DATA_FILE.parent.mkdir(exist_ok=True)
    DATA_FILE.write_text(json.dumps(rp.dump_credentials(), indent=2))


def report(kind: str, result: Result) -> dict:
    failed = [c.name for c in result.checks if not c.ok]
    print(f"[{kind}] {'PASS' if result.ok else 'FAIL'}" + (f" failed={failed}" if failed else ""), flush=True)
    return {"ok": result.ok, "checks": [c.__dict__ for c in result.checks]}


def finish_registration(body: dict) -> dict:
    resp = body["response"]
    result = rp.finish_registration(
        client_data_json=b64url_decode(resp["clientDataJSON"]),
        attestation_object=b64url_decode(resp["attestationObject"]),
    )
    if result.ok:
        save()
    return report("register", result)


def finish_authentication(body: dict) -> dict:
    resp = body["response"]
    result = rp.finish_authentication(
        credential_id=b64url_decode(body["rawId"]),
        client_data_json=b64url_decode(resp["clientDataJSON"]),
        authenticator_data=b64url_decode(resp["authenticatorData"]),
        signature=b64url_decode(resp["signature"]),
    )
    if result.ok:
        save()
    return report("sign-in", result)


def credentials_summary() -> dict:
    return {
        "rp_id": rp.rp_id,
        "origin": rp.origin,
        "credentials": [
            {"username": c.username, "counter": c.counter, "aaguid": c.aaguid,
             "attestation_format": c.attestation_format}
            for c in rp.credentials.values()
        ],
    }


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # keep request bodies and noise out of the log
        pass

    def _send(self, status: int, payload: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def _json(self, payload: dict, status: int = HTTPStatus.OK) -> None:
        self._send(status, json.dumps(payload).encode(), "application/json")

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(HTTPStatus.OK, INDEX.read_bytes(), "text/html; charset=utf-8")
        elif self.path == "/api/credentials":
            with lock:
                self._json(credentials_summary())
        else:
            self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, json.JSONDecodeError):
            self._json({"error": "invalid JSON"}, HTTPStatus.BAD_REQUEST)
            return
        try:
            with lock:
                if self.path == "/api/register/begin":
                    username = str(body.get("username", "")).strip()
                    if not username:
                        self._json({"error": "username required"}, HTTPStatus.BAD_REQUEST)
                        return
                    self._json(rp.registration_options(username))
                elif self.path == "/api/register/finish":
                    last_finish["register"] = body
                    self._json(finish_registration(body))
                elif self.path == "/api/login/begin":
                    self._json(rp.authentication_options())
                elif self.path == "/api/login/finish":
                    last_finish["login"] = body
                    self._json(finish_authentication(body))
                elif self.path == "/api/login/replay":
                    if "login" not in last_finish:
                        self._json({"error": "no sign-in to replay yet"}, HTTPStatus.BAD_REQUEST)
                        return
                    self._json(finish_authentication(last_finish["login"]))
                else:
                    self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)
        except (KeyError, TypeError, ValueError) as exc:
            self._json({"error": f"malformed request: {type(exc).__name__}"}, HTTPStatus.BAD_REQUEST)


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"KeyRelay test RP: RP ID {RP_ID!r}, expected origin {ORIGIN}", flush=True)
    print(f"Listening on http://{HOST}:{PORT}  (open {ORIGIN} in the browser)", flush=True)
    print(f"{len(rp.credentials)} stored credential(s) in {DATA_FILE}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
