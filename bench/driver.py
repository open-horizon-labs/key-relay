"""Bench driver: plays Chrome and the receiver so the phone app can be tested
against the test relying party before the Pi receiver exists.

    Chrome role:   fetch options from the test RP, build clientDataJSON with the
                   RP's origin, submit the result and print the RP's checks.
    Receiver role: listen for the phone on interface B (docs/relay-contract.md),
                   send it CTAP requests as Chrome would send them to an
                   authenticator advertising built-in UV, and collect responses.

Bench shortcut: interface B runs as plain TCP with no pinned-key channel (D2).
Use it only on a private network such as a tailnet, with test credentials.

Usage:
    uv run --project bench bench/driver.py register [--user test-user]
    uv run --project bench bench/driver.py sign-in
    uv run --project bench bench/driver.py sign-in --probe   # send an up:false probe first
    uv run --project bench bench/driver.py sign-in --uv absent   # like userVerification "discouraged"
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import socket
import struct
import sys
import time
import urllib.request

from fido2 import cbor
from fido2.webauthn import AuthenticatorData

CTAP_MAKE_CREDENTIAL = 1
CTAP_GET_ASSERTION = 2
PROTOCOL_VERSION = 1
MAX_FRAME = 64 * 1024


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# Chrome role: what the browser builds before talking to an authenticator


def client_data_json(type_: str, challenge_b64: str, origin: str) -> bytes:
    """Same member order and compact form Chrome uses."""
    return json.dumps(
        {"type": type_, "challenge": challenge_b64, "origin": origin, "crossOrigin": False},
        separators=(",", ":"),
    ).encode()


def _options_map(uv: str, up: bool | None = None) -> dict:
    options = {}
    if uv == "true":
        options["uv"] = True
    if up is False:
        options["up"] = False
    return options


def make_credential_params(options: dict, client_data_hash: bytes, uv: str = "true") -> bytes:
    params = {
        1: client_data_hash,
        2: {"id": options["rp"]["id"], "name": options["rp"]["name"]},
        3: {"id": unb64u(options["user"]["id"]), "name": options["user"]["name"],
            "displayName": options["user"]["displayName"]},
        4: [{"alg": p["alg"], "type": p["type"]} for p in options["pubKeyCredParams"]],
    }
    if options.get("excludeCredentials"):
        params[5] = [{"id": unb64u(c["id"]), "type": c["type"]} for c in options["excludeCredentials"]]
    if opts := _options_map(uv):
        params[7] = opts
    return cbor.encode(params)


def get_assertion_params(options: dict, client_data_hash: bytes, uv: str = "true",
                         up: bool | None = None) -> bytes:
    params = {1: options["rpId"], 2: client_data_hash}
    if options.get("allowCredentials"):
        params[3] = [{"id": unb64u(c["id"]), "type": c["type"]} for c in options["allowCredentials"]]
    if opts := _options_map(uv, up):
        params[5] = opts
    return cbor.encode(params)


def registration_payload(response: dict, cdj: bytes) -> dict:
    """CTAP makeCredential response map -> the JSON the test RP's page would post."""
    auth_data = AuthenticatorData(response[2])
    credential_id = auth_data.credential_data.credential_id
    attestation_object = cbor.encode({"fmt": response[1], "authData": response[2], "attStmt": response[3]})
    return {
        "id": b64u(credential_id), "rawId": b64u(credential_id), "type": "public-key",
        "response": {"clientDataJSON": b64u(cdj), "attestationObject": b64u(attestation_object)},
    }


def assertion_payload(response: dict, cdj: bytes) -> dict:
    """CTAP getAssertion response map -> the JSON the test RP's page would post."""
    credential_id = response[1]["id"]
    return {
        "id": b64u(credential_id), "rawId": b64u(credential_id), "type": "public-key",
        "response": {"clientDataJSON": b64u(cdj), "authenticatorData": b64u(response[2]),
                     "signature": b64u(response[3])},
    }


# Receiver role: interface B framing and session


def encode_frame(message: dict) -> bytes:
    body = json.dumps(message, separators=(",", ":")).encode()
    if len(body) > MAX_FRAME:
        raise ValueError("frame too large")
    return struct.pack(">I", len(body)) + body


class ProtocolError(Exception):
    pass


class PhoneSession:
    """One connected phone. Implements the receiver side of interface B."""

    def __init__(self, sock: socket.socket, log=print):
        self.sock = sock
        self.log = log
        self.buffer = b""
        self.armed_until = 0.0
        self.next_request_id = 1
        self.last_sent = time.monotonic()

    def send(self, message: dict) -> None:
        self.sock.sendall(encode_frame({**message, "v": PROTOCOL_VERSION}))
        self.last_sent = time.monotonic()

    def _read_exact(self, n: int, deadline: float) -> bytes:
        while len(self.buffer) < n:
            if time.monotonic() > deadline:
                raise TimeoutError
            if time.monotonic() - self.last_sent > 5:
                self.send({"type": "ping"})
            self.sock.settimeout(1.0)
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                continue
            if not chunk:
                raise ConnectionError("phone closed the connection")
            self.buffer += chunk
        data, self.buffer = self.buffer[:n], self.buffer[n:]
        return data

    def receive(self, timeout_s: float) -> dict:
        deadline = time.monotonic() + timeout_s
        (length,) = struct.unpack(">I", self._read_exact(4, deadline))
        if length > MAX_FRAME:
            raise ProtocolError("frame too large")
        message = json.loads(self._read_exact(length, deadline))
        if message.get("v") != PROTOCOL_VERSION:
            self.send({"type": "error", "code": "version", "message": "expected v=1"})
            raise ProtocolError(f"phone speaks v={message.get('v')}")
        return message

    def _handle_control(self, message: dict) -> bool:
        """Apply arm/disarm/ping. Returns True if the message was a control message."""
        kind = message.get("type")
        if kind == "ping":
            return True
        if kind == "arm":
            ttl_ms = int(message["ttl_ms"])
            if not 1000 <= ttl_ms <= 900_000:
                raise ProtocolError("ttl_ms out of range")
            self.armed_until = time.monotonic() + ttl_ms / 1000
            self.log(f"phone armed for {ttl_ms // 1000} s")
            self.send_state(None)
            return True
        if kind == "disarm":
            self.armed_until = 0
            self.log("phone disarmed")
            self.send_state(None)
            return True
        if kind == "error":
            raise ProtocolError(f"phone error {message.get('code')}: {message.get('message')}")
        return False

    def armed(self) -> bool:
        return time.monotonic() < self.armed_until

    def send_state(self, pending: int | None) -> None:
        remaining = max(0, int((self.armed_until - time.monotonic()) * 1000))
        self.send({"type": "state", "armed": remaining > 0, "expires_in_ms": remaining,
                   "pending_request_id": pending})

    def handshake(self, timeout_s: float = 30) -> None:
        hello = self.receive(timeout_s)
        if hello.get("type") != "hello" or hello.get("role") != "phone":
            raise ProtocolError("first message was not a phone hello")
        self.log(f"phone connected, app {hello.get('app_version')}")
        self.send({"type": "hello", "role": "receiver", "app_version": "bench-driver 0.1"})

    def wait_armed(self, timeout_s: float = 120) -> None:
        deadline = time.monotonic() + timeout_s
        while not self.armed():
            message = self.receive(max(0.1, deadline - time.monotonic()))
            if not self._handle_control(message):
                raise ProtocolError(f"unexpected {message.get('type')} before arming")

    def request(self, ctap_command: int, ctap_params: bytes, deadline_ms: int = 120_000) -> tuple[int, list[dict]]:
        if not self.armed():
            raise ProtocolError("not armed")
        request_id = self.next_request_id
        self.next_request_id += 1
        self.send({"type": "request", "request_id": request_id, "ctap_command": ctap_command,
                   "ctap_params": b64u(ctap_params), "deadline_ms": deadline_ms})
        deadline = time.monotonic() + deadline_ms / 1000
        while True:
            try:
                message = self.receive(max(0.1, deadline - time.monotonic()))
            except TimeoutError:
                self.send({"type": "cancel", "request_id": request_id})
                return 0x2F, []
            if self._handle_control(message):
                continue
            if message.get("type") != "response":
                raise ProtocolError(f"unexpected {message.get('type')} while pending")
            if message.get("request_id") != request_id:
                self.log(f"discarding response for stale request {message.get('request_id')}")
                continue
            status = int(message["status"])
            results = [cbor.decode(unb64u(r)) for r in message.get("results", [])]
            if (status == 0) != bool(results):
                raise ProtocolError("status and results disagree")
            self.send_state(None)
            return status, results


# Glue: one ceremony end to end


def http_json(url: str, body: dict) -> dict:
    req = urllib.request.Request(url, json.dumps(body).encode(), {"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as res:
        return json.loads(res.read())


def run_register(session: PhoneSession, rp_url: str, origin: str, user: str, uv: str) -> dict:
    options = http_json(f"{rp_url}/api/register/begin", {"username": user})
    cdj = client_data_json("webauthn.create", options["challenge"], origin)
    params = make_credential_params(options, hashlib.sha256(cdj).digest(), uv)
    status, results = session.request(CTAP_MAKE_CREDENTIAL, params)
    if status != 0:
        return {"ok": False, "ctap_status": f"0x{status:02X}"}
    return http_json(f"{rp_url}/api/register/finish", registration_payload(results[0], cdj))


def run_sign_in(session: PhoneSession, rp_url: str, origin: str, uv: str, probe: bool) -> dict:
    options = http_json(f"{rp_url}/api/login/begin", {})
    if probe:
        status, _ = session.request(
            CTAP_GET_ASSERTION, get_assertion_params(options, b"\0" * 32, uv="absent", up=False)
        )
        print(f"probe (up: false) answered with status 0x{status:02X}")
    cdj = client_data_json("webauthn.get", options["challenge"], origin)
    params = get_assertion_params(options, hashlib.sha256(cdj).digest(), uv)
    status, results = session.request(CTAP_GET_ASSERTION, params)
    if status != 0:
        return {"ok": False, "ctap_status": f"0x{status:02X}"}
    return http_json(f"{rp_url}/api/login/finish", assertion_payload(results[0], cdj))


def print_report(result: dict) -> None:
    if "checks" not in result:
        print(f"FAIL before reaching the RP: {result}")
        return
    print("PASS" if result["ok"] else "FAIL")
    for check in result["checks"]:
        print(f"  {'✓' if check['ok'] else '✗'} {check['name']:<16} {check['detail']}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("ceremony", choices=["register", "sign-in"])
    parser.add_argument("--user", default="test-user")
    parser.add_argument("--rp", default="http://localhost:8765", help="test RP base URL")
    parser.add_argument("--origin", default=None, help="origin to claim (default: the RP URL)")
    parser.add_argument("--listen", default="0.0.0.0:47100", help="address for the phone to connect to")
    parser.add_argument("--uv", choices=["true", "absent"], default="true",
                        help="whether the request carries options.uv like Chrome with UV required")
    parser.add_argument("--probe", action="store_true", help="send an up:false probe before signing in")
    args = parser.parse_args(argv)
    origin = args.origin or args.rp

    host, port = args.listen.rsplit(":", 1)
    with socket.create_server((host, int(port)), reuse_port=False) as server:
        print(f"waiting for the phone on {args.listen} …")
        conn, peer = server.accept()
        with conn:
            session = PhoneSession(conn)
            session.handshake()
            print("waiting for the phone to arm …")
            session.wait_armed()
            if args.ceremony == "register":
                result = run_register(session, args.rp, origin, args.user, args.uv)
            else:
                result = run_sign_in(session, args.rp, origin, args.uv, args.probe)
            print_report(result)
            return 0 if result.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
