"""A fake phone with a software key: speaks the phone side of interface B and signs
like a YubiKey after a PIN. Used by tests, and runnable for bench dry runs:

    uv run --project bench bench/fake_phone.py 127.0.0.1:47100
"""

import hashlib
import json
import os
import socket
import struct
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2 import cbor
from fido2.cose import ES256
from fido2.webauthn import AttestedCredentialData, AuthenticatorData

from driver import b64u, unb64u


class FakePhone:
    """Speaks the phone side of interface B and signs like a YubiKey after a PIN."""

    def __init__(self, sock, *, version=1, stale_first=False, silent=False):
        self.sock = sock
        self.version = version
        self.stale_first = stale_first
        self.silent = silent
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = os.urandom(32)
        self.counter = 0
        self.requests = []  # decoded CTAP params, for assertions
        self.cancels = []

    def send(self, message):
        body = json.dumps({**message, "v": self.version}).encode()
        self.sock.sendall(struct.pack(">I", len(body)) + body)

    def recv(self):
        header = self._exact(4)
        if header is None:
            return None
        return json.loads(self._exact(struct.unpack(">I", header)[0]))

    def _exact(self, n):
        data = b""
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    def _sign(self, rp_id, cdh, flags, credential_data=b""):
        self.counter += 1
        auth_data = AuthenticatorData.create(
            hashlib.sha256(rp_id.encode()).digest(), flags, self.counter, credential_data
        )
        sig = self.key.sign(bytes(auth_data) + cdh, ec.ECDSA(hashes.SHA256()))
        return auth_data, sig

    def answer(self, command, params):
        flags = AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.UV  # the phone always verifies the PIN
        if command == 1:
            cred = AttestedCredentialData.create(
                b"\0" * 16, self.credential_id, ES256.from_cryptography_key(self.key.public_key())
            )
            auth_data, sig = self._sign(params[2]["id"], params[1], flags | AuthenticatorData.FLAG.AT, cred)
            return {1: "packed", 2: bytes(auth_data), 3: {"alg": -7, "sig": sig}}
        if params.get(5, {}).get("up") is False:
            flags = AuthenticatorData.FLAG(0)
        auth_data, sig = self._sign(params[1], params[2], flags)
        return {1: {"id": self.credential_id, "type": "public-key"}, 2: bytes(auth_data), 3: sig}

    def run(self):
        try:
            self._run()
        except (OSError, AssertionError, TypeError):
            pass  # the receiver closed or rejected us; the test asserts on its side

    def _run(self):
        self.send({"type": "hello", "role": "phone", "app_version": "fake 0"})
        assert self.recv()["type"] == "hello"
        self.send({"type": "arm", "ttl_ms": 60_000})
        while (message := self.recv()) is not None:
            if message["type"] == "request":
                params = cbor.decode(unb64u(message["ctap_params"]))
                self.requests.append(params)
                if self.silent:
                    continue
                if self.stale_first:
                    self.stale_first = False
                    self.send({"type": "response", "request_id": 999, "status": 0x27, "results": []})
                result = self.answer(message["ctap_command"], params)
                self.send({"type": "response", "request_id": message["request_id"], "status": 0,
                           "results": [b64u(cbor.encode(result))]})
            elif message["type"] == "cancel":
                self.cancels.append(message["request_id"])


if __name__ == "__main__":
    host, port = sys.argv[1].rsplit(":", 1)
    sock = socket.create_connection((host, int(port)))
    print(f"fake phone connected to {sys.argv[1]}", flush=True)
    FakePhone(sock).run()
