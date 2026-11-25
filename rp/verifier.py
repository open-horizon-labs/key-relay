"""WebAuthn verification for the KeyRelay test relying party.

Every check the README requires is made explicitly and reported by name, so a test
run shows which property held and which failed. Cryptography comes from python-fido2.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import time
from dataclasses import dataclass, field
from typing import Callable

from fido2 import cbor
from fido2.attestation import Attestation
from fido2.cose import CoseKey
from fido2.webauthn import AttestationObject, AuthenticatorData, CollectedClientData


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


@dataclass
class Check:
    name: str
    ok: bool
    detail: str


@dataclass
class Result:
    checks: list[Check] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return bool(self.checks) and all(c.ok for c in self.checks)

    def add(self, name: str, ok: bool, detail: str) -> bool:
        self.checks.append(Check(name, ok, detail))
        return ok


@dataclass
class StoredCredential:
    credential_id: bytes
    public_key: bytes  # CBOR-encoded COSE key
    username: str
    user_handle: bytes
    counter: int
    aaguid: str
    attestation_format: str


PURPOSE_CREATE = "webauthn.create"
PURPOSE_GET = "webauthn.get"


class RelyingParty:
    def __init__(self, rp_id: str, origin: str, challenge_ttl_s: float = 120,
                 clock: Callable[[], float] = time.monotonic):
        self.rp_id = rp_id
        self.origin = origin
        self.rp_id_hash = hashlib.sha256(rp_id.encode()).digest()
        self.challenge_ttl_s = challenge_ttl_s
        self.clock = clock
        self.credentials: dict[bytes, StoredCredential] = {}
        self.users: dict[str, bytes] = {}
        self._challenges: dict[bytes, tuple[str, float, str | None]] = {}

    # Challenges

    def _issue_challenge(self, purpose: str, username: str | None = None) -> bytes:
        challenge = os.urandom(32)
        self._challenges[challenge] = (purpose, self.clock(), username)
        return challenge

    def _consume_challenge(self, result: Result, challenge: bytes, purpose: str) -> str | None:
        """Single use: the challenge is removed whether or not verification succeeds."""
        entry = self._challenges.pop(challenge, None)
        if entry is None:
            result.add("challenge", False, "not issued by this RP, or already used")
            return None
        issued_for, issued_at, username = entry
        if issued_for != purpose:
            result.add("challenge", False, f"issued for {issued_for}, presented for {purpose}")
            return None
        age = self.clock() - issued_at
        if age > self.challenge_ttl_s:
            result.add("challenge", False, f"expired ({age:.0f} s old, limit {self.challenge_ttl_s:.0f} s)")
            return None
        result.add("challenge", True, f"issued by this RP {age:.1f} s ago, now consumed")
        return username or ""

    # Shared checks

    def _check_client_data(self, result: Result, client_data_json: bytes, purpose: str):
        try:
            client_data = CollectedClientData(client_data_json)
        except Exception as exc:  # malformed input from the browser
            result.add("client_data", False, f"unparseable: {exc}")
            return None, None
        result.add("type", client_data.type == purpose, f"{client_data.type!r}, expected {purpose!r}")
        username = self._consume_challenge(result, client_data.challenge, purpose)
        result.add("origin", client_data.origin == self.origin,
                   f"{client_data.origin!r}, expected {self.origin!r}")
        result.add("cross_origin", not client_data.cross_origin,
                   "cross-origin request" if client_data.cross_origin else "same origin")
        return client_data, username

    def _check_auth_data(self, result: Result, auth_data: AuthenticatorData) -> None:
        result.add("rp_id_hash", hmac.compare_digest(auth_data.rp_id_hash, self.rp_id_hash),
                   f"matches SHA-256({self.rp_id!r})" if auth_data.rp_id_hash == self.rp_id_hash
                   else f"does not match SHA-256({self.rp_id!r})")
        result.add("user_present", auth_data.is_user_present(), "UP flag set"
                   if auth_data.is_user_present() else "UP flag not set")
        result.add("user_verified", auth_data.is_user_verified(), "UV flag set"
                   if auth_data.is_user_verified() else "UV flag not set")

    # Registration

    def registration_options(self, username: str) -> dict:
        user_handle = self.users.setdefault(username, os.urandom(16))
        challenge = self._issue_challenge(PURPOSE_CREATE, username)
        existing = [c for c in self.credentials.values() if c.user_handle == user_handle]
        return {
            "rp": {"id": self.rp_id, "name": "KeyRelay test RP"},
            "user": {"id": b64url_encode(user_handle), "name": username, "displayName": username},
            "challenge": b64url_encode(challenge),
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}, {"type": "public-key", "alg": -8}],
            "timeout": int(self.challenge_ttl_s * 1000),
            "excludeCredentials": [{"type": "public-key", "id": b64url_encode(c.credential_id)}
                                   for c in existing],
            "authenticatorSelection": {"residentKey": "discouraged", "userVerification": "required"},
            "attestation": "direct",
        }

    def finish_registration(self, client_data_json: bytes, attestation_object: bytes) -> Result:
        result = Result()
        client_data, username = self._check_client_data(result, client_data_json, PURPOSE_CREATE)
        if client_data is None:
            return result
        try:
            att_obj = AttestationObject(attestation_object)
        except Exception as exc:
            result.add("attestation_object", False, f"unparseable: {exc}")
            return result

        auth_data = att_obj.auth_data
        self._check_auth_data(result, auth_data)
        cred_data = auth_data.credential_data
        if not result.add("credential_data", cred_data is not None,
                          "attested credential data present" if cred_data else "missing"):
            return result
        result.add("credential_new", cred_data.credential_id not in self.credentials,
                   "credential ID not seen before" if cred_data.credential_id not in self.credentials
                   else "credential ID already registered")

        try:
            Attestation.for_type(att_obj.fmt)().verify(att_obj.att_stmt, auth_data, client_data.hash)
            result.add("attestation", True,
                       f"{att_obj.fmt!r} statement signature valid (trust chain not checked)")
        except Exception as exc:
            result.add("attestation", False, f"{att_obj.fmt!r} statement rejected: {type(exc).__name__}")

        if result.ok and username is not None:
            self.credentials[cred_data.credential_id] = StoredCredential(
                credential_id=cred_data.credential_id,
                public_key=cbor.encode(dict(cred_data.public_key)),
                username=username,
                user_handle=self.users[username],
                counter=auth_data.counter,
                aaguid=str(cred_data.aaguid),
                attestation_format=att_obj.fmt,
            )
        return result

    # Authentication

    def authentication_options(self) -> dict:
        challenge = self._issue_challenge(PURPOSE_GET)
        return {
            "challenge": b64url_encode(challenge),
            "rpId": self.rp_id,
            "timeout": int(self.challenge_ttl_s * 1000),
            "allowCredentials": [{"type": "public-key", "id": b64url_encode(c.credential_id)}
                                 for c in self.credentials.values()],
            "userVerification": "required",
        }

    def finish_authentication(self, credential_id: bytes, client_data_json: bytes,
                              authenticator_data: bytes, signature: bytes) -> Result:
        result = Result()
        client_data, _ = self._check_client_data(result, client_data_json, PURPOSE_GET)
        if client_data is None:
            return result

        stored = self.credentials.get(credential_id)
        if not result.add("credential_known", stored is not None,
                          f"registered to {stored.username!r}" if stored else "not registered here"):
            return result
        try:
            auth_data = AuthenticatorData(authenticator_data)
        except Exception as exc:
            result.add("authenticator_data", False, f"unparseable: {exc}")
            return result
        self._check_auth_data(result, auth_data)

        try:
            CoseKey.parse(cbor.decode(stored.public_key)).verify(
                authenticator_data + client_data.hash, signature
            )
            result.add("signature", True, "valid over authenticatorData ‖ SHA-256(clientDataJSON)")
        except Exception as exc:
            result.add("signature", False, f"invalid: {type(exc).__name__}")

        if stored.counter == 0 and auth_data.counter == 0:
            result.add("counter", True, "authenticator does not use a counter")
        else:
            result.add("counter", auth_data.counter > stored.counter,
                       f"{auth_data.counter}, previously {stored.counter}")

        if result.ok:
            stored.counter = auth_data.counter
        return result

    # Persistence (public keys and counters only; nothing secret is stored)

    def dump_credentials(self) -> dict:
        return {
            "users": {name: b64url_encode(handle) for name, handle in self.users.items()},
            "credentials": [
                {
                    "credential_id": b64url_encode(c.credential_id),
                    "public_key": b64url_encode(c.public_key),
                    "username": c.username,
                    "user_handle": b64url_encode(c.user_handle),
                    "counter": c.counter,
                    "aaguid": c.aaguid,
                    "attestation_format": c.attestation_format,
                }
                for c in self.credentials.values()
            ],
        }

    def load_credentials(self, data: dict) -> None:
        self.users = {name: b64url_decode(h) for name, h in data.get("users", {}).items()}
        self.credentials = {}
        for c in data.get("credentials", []):
            cred = StoredCredential(
                credential_id=b64url_decode(c["credential_id"]),
                public_key=b64url_decode(c["public_key"]),
                username=c["username"],
                user_handle=b64url_decode(c["user_handle"]),
                counter=c["counter"],
                aaguid=c["aaguid"],
                attestation_format=c["attestation_format"],
            )
            self.credentials[cred.credential_id] = cred
