"""Verifier tests driven by a software authenticator.

The software authenticator builds the same structures a YubiKey returns, so every
check the relying party makes can be exercised in both its passing and failing form.
"""

import hashlib
import os

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2 import cbor
from fido2.cose import ES256
from fido2.webauthn import (
    AttestationObject,
    AttestedCredentialData,
    AuthenticatorData,
    CollectedClientData,
)

from verifier import RelyingParty, b64url_decode

RP_ID = "localhost"
ORIGIN = "http://localhost:8765"
FLAGS_UP_UV = AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.UV


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class SoftAuthenticator:
    """One credential, signing like a security key with packed self-attestation."""

    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = os.urandom(32)
        self.counter = 0

    def _sign(self, message: bytes) -> bytes:
        return self.key.sign(message, ec.ECDSA(hashes.SHA256()))

    def register(self, options, *, origin=ORIGIN, rp_id=RP_ID, flags=FLAGS_UP_UV,
                 type_="webauthn.create", challenge=None):
        challenge = challenge if challenge is not None else b64url_decode(options["challenge"])
        client_data = CollectedClientData.create(type=type_, challenge=challenge, origin=origin)
        self.counter += 1
        credential_data = AttestedCredentialData.create(
            b"\0" * 16, self.credential_id, ES256.from_cryptography_key(self.key.public_key())
        )
        auth_data = AuthenticatorData.create(
            hashlib.sha256(rp_id.encode()).digest(),
            flags | AuthenticatorData.FLAG.AT,
            self.counter,
            credential_data,
        )
        signature = self._sign(bytes(auth_data) + client_data.hash)
        att_obj = AttestationObject.create("packed", auth_data, {"alg": -7, "sig": signature})
        return {"client_data_json": bytes(client_data), "attestation_object": bytes(att_obj)}

    def sign_in(self, options, *, origin=ORIGIN, rp_id=RP_ID, flags=FLAGS_UP_UV,
                type_="webauthn.get", challenge=None, counter=None, corrupt_signature=False,
                credential_id=None):
        challenge = challenge if challenge is not None else b64url_decode(options["challenge"])
        client_data = CollectedClientData.create(type=type_, challenge=challenge, origin=origin)
        self.counter = counter if counter is not None else self.counter + 1
        auth_data = AuthenticatorData.create(
            hashlib.sha256(rp_id.encode()).digest(), flags, self.counter
        )
        signature = self._sign(bytes(auth_data) + client_data.hash)
        if corrupt_signature:
            signature = signature[:-1] + bytes([signature[-1] ^ 0x01])
        return {
            "credential_id": credential_id or self.credential_id,
            "client_data_json": bytes(client_data),
            "authenticator_data": bytes(auth_data),
            "signature": signature,
        }


def failed(result):
    return {c.name for c in result.checks if not c.ok}


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def rp(clock):
    return RelyingParty(RP_ID, ORIGIN, challenge_ttl_s=120, clock=clock)


@pytest.fixture
def key():
    return SoftAuthenticator()


@pytest.fixture
def registered(rp, key):
    result = rp.finish_registration(**key.register(rp.registration_options("alice")))
    assert result.ok, failed(result)
    return key


# Registration


def test_registration_passes_every_check(rp, key):
    result = rp.finish_registration(**key.register(rp.registration_options("alice")))
    assert result.ok
    assert failed(result) == set()
    assert key.credential_id in rp.credentials


def test_registration_options_require_user_verification(rp):
    options = rp.registration_options("alice")
    assert options["authenticatorSelection"]["userVerification"] == "required"
    assert options["rp"]["id"] == RP_ID


def test_registration_replay_is_rejected(rp, key):
    response = key.register(rp.registration_options("alice"))
    assert rp.finish_registration(**response).ok
    replay = rp.finish_registration(**response)
    assert not replay.ok
    assert "challenge" in failed(replay)


def test_registration_unknown_challenge_is_rejected(rp, key):
    rp.registration_options("alice")
    result = rp.finish_registration(**key.register({}, challenge=os.urandom(32)))
    assert "challenge" in failed(result)


def test_registration_wrong_origin_is_rejected(rp, key):
    result = rp.finish_registration(
        **key.register(rp.registration_options("alice"), origin="https://evil.example")
    )
    assert "origin" in failed(result)


def test_registration_wrong_rp_id_is_rejected(rp, key):
    result = rp.finish_registration(
        **key.register(rp.registration_options("alice"), rp_id="evil.example")
    )
    assert "rp_id_hash" in failed(result)


def test_registration_without_user_verification_is_rejected(rp, key):
    result = rp.finish_registration(
        **key.register(rp.registration_options("alice"), flags=AuthenticatorData.FLAG.UP)
    )
    assert failed(result) == {"user_verified"}


def test_registration_without_user_presence_is_rejected(rp, key):
    result = rp.finish_registration(
        **key.register(rp.registration_options("alice"), flags=AuthenticatorData.FLAG.UV)
    )
    assert "user_present" in failed(result)


def test_registration_with_get_type_is_rejected(rp, key):
    result = rp.finish_registration(
        **key.register(rp.registration_options("alice"), type_="webauthn.get")
    )
    assert "type" in failed(result)


def test_registration_with_bad_attestation_signature_is_rejected(rp, key):
    response = key.register(rp.registration_options("alice"))
    att = cbor.decode(response["attestation_object"])
    att["attStmt"]["sig"] = att["attStmt"]["sig"][:-1] + b"\x00"
    response["attestation_object"] = cbor.encode(att)
    result = rp.finish_registration(**response)
    assert "attestation" in failed(result)


def test_registration_of_existing_credential_is_rejected(rp, registered):
    result = rp.finish_registration(**registered.register(rp.registration_options("alice")))
    assert "credential_new" in failed(result)


def test_registration_garbage_input_fails_cleanly(rp):
    rp.registration_options("alice")
    result = rp.finish_registration(client_data_json=b"not json", attestation_object=b"\x00")
    assert not result.ok


# Authentication


def test_sign_in_passes_every_check(rp, registered):
    result = rp.finish_authentication(**registered.sign_in(rp.authentication_options()))
    assert result.ok, failed(result)
    assert rp.credentials[registered.credential_id].counter == registered.counter


def test_sign_in_options_list_registered_credentials(rp, registered):
    options = rp.authentication_options()
    ids = [b64url_decode(c["id"]) for c in options["allowCredentials"]]
    assert ids == [registered.credential_id]
    assert options["userVerification"] == "required"


def test_sign_in_replay_is_rejected(rp, registered):
    response = registered.sign_in(rp.authentication_options())
    assert rp.finish_authentication(**response).ok
    replay = rp.finish_authentication(**response)
    assert not replay.ok
    assert "challenge" in failed(replay)


def test_sign_in_with_registration_challenge_is_rejected(rp, registered):
    options = rp.registration_options("bob")
    result = rp.finish_authentication(**registered.sign_in(options))
    assert "challenge" in failed(result)


def test_sign_in_with_expired_challenge_is_rejected(rp, registered, clock):
    options = rp.authentication_options()
    clock.now += 121
    result = rp.finish_authentication(**registered.sign_in(options))
    assert "challenge" in failed(result)


def test_sign_in_wrong_origin_is_rejected(rp, registered):
    result = rp.finish_authentication(
        **registered.sign_in(rp.authentication_options(), origin="https://evil.example")
    )
    assert "origin" in failed(result)


def test_sign_in_wrong_rp_id_is_rejected(rp, registered):
    result = rp.finish_authentication(
        **registered.sign_in(rp.authentication_options(), rp_id="evil.example")
    )
    assert "rp_id_hash" in failed(result)


def test_sign_in_without_user_verification_is_rejected(rp, registered):
    result = rp.finish_authentication(
        **registered.sign_in(rp.authentication_options(), flags=AuthenticatorData.FLAG.UP)
    )
    assert failed(result) == {"user_verified"}


def test_sign_in_without_user_presence_is_rejected(rp, registered):
    result = rp.finish_authentication(
        **registered.sign_in(rp.authentication_options(), flags=AuthenticatorData.FLAG.UV)
    )
    assert "user_present" in failed(result)


def test_sign_in_bad_signature_is_rejected(rp, registered):
    result = rp.finish_authentication(
        **registered.sign_in(rp.authentication_options(), corrupt_signature=True)
    )
    assert failed(result) == {"signature"}


def test_sign_in_unknown_credential_is_rejected(rp, registered):
    result = rp.finish_authentication(
        **registered.sign_in(rp.authentication_options(), credential_id=os.urandom(32))
    )
    assert "credential_known" in failed(result)


def test_sign_in_counter_must_increase(rp, registered):
    assert rp.finish_authentication(**registered.sign_in(rp.authentication_options(), counter=5)).ok
    result = rp.finish_authentication(**registered.sign_in(rp.authentication_options(), counter=5))
    assert failed(result) == {"counter"}


def test_sign_in_with_create_type_is_rejected(rp, registered):
    result = rp.finish_authentication(
        **registered.sign_in(rp.authentication_options(), type_="webauthn.create")
    )
    assert "type" in failed(result)


def test_failed_sign_in_does_not_update_counter(rp, registered):
    before = rp.credentials[registered.credential_id].counter
    rp.finish_authentication(
        **registered.sign_in(rp.authentication_options(), corrupt_signature=True)
    )
    assert rp.credentials[registered.credential_id].counter == before


# Persistence


def test_credentials_round_trip_through_json(rp, registered, clock):
    restored = RelyingParty(RP_ID, ORIGIN, clock=clock)
    restored.load_credentials(rp.dump_credentials())
    result = restored.finish_authentication(**registered.sign_in(restored.authentication_options()))
    assert result.ok, failed(result)
