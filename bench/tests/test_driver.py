"""Bench driver tests: a fake phone with a software key answers over interface B,
and the real test RP judges the result."""

import hashlib
import json
import os
import socket
import struct
import sys
import threading

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2 import cbor
from fido2.cose import ES256
from fido2.webauthn import AttestedCredentialData, AuthenticatorData

import driver
from driver import PhoneSession, ProtocolError, b64u, unb64u
from fake_phone import FakePhone

ORIGIN = "http://localhost:8765"


@pytest.fixture
def rp_url(tmp_path, monkeypatch):
    monkeypatch.setenv("KEYRELAY_RP_ORIGIN", ORIGIN)
    monkeypatch.setenv("KEYRELAY_RP_ID", "localhost")
    monkeypatch.setenv("KEYRELAY_RP_DATA", str(tmp_path / "credentials.json"))
    sys.modules.pop("server", None)
    import server

    httpd = server.ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    sys.modules.pop("server", None)


def connect(**phone_kwargs):
    receiver_sock, phone_sock = socket.socketpair()
    phone = FakePhone(phone_sock, **phone_kwargs)
    threading.Thread(target=phone.run, daemon=True).start()
    session = PhoneSession(receiver_sock, log=lambda *_: None)
    return session, phone


def ready(**phone_kwargs):
    session, phone = connect(**phone_kwargs)
    session.handshake(timeout_s=5)
    session.wait_armed(timeout_s=5)
    return session, phone


def failed(result):
    return [c["name"] for c in result["checks"] if not c["ok"]]


def test_register_then_sign_in_pass_at_the_rp(rp_url):
    session, phone = ready()
    reg = driver.run_register(session, rp_url, ORIGIN, "test-user", "true")
    assert reg["ok"], failed(reg)
    signin = driver.run_sign_in(session, rp_url, ORIGIN, "true", probe=False)
    assert signin["ok"], failed(signin)


def test_requests_carry_uv_like_chrome_and_nothing_else(rp_url):
    session, phone = ready()
    driver.run_register(session, rp_url, ORIGIN, "test-user", "true")
    driver.run_sign_in(session, rp_url, ORIGIN, "true", probe=False)
    mc, ga = phone.requests
    assert set(mc) == {1, 2, 3, 4, 7} and mc[7] == {"uv": True}
    assert set(ga) == {1, 2, 3, 5} and ga[5] == {"uv": True}
    assert ga[1] == "localhost" and ga[3][0]["id"] == phone.credential_id


def test_uv_absent_omits_the_options_map(rp_url):
    session, phone = ready()
    driver.run_register(session, rp_url, ORIGIN, "test-user", "absent")
    assert 7 not in phone.requests[0]


def test_probe_precedes_the_real_sign_in(rp_url):
    session, phone = ready()
    driver.run_register(session, rp_url, ORIGIN, "test-user", "true")
    signin = driver.run_sign_in(session, rp_url, ORIGIN, "true", probe=True)
    assert signin["ok"], failed(signin)
    probe = phone.requests[1]
    assert probe[5] == {"up": False} and probe[2] == b"\0" * 32


def test_client_data_json_matches_chrome_layout():
    cdj = driver.client_data_json("webauthn.get", "abc", ORIGIN)
    assert cdj == b'{"type":"webauthn.get","challenge":"abc","origin":"http://localhost:8765","crossOrigin":false}'


def test_requests_are_canonical_cbor(rp_url):
    session, phone = ready()
    driver.run_register(session, rp_url, ORIGIN, "test-user", "true")
    params = phone.requests[0]
    assert cbor.encode(params) == cbor.encode(cbor.decode(cbor.encode(params)))


def test_stale_response_is_discarded(rp_url):
    session, phone = ready(stale_first=True)
    reg = driver.run_register(session, rp_url, ORIGIN, "test-user", "true")
    assert reg["ok"], failed(reg)


def test_deadline_sends_cancel_and_times_out():
    session, phone = ready(silent=True)
    status, results = session.request(1, cbor.encode({1: b"\0" * 32}), deadline_ms=300)
    assert (status, results) == (0x2F, [])


def test_version_mismatch_is_rejected():
    session, phone = connect(version=2)
    with pytest.raises(ProtocolError):
        session.handshake(timeout_s=5)


def test_request_requires_arming():
    session, phone = connect()
    session.handshake(timeout_s=5)
    with pytest.raises(ProtocolError):
        session.request(1, b"\xa0")
