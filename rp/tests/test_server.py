"""HTTP round trip: the browser-shaped JSON the page sends is decoded and verified."""

import json
import os
import sys
import threading
import urllib.error
import urllib.request

import pytest

from verifier import b64url_encode

from test_verifier import ORIGIN, SoftAuthenticator


@pytest.fixture
def base_url(tmp_path, monkeypatch):
    monkeypatch.setenv("KEYRELAY_RP_ORIGIN", ORIGIN)
    monkeypatch.setenv("KEYRELAY_RP_ID", "localhost")
    monkeypatch.setenv("KEYRELAY_RP_DATA", str(tmp_path / "credentials.json"))
    sys.modules.pop("server", None)
    import server

    httpd = server.ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}", tmp_path / "credentials.json"
    httpd.shutdown()
    sys.modules.pop("server", None)


def post(url, body):
    req = urllib.request.Request(url, json.dumps(body).encode(), {"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as res:
            return res.status, json.loads(res.read())
    except urllib.error.HTTPError as err:
        return err.code, json.loads(err.read())


def test_register_sign_in_and_replay_over_http(base_url):
    url, data_file = base_url
    key = SoftAuthenticator()

    _, options = post(f"{url}/api/register/begin", {"username": "test-user"})
    reg = key.register(options)
    status, result = post(f"{url}/api/register/finish", {
        "id": b64url_encode(key.credential_id), "rawId": b64url_encode(key.credential_id),
        "type": "public-key",
        "response": {"clientDataJSON": b64url_encode(reg["client_data_json"]),
                     "attestationObject": b64url_encode(reg["attestation_object"])},
    })
    assert status == 200 and result["ok"], result
    assert data_file.exists()

    _, options = post(f"{url}/api/login/begin", {})
    sig = key.sign_in(options)
    body = {
        "id": b64url_encode(key.credential_id), "rawId": b64url_encode(key.credential_id),
        "type": "public-key",
        "response": {"clientDataJSON": b64url_encode(sig["client_data_json"]),
                     "authenticatorData": b64url_encode(sig["authenticator_data"]),
                     "signature": b64url_encode(sig["signature"])},
    }
    status, result = post(f"{url}/api/login/finish", body)
    assert status == 200 and result["ok"], result

    status, replay = post(f"{url}/api/login/replay", {})
    assert status == 200 and not replay["ok"]
    # A replay reuses both the challenge and the signature counter, so both checks fail.
    assert {c["name"] for c in replay["checks"] if not c["ok"]} == {"challenge", "counter"}


def test_malformed_requests_get_400(base_url):
    url, _ = base_url
    assert post(f"{url}/api/register/begin", {})[0] == 400
    assert post(f"{url}/api/login/finish", {"response": {}})[0] == 400
    assert post(f"{url}/api/login/replay", {})[0] == 400
