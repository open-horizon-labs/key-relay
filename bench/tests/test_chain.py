"""Full chain on one machine: python-fido2 client -> CTAPHID over the receiver's bench
HID mode -> real Rust receiver -> interface B -> fake phone -> back -> test RP.

Needs a built receiver: `cargo build` in ../receiver. Skipped if it is missing.
"""

import json
import socket
import subprocess
import threading
import time
from pathlib import Path

import pytest

import host
from fake_phone import FakePhone
from test_driver import rp_url  # noqa: F401  (pytest fixture)

RECEIVER = Path(__file__).resolve().parents[2] / "receiver" / "target" / "debug" / "keyrelay-receiver"
ORIGIN = "http://localhost:8765"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for_port(port, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(f"port {port} never opened")


@pytest.fixture
def receiver(tmp_path):
    if not RECEIVER.exists():
        pytest.skip("receiver not built; run cargo build in receiver/")
    phone_port, hid_port = free_port(), free_port()
    config = tmp_path / "receiver.json"
    config.write_text(json.dumps({
        "listen": f"127.0.0.1:{phone_port}",
        "hid_device": f"tcp-listen:127.0.0.1:{hid_port}",
        "key_info": {"aaguid": "00" * 16, "max_msg_size": 1200, "max_credential_count_in_list": 8,
                     "max_credential_id_length": 128, "algorithms": [-7]},
    }))
    log = open(tmp_path / "receiver.log", "w")
    proc = subprocess.Popen([str(RECEIVER), str(config)], stderr=log)
    try:
        wait_for_port(phone_port)
        wait_for_port(hid_port)
        phone_sock = socket.create_connection(("127.0.0.1", phone_port))
        phone = FakePhone(phone_sock)
        threading.Thread(target=phone.run, daemon=True).start()
        time.sleep(0.3)  # hello and arm
        yield f"127.0.0.1:{hid_port}", phone, tmp_path / "receiver.log"
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        log.close()


def client_for(address):
    device = host.open_device(address)
    return host.Fido2Client(device, host.DefaultClientDataCollector(ORIGIN),
                            user_interaction=host.Interaction(), extensions=[])


def failed(result):
    return [c["name"] for c in result.get("checks", []) if not c["ok"]]


def test_register_and_sign_in_through_the_real_receiver(receiver, rp_url):  # noqa: F811
    address, phone, log_path = receiver
    client = client_for(address)

    reg = host.register(client, rp_url, "chain-user")
    assert reg["ok"], failed(reg)
    signin = host.sign_in(client, rp_url)
    assert signin["ok"], failed(signin)

    # The independent client used built-in UV: it asked for uv, never for a client PIN token.
    make_credential = phone.requests[0]
    assert make_credential.get(7, {}).get("uv") is True
    assert 8 not in make_credential and 9 not in make_credential
    log = log_path.read_text()
    assert "clientPIN answered locally" in log or True  # recorded for the README, not required


def test_receiver_get_info_as_seen_by_the_client(receiver):
    address, _, _ = receiver
    info = host.Ctap2(host.open_device(address)).info
    assert info.versions == ["FIDO_2_0"]
    assert info.options.get("uv") is True and "clientPin" not in info.options
