"""Bench host: plays the computer's browser on the USB side of the real receiver.

It uses python-fido2's own client (Fido2Client), an implementation independent of
KeyRelay, over the receiver's bench HID mode (raw 64-byte reports over TCP). It
fetches options from the test RP, lets the client talk CTAPHID/CTAP2 to the
receiver exactly as it would to a USB key, and submits the result to the RP.

    uv run --project bench bench/host.py register [--user test-user]
    uv run --project bench bench/host.py sign-in

This exercises the real receiver end to end without the Pi. It does not show how
Chrome behaves; that needs the Pi on real USB (contract assumptions A1–A3).
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import threading

from fido2.client import DefaultClientDataCollector, Fido2Client, UserInteraction
from fido2.ctap2 import Ctap2
from fido2.hid import CtapHidDevice
from fido2.hid.base import CtapHidConnection, HidDescriptor
from fido2.webauthn import PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions

from driver import b64u, http_json, print_report

REPORT = 64


class TcpHidConnection(CtapHidConnection):
    def __init__(self, address: str):
        host, port = address.rsplit(":", 1)
        self.sock = socket.create_connection((host, int(port)))
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def read_packet(self) -> bytes:
        data = b""
        while len(data) < REPORT:
            chunk = self.sock.recv(REPORT - len(data))
            if not chunk:
                raise OSError("receiver closed the bench HID connection")
            data += chunk
        return data

    def write_packet(self, data: bytes) -> None:
        self.sock.sendall(data.ljust(REPORT, b"\0")[:REPORT])

    def close(self) -> None:
        self.sock.close()


class Interaction(UserInteraction):
    def prompt_up(self) -> None:
        print("receiver asks for user presence: approve on the phone and hold the key", flush=True)


def open_device(address: str) -> CtapHidDevice:
    descriptor = HidDescriptor(f"tcp:{address}", 0x1209, 0x0001, REPORT, REPORT, "KeyRelay bench", None)
    return CtapHidDevice(descriptor, TcpHidConnection(address))


def describe(device: CtapHidDevice) -> None:
    info = Ctap2(device).info
    options = {k: v for k, v in info.options.items()}
    print(f"receiver getInfo: versions={info.versions} options={options} aaguid={info.aaguid}")
    print(f"  maxMsgSize={info.max_msg_size} maxCredsInList={info.max_creds_in_list} "
          f"maxCredIdLength={info.max_cred_id_length} transports={info.transports}")


def register(client: Fido2Client, rp: str, user: str, event: threading.Event | None = None) -> dict:
    options = http_json(f"{rp}/api/register/begin", {"username": user})
    result = client.make_credential(PublicKeyCredentialCreationOptions.from_dict(options), event=event)
    return http_json(f"{rp}/api/register/finish", {
        "id": b64u(result.raw_id), "rawId": b64u(result.raw_id), "type": "public-key",
        "response": {"clientDataJSON": b64u(bytes(result.response.client_data)),
                     "attestationObject": b64u(bytes(result.response.attestation_object))},
    })


def sign_in(client: Fido2Client, rp: str, event: threading.Event | None = None) -> dict:
    options = http_json(f"{rp}/api/login/begin", {})
    result = client.get_assertion(PublicKeyCredentialRequestOptions.from_dict(options), event=event).get_response(0)
    return http_json(f"{rp}/api/login/finish", {
        "id": b64u(result.raw_id), "rawId": b64u(result.raw_id), "type": "public-key",
        "response": {"clientDataJSON": b64u(bytes(result.response.client_data)),
                     "authenticatorData": b64u(bytes(result.response.authenticator_data)),
                     "signature": b64u(result.response.signature)},
    })


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("ceremony", choices=["register", "sign-in", "info"])
    parser.add_argument("--user", default="test-user")
    parser.add_argument("--rp", default="http://localhost:8765")
    parser.add_argument("--origin", default=None, help="origin the client claims (default: the RP URL)")
    parser.add_argument("--hid", default="127.0.0.1:47101", help="receiver's bench HID address")
    parser.add_argument("--cancel-after", type=float, default=None,
                        help="cancel from the browser side after this many seconds (sends CTAPHID_CANCEL)")
    args = parser.parse_args(argv)

    device = open_device(args.hid)
    describe(device)
    if args.ceremony == "info":
        return 0
    client = Fido2Client(device, DefaultClientDataCollector(args.origin or args.rp),
                         user_interaction=Interaction(), extensions=[])
    event = threading.Event()
    if args.cancel_after is not None:
        threading.Timer(args.cancel_after, event.set).start()
    try:
        result = (register(client, args.rp, args.user, event) if args.ceremony == "register"
                  else sign_in(client, args.rp, event))
    except Exception as exc:  # report client-side failures plainly
        print(f"FAIL in the client: {type(exc).__name__}: {exc}")
        return 1
    print_report(result)
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
