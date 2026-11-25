# KeyRelay

Sign in on one computer with a FIDO2 security key you hold to your iPhone.

A small USB device plugged into the computer presents itself to the browser as a security key. Each sign-in request is relayed to an iPhone app; you enter the key's PIN on the phone and hold the key to it over NFC. The site verifies the key's own signature, as for any security key.

**Status: experimental.** The phone app and receiver work end to end on a bench setup (details below). A browser on real USB hardware has not been tested yet. Do not rely on it for accounts that matter.

## How it works

```
Browser ──CTAPHID over USB──▶ Receiver (Raspberry Pi) ──framed JSON over TCP──▶ iPhone app ──NFC──▶ YubiKey
```

- The receiver tells the browser it is a key with **built-in user verification**, so the browser never asks for a PIN.
- The phone shows the site asking, takes the PIN, gets a PIN token from the key and sends the browser's request to the key with that token.
- **One hold per sign-in.** Browsers often send a silent "is this credential here?" check before signing in. The phone answers it and the real sign-in in the same NFC session.
- The browser's `clientDataHash` is passed through unchanged, and the key signs it. The site therefore verifies an ordinary assertion.

The full protocol, including message formats, state rules and security properties, is in [docs/relay-contract.md](docs/relay-contract.md).

## Repository layout

| Path | What it is |
|---|---|
| [`phone/`](phone/) | iPhone app (SwiftUI, [YubiKit Swift](https://github.com/Yubico/yubikit-swift)). `phone/RelayCore` holds the platform-independent logic: strict CTAP CBOR parsing, request checks and rewriting, framing, CTAP over APDUs. |
| [`receiver/`](receiver/) | Receiver in Rust: CTAPHID device, getInfo, relaying to the phone. `receiver/pi/` has the Linux USB gadget script and systemd units. |
| [`rp/`](rp/) | Local WebAuthn relying party that reports every verification check: signature, challenge, origin, RP ID hash, UP and UV flags, counter, attestation. |
| [`bench/`](bench/) | Tools to exercise the chain without USB hardware: a browser-side client using python-fido2, and a receiver stand-in. |
| [`docs/relay-contract.md`](docs/relay-contract.md) | The relay contract. |

## Requirements

- A YubiKey (or other FIDO2 key) with FIDO2 enabled over NFC and a PIN set.
- An iPhone with NFC, and an Apple Developer account. The NFC tag-reading entitlement is not available to free provisioning.
- For the receiver: a Linux board with USB device (gadget) mode, such as a Raspberry Pi Zero 2 W.
- Network reachability from the phone to the receiver, for example a private overlay network.

## Build and test

Phone core library (macOS):

```bash
cd phone/RelayCore && swift test
```

Phone app ([XcodeGen](https://github.com/yonaskolb/XcodeGen); set your own team):

```bash
cd phone && xcodegen generate
```

```bash
xcodebuild -project phone/KeyRelayPhone.xcodeproj -scheme KeyRelayPhone -destination 'generic/platform=iOS' -allowProvisioningUpdates DEVELOPMENT_TEAM=<your team ID> build
```

Receiver tests, and a cross-compile for a 32-bit Raspberry Pi OS image (works on the Zero 2 W) with [cargo-zigbuild](https://github.com/rust-cross/cargo-zigbuild):

```bash
cd receiver && cargo test
```

```bash
cd receiver && cargo zigbuild --release --target arm-unknown-linux-gnueabihf
```

On the Pi, enable gadget mode (`dtoverlay=dwc2,dr_mode=peripheral` in `config.txt`), install `receiver/pi/setup-gadget.sh` and the two units, and write `/etc/keyrelay/receiver.json` from `receiver/pi/receiver.example.json` with your key's getInfo values.

Test relying party and bench tests:

```bash
uv run --project rp rp/server.py
```

```bash
uv run --project rp pytest rp
```

```bash
cd receiver && cargo build && cd ../bench && uv run pytest
```

The bench chain test runs a python-fido2 client against the real receiver (in its `tcp-listen` HID mode) and a simulated phone. `bench/host.py` does the same with the real phone app and key.

## What has been tested

| Path | Result |
|---|---|
| iPhone app ↔ YubiKey over NFC, rewritten requests | Registration and sign-in pass every check at the test RP |
| python-fido2 client ↔ receiver ↔ iPhone app ↔ key | Registration and sign-in pass; sign-in takes one PIN and one hold |
| Failure paths | Wrong PIN and retry, deny, and browser cancel all behave as the contract specifies |
| Automated | RelayCore 24 Swift tests; receiver 32 Rust tests; bench and RP 41 Python tests |
| A real browser over USB with the Pi receiver | **Not yet tested** |

## Security notes and limits

- The private key never leaves the security key. The PIN never leaves the phone and is not sent to the receiver.
- The phone parses every request strictly and shows the RP ID from the bytes it sends to the key.
- **The phone cannot see the browser's origin or challenge.** A compromised computer or receiver can use an approval meant for one sign-in to complete another sign-in to the same site.
- **The phone–receiver channel is plain TCP in this version.** The contract's pinned-key encryption (decision D2) is not implemented. Use only on a network you control.
- Extensions such as hmac-secret, PRF and largeBlob are not supported.

## License

[MIT](LICENSE)
