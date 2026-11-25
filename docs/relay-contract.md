# KeyRelay relay contract

**Status:** draft v0.1. Implemented by `phone/` and `receiver/`. Assumptions **A1–A6** are untested and listed with their tests at the end; open decisions are **D2–D7**.

This contract defines the two interfaces a KeyRelay sign-in crosses:

```
Mac browser ──A: CTAPHID over USB──▶ Receiver (Raspberry Pi) ──B: framed JSON over TCP──▶ Phone app ──NFC──▶ YubiKey
```

- **Interface A** is fixed by the FIDO CTAP specification. The contract says which parts the receiver implements and how.
- **Interface B** is ours. The contract defines its messages, states and errors.

The YubiKey side uses CTAP over NFC through YubiKit Swift and is not redefined here.

## Design decision: the phone performs user verification

The receiver presents itself to the browser as an authenticator with **built-in user verification and no client PIN**, like a key with a fingerprint reader. The browser never asks for a PIN. The phone collects the real PIN, obtains a PIN token from the YubiKey and rewrites each request into the form the YubiKey accepts.

**The phone verifies the PIN for every request that needs user presence**, whatever the browser asked for. A relying party that sets `userVerification: "discouraged"` makes the browser omit `uv`; without a PIN token the key would then refuse a discoverable `makeCredential` (`0x36`) or sign without the UV flag, which breaks the requirement for key-backed PIN verification.

| Property | Consequence |
|---|---|
| The PIN never leaves the phone | No PIN typed on the remote computer, and no PIN on interface B |
| The browser's `clientDataHash` is forwarded unchanged | The key's signature covers `authData ‖ clientDataHash`; the key builds `authData` with the RP ID hash and the UP and UV flags, so the relying party verifies it as for any other key |
| The phone changes only `options.uv`, `pinUvAuthParam` and `pinUvAuthProtocol` | None of these are covered by the signature. The outer map is re-encoded in canonical order; every other value is copied unchanged. |
| The PIN is entered before the tap | One NFC hold per sign-in instead of the two seen in Yubico's sample |
| The receiver answers some commands itself | It must be trusted to do so correctly; see the security section for what a compromised receiver can still do |
| No extensions are advertised | hmac-secret, PRF, credBlob and largeBlob are unavailable; credProtect is not requested by browsers. |

Alternative rejected for now: a transparent relay, where the browser runs the PIN protocol with the key and the PIN is typed on the remote computer. It keeps the receiver simpler but has the PIN typed on the computer itself, and requires one NFC hold to span the typing.

## Interface A: browser to receiver

### USB presence

The receiver exposes its USB HID function **only after pairing** has cached the key's `getInfo` fields. Before that the Mac sees no security key.

The HID function uses the FIDO usage page `0xF1D0`, usage `0x01`, with 64-byte input and output reports. Vendor and product IDs are open decision **D3** and must not impersonate Yubico's.

### CTAPHID framing

Checked against the CTAP 2.2 specification's USB HID section (CTAPHID). Where the specification is silent, the row says so.

| Item | Rule |
|---|---|
| Initialisation packet | Channel ID (4 bytes), command with the high bit set (1), payload length big-endian (2), up to 57 payload bytes |
| Continuation packet | Channel ID (4), sequence number 0–127 (1), up to 59 payload bytes |
| Maximum message | 7609 bytes (57 + 128 × 59) |
| `INIT` request | On the broadcast channel `0xFFFFFFFF` with an 8-byte nonce |
| `INIT` response, 17 bytes | Nonce (8), new channel ID (4), CTAPHID protocol version `2` (1), device version major, minor, build (3), capability flags (1) |
| `INIT` on a channel with a transaction in progress | Aborts that transaction; the channel stays allocated |
| Unknown channel ID | `ERROR 0x0B` invalid channel |
| Missing continuation packets | `ERROR 0x05` message timeout. The specification gives no value; the receiver uses 3 s (**D7**). |
| `CANCEL` from a channel other than the pending one | Ignored |

### CTAPHID commands

| Command | Code | Receiver behaviour |
|---|---|---|
| `INIT` | `0x06` | As above. Capability flags `CBOR \| NMSG` (`0x04 \| 0x08 = 0x0C`): CTAP2 only, no U2F, no wink. Broadcast `INIT` is answered even while another channel is busy; the specification does not address this case, and refusing it would block a browser from opening the device during a request. |
| `PING` | `0x01` | Echo |
| `CBOR` | `0x10` | Dispatch per the next table |
| `CANCEL` | `0x11` | Only from the channel with the pending request; ignored otherwise and when nothing is pending. Never answered itself. Send `cancel` on interface B and answer the pending `CBOR` with CTAP status `0x2D` (keepalive cancel) as a normal `CBOR` response. |
| `KEEPALIVE` | `0x3B` | Sent by the receiver at least every 100 ms, and whenever the status changes, while a `CBOR` request is pending: status `0x02` (user presence needed) from forwarding the request until the phone answers |
| `MSG` | `0x03` | `ERROR 0x01`; U2F is out of scope |
| `WINK`, `LOCK` | `0x08`, `0x04` | `ERROR 0x01` |

Only one `CBOR` request is in flight at a time. A `CBOR` request on another channel meanwhile gets `ERROR 0x06` channel busy.

### CTAP2 commands

| Command | Code | Handled by | Behaviour |
|---|---|---|---|
| `authenticatorGetInfo` | `0x04` | Receiver | Answer from the template below, without contacting the phone |
| `authenticatorMakeCredential` | `0x01` | Phone | Forward as a `request` |
| `authenticatorGetAssertion` | `0x02` | Phone | Forward as a `request`. If the phone returns several assertions, return the first and keep the rest. |
| `authenticatorGetNextAssertion` | `0x08` | Receiver | Return the next kept assertion. `0x30` (not allowed) if none remain, if another command intervened, or if 30 s have passed since the `getAssertion` |
| `authenticatorClientPIN`, subcommand `getUVRetries` (`0x07`) | `0x06` | Receiver | `{0x05: 3}`. It must be above zero: YubiKit's client skips built-in UV when it is zero, and browsers are assumed to behave alike (**A2**). |
| `authenticatorClientPIN`, any other subcommand | `0x06` | Receiver | `0x2B` (unsupported option) |
| `authenticatorSelection` | `0x0B` | Receiver | `0x01` (invalid command). It is a CTAP 2.1 command and the receiver claims 2.0 only. |
| Anything else | | Receiver | `0x01` (invalid command) |

### getInfo template

| Key | Field | Value |
|---|---|---|
| `0x01` | versions | `["FIDO_2_0"]` only. Claiming 2.1 would invite the 2.1 token path for built-in UV (**A1**). |
| `0x02` | extensions | omitted |
| `0x03` | aaguid | the paired key's AAGUID |
| `0x04` | options | `{"rk": true, "up": true, "uv": true, "plat": false}`; `clientPin` and `pinUvAuthToken` absent |
| `0x05` | maxMsgSize | the paired key's value |
| `0x06` | pinUvAuthProtocols | the paired key's list, e.g. `[2, 1]`. Required even without `clientPin`: clients send `getUVRetries` with a protocol version, and python-fido2 2.2.1 refuses built-in UV when the list is empty. |
| `0x07` | maxCredentialCountInList | the paired key's value, so clients send allow-lists in as few requests as possible |
| `0x08` | maxCredentialIdLength | the paired key's value |
| `0x09` | transports | `["usb"]` (a 2.1 field; 2.0 clients ignore it) |
| `0x0A` | algorithms | the paired key's list (a 2.1 field) |

### Status codes the receiver produces

| Situation | CTAP status to the browser |
|---|---|
| Operator tapped Deny on the phone | `0x27` operation denied |
| PIN blocked, or the key reports a PIN or UV error the phone cannot resolve | `0x27` operation denied. Wrong PINs are retried on the phone and never reach the browser. |
| No phone armed within the wait, phone gave no answer before the deadline, or the phone connection dropped | `0x2F` user action timeout |
| Browser sent `CANCEL` | `0x2D` keepalive cancel |
| Key returned `0x2E` no credentials, `0x19` credential excluded, `0x26` unsupported algorithm or `0x28` key store full | Passed through unchanged |
| Key returned any other error | `0x7F` other |
| Malformed request from the browser | `0x12` invalid CBOR, or `0x14` missing parameter |

## Interface B: receiver to phone

### Transport

- **Direction:** the phone connects to the receiver. The receiver listens on its Tailscale address, port **D6**. A LAN address is allowed for bench tests.
- **Channel security:** a mutually authenticated, encrypted channel with keys pinned at pairing, independent of Tailscale (**D2**). A connection that fails the handshake is closed before any message is read.
- **One session:** after a successful handshake, a new session replaces any existing one. The old one is closed, and its pending request is cancelled and answered `0x2F`.
- **Framing:** each message is a 4-byte big-endian length followed by that many bytes of UTF-8 JSON. Maximum message length 64 KiB. Binary fields are base64url without padding.
- **Liveness:** each side sends `ping` after 5 s without sending anything else, and treats 15 s without receiving anything as a lost connection.
- **Time:** all times are relative durations in milliseconds. The Pi Zero has no real-time clock, so no absolute timestamps cross the wire.

### Pairing

The phone's public key is installed on the receiver over SSH. The receiver's public key is entered in the phone app together with a **host label chosen by the operator**, which the phone stores against that key. Pairing also caches on the receiver the key's `getInfo` fields used in the template. Re-pairing is required if the YubiKey changes.

### Messages

Every message has `"type"` and `"v": 1`. A receiver or phone that gets a different `v` sends `error` with code `version` and closes.

| Type | Direction | Fields | Meaning |
|---|---|---|---|
| `hello` | both | `role` (`"phone"` or `"receiver"`), `app_version` | First message after the handshake |
| `arm` | phone → receiver | `ttl_ms` (1 000–900 000) | The operator authorises requests for this long. Sent only while the app is in the foreground. Arming while armed replaces the remaining time. |
| `disarm` | phone → receiver | | Ends authorisation now |
| `state` | receiver → phone | `armed` (bool), `expires_in_ms`, `pending_request_id` (or null) | Sent after `arm`, `disarm`, expiry and request completion |
| `request` | receiver → phone | `request_id`, `ctap_command` (`1` or `2`), `ctap_params` (CBOR map, base64url), `deadline_ms` | A browser request to perform. The receiver sets `deadline_ms`. |
| `response` | phone → receiver | `request_id`, `status` (CTAP status byte), `results` (list of CTAP response CBOR maps, base64url, without status byte) | Outcome. If `status` is `0`, `results` holds one map for `makeCredential` and one or more for `getAssertion`. If `status` is not `0`, `results` is empty. |
| `cancel` | receiver → phone | `request_id` | Browser cancelled or deadline passed; the phone ends the NFC session and discards the result |
| `ping` | both | | Liveness only |
| `error` | both | `code` (`version`, `malformed`, `unexpected`, `internal`), `message` | Protocol error; the sender closes the connection afterwards |

`request_id` is an unsigned integer that the receiver increments for each request within a session. The receiver discards any `response` whose `request_id` is not the pending one, including late responses after `cancel`. A `response` with `status` 0 and empty `results`, or the reverse, is `malformed`.

### States

```
disconnected ──handshake + hello──▶ connected ──arm──▶ armed ──request──▶ pending
     ▲                                ▲   ▲              │                   │
     │                                │   └─disarm / TTL─┘                   │
     │                                └──── response or cancel, TTL expired ─┤
     │                                       response or cancel, TTL left ───┴──▶ armed
     └──────────────── connection lost (from any state) ────────────────────────
```

- The receiver sends a `request` only in `armed`, and only one at a time.
- A browser request that arrives while not armed waits, with keepalives, until the phone arms or 30 s pass, then gets `0x2F`.
- Expiry of `ttl_ms` during `pending` does not abort that request; it only stops new ones.
- A lost connection cancels the pending request and disarms. A new connection must `arm` again; arming never survives a reconnect.

## Phone obligations

1. **Parse strictly before showing or forwarding anything.** `ctap_params` must be a single CTAP2 canonical CBOR map, with no duplicate keys, no trailing bytes and no indefinite lengths. Anything else is answered `0x12` and not sent to the key. This prevents a compromised receiver from crafting bytes the phone reads one way and the key another.
2. **Accept only the fields a browser legitimately sends to this authenticator.** For `makeCredential`: keys 1–5 and 7. For `getAssertion`: keys 1, 2, 3 and 5. Reject extensions, a preset `pinUvAuthParam` or `pinUvAuthProtocol`, and `enterpriseAttestation` with `0x2B`. Reject any `ctap_command` other than 1 or 2.
3. **Show what is being approved, from the parsed request.** `rp.id` (key 2) and `user.name` (key 3) for `makeCredential`; `rpId` (key 1) for `getAssertion`. Show the host label the phone stored at pairing, never one sent by the receiver. Make **Register a new passkey** look different from **Sign in**, and warn that registering again for the same site and user replaces an existing passkey.
4. **Collect the PIN, then open one NFC session.** In it, obtain a PIN token with `mc` or `ga` permission bound to that RP ID, send the rewritten command and, if `numberOfCredentials` (response key `0x05`) is above 1, fetch the rest with `getNextAssertion` before the session closes. Wrong PINs are re-prompted on the phone, showing the remaining retries.
5. **Rewrite only the user-verification fields** for every relayed request, silent probes included: remove `uv` from the options map (`makeCredential` key 7, `getAssertion` key 5), omitting the map if it becomes empty, and set `pinUvAuthParam` (keys 8 and 6) and `pinUvAuthProtocol` (keys 9 and 7).
6. **Treat a `getAssertion` with `options.up` false as the start of a sign-in.** Clients probe the allow-list this way before the real request (verified in YubiKit's client, which sends an all-zero `clientDataHash`). The phone shows the site, collects the PIN, opens the NFC session, answers the probe, and keeps the session open for up to 10 s for the following request with the same RP ID, so the operator holds the key once. The PIN token is requested with both `mc` and `ga` permissions for that RP ID so it serves whichever request follows; only a following `getAssertion` for the same RP ID runs without a new approval.
7. **Return the key's response maps unchanged.**
8. **Never send, store or log** the PIN or PIN token, and keep `ctap_params` and responses out of logs.
9. **Offer Deny,** which answers `status: 0x27`.

## Security properties

| Security requirement | Where the contract meets it |
|---|---|
| Private key stays on the YubiKey | Only CTAP requests and responses cross interface B |
| Genuine presence and key-backed PIN | NFC tap is presence; the phone obtains a PIN token for every request needing presence |
| Operator knows which site asks | Phone obligations 1–3: the displayed RP ID comes from strictly parsed bytes that go to the key unchanged |
| Operator identifies the paired host | Pinned keys and a host label stored on the phone |
| Short authorised session | `arm` with `ttl_ms`; never survives reconnect |
| Competing requests | One in flight on each interface; one session on interface B |
| Disconnect cancels pending work | Liveness pings detect loss within 15 s; the browser gets `0x2F`; the phone discards |
| PINs and traffic out of logs | Phone obligation 8; the receiver logs only message types, IDs, status codes and timings |

**Limit not covered:** the phone sees the RP ID but not the browser origin or challenge. A compromised Mac or receiver can therefore use an approval meant for one sign-in to complete a different session for the same site, for example an attacker's. The operator can only check the site name and that a sign-in was expected at that moment.

Ending the relay stops future key operations. It does not sign the user out of existing web sessions.

## Assumptions to test, most consequential first

| ID | Assumption | Test |
|---|---|---|
| **A1** | Chrome on macOS sends `options.uv = true` to an authenticator advertising `uv: true`, no `clientPin`, version `FIDO_2_0` only, and accept the result | Receiver bench test on a Mac in Chrome, against the test RP |
| **A2** | Among `clientPIN` subcommands, browsers query only `getUVRetries` for such an authenticator | Same bench test; the receiver logs every command it receives |
| **A3** | Browser probes (`up: false`) and Chrome's "dummy" `makeCredential` for choosing between several keys (`rp.id` `.dummy`, believed) are infrequent enough to handle as in obligation 6 | Same bench test, plus a run with a second security key attached |
| **A4** | A Raspberry Pi keeps keepalives under 100 ms while waiting on the network | Bench test with timing logged |
| **A5** | The YubiKey sets UP and UV over NFC for the rewritten request, and keeps an NFC session usable across a probe and the following request | Phone-only test against the test RP, before any receiver exists |
| **A6** | A relying party's authenticator policy (for example an AAGUID allow-list) accepts the paired key's AAGUID with these flags | Depends on each relying party; the test RP accepts any key |

## Open decisions

| ID | Decision | Current lean |
|---|---|---|
| D2 | Channel security on interface B | Noise `XX`, or TLS 1.3 with pinned self-signed keys |
| D3 | USB vendor and product ID | A test ID from a shared open-source allocation, never Yubico's |
| D4 | How the phone handles Chrome's `.dummy` `makeCredential` | Answer `0x27` without touching the key, if A3 shows it occurs |
| D5 | Should the phone allow `makeCredential` at all in normal use | Yes, behind the distinct Register screen; revisit after A6 |
| D6 | Receiver TCP port | Any fixed high port |
| D7 | CTAPHID continuation timeout | 3 s; the specification sets no value |

## Verification of this document

- Command codes, status codes, CBOR keys, `clientPIN` subcommands, CTAPHID capability bits and keepalive status values were checked against YubiKit Swift v1.5.0 source, by the author and again by an independent reviewer.
- YubiKit's client behaviour cited above (`getUVRetries` before built-in UV; `up: false` allow-list probes with an all-zero `clientDataHash`) was read in its source.
- Checked against the CTAP 2.2 specification text: the CTAPHID framing table, usage page `0xF1D0` and usage `0x01`, 64-byte reports, `INIT` layout, command and error codes, capability bits, `CANCEL` and busy rules, the 100 ms keepalive interval and the 30 s `getNextAssertion` expiry. The specification states no continuation timeout and does not cover broadcast `INIT` while busy.
- Chrome behaviour is entirely untested; that is what A1–A3 are for. Safari is out of scope.
