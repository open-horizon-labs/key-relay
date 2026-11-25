//! Receiver logic, free of I/O: CTAPHID on one side (interface A), the phone
//! session on the other (interface B). Time is passed in so tests control it.
//! See docs/relay-contract.md.

use std::collections::{HashSet, VecDeque};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use ciborium::value::Value;
use serde_json::{json, Value as Json};

use crate::ctaphid::{self, cmd, err, Assembly, Packet, Report};

pub const PROTOCOL_VERSION: u64 = 1;
const KEEPALIVE_EVERY: Duration = Duration::from_millis(80);
const CONTINUATION_TIMEOUT: Duration = Duration::from_secs(3); // D7
const ARM_WAIT: Duration = Duration::from_secs(30);
const REQUEST_DEADLINE: Duration = Duration::from_secs(120);
const NEXT_ASSERTION_TTL: Duration = Duration::from_secs(30);
const PING_AFTER: Duration = Duration::from_secs(5);
const PHONE_SILENCE_LIMIT: Duration = Duration::from_secs(15);

mod ctap {
    pub const MAKE_CREDENTIAL: u8 = 0x01;
    pub const GET_ASSERTION: u8 = 0x02;
    pub const GET_INFO: u8 = 0x04;
    pub const CLIENT_PIN: u8 = 0x06;
    pub const GET_NEXT_ASSERTION: u8 = 0x08;
    pub const OK: u8 = 0x00;
    pub const INVALID_COMMAND: u8 = 0x01;
    pub const INVALID_CBOR: u8 = 0x12;
    pub const UNSUPPORTED_OPTION: u8 = 0x2B;
    pub const KEEPALIVE_CANCEL: u8 = 0x2D;
    pub const USER_ACTION_TIMEOUT: u8 = 0x2F;
    pub const NOT_ALLOWED: u8 = 0x30;
}

#[derive(Debug, Clone, PartialEq)]
pub enum Output {
    /// An input report to write to the HID device.
    Hid(Report),
    /// A message to send to the phone (already carries "v").
    Phone(Json),
    /// Close the phone connection.
    ClosePhone,
    /// Operational log line: types, IDs, status codes and timings only.
    Log(String),
}

struct Pending {
    cid: u32,
    command: u8,
    params: Vec<u8>,
    received: Instant,
    sent: Option<(u64, Instant)>,
    last_keepalive: Instant,
}

struct PhoneState {
    hello: bool,
    armed_until: Option<Instant>,
    last_rx: Instant,
    last_tx: Instant,
}

struct NextAssertions {
    remaining: VecDeque<Vec<u8>>,
    at: Instant,
}

pub struct Core {
    get_info: Vec<u8>,
    channels: HashSet<u32>,
    next_cid: u32,
    assembly: Option<(Assembly, Instant)>,
    pending: Option<Pending>,
    phone: Option<PhoneState>,
    next_request_id: u64,
    next_assertions: Option<NextAssertions>,
    out: Vec<Output>,
}

impl Core {
    pub fn new(get_info: Vec<u8>) -> Self {
        Core {
            get_info,
            channels: HashSet::new(),
            next_cid: 1,
            assembly: None,
            pending: None,
            phone: None,
            next_request_id: 1,
            next_assertions: None,
            out: Vec::new(),
        }
    }

    fn take(&mut self) -> Vec<Output> {
        std::mem::take(&mut self.out)
    }

    fn log(&mut self, line: impl Into<String>) {
        self.out.push(Output::Log(line.into()));
    }

    // ---------------------------------------------------------------- HID side

    pub fn handle_report(&mut self, report: &Report, now: Instant) -> Vec<Output> {
        match ctaphid::parse(report) {
            Packet::Init { cid, cmd, bcnt, data } => self.on_init_packet(cid, cmd, bcnt, data, now),
            Packet::Cont { cid, seq, data } => self.on_cont_packet(cid, seq, data, now),
        }
        self.take()
    }

    fn hid(&mut self, cid: u32, command: u8, payload: &[u8]) {
        for report in ctaphid::frame(cid, command, payload) {
            self.out.push(Output::Hid(report));
        }
    }

    fn hid_error(&mut self, cid: u32, code: u8) {
        self.hid(cid, cmd::ERROR, &[code]);
    }

    fn cbor_reply(&mut self, cid: u32, status: u8, body: &[u8]) {
        let mut payload = vec![status];
        payload.extend_from_slice(body);
        self.hid(cid, cmd::CBOR, &payload);
    }

    fn on_init_packet(&mut self, cid: u32, command: u8, bcnt: usize, data: &[u8], now: Instant) {
        if cid == 0 {
            return self.hid_error(cid, err::INVALID_CHANNEL);
        }
        if command == cmd::INIT {
            return self.on_init_command(cid, bcnt, data, now);
        }
        if cid == ctaphid::BROADCAST_CID || !self.channels.contains(&cid) {
            return self.hid_error(cid, err::INVALID_CHANNEL);
        }
        if command == cmd::CANCEL {
            if self.pending.as_ref().is_some_and(|p| p.cid == cid) {
                self.log(format!("browser cancelled on channel {cid:#x}"));
                self.cancel_pending(ctap::KEEPALIVE_CANCEL, now);
            }
            return; // never answered; ignored when nothing is pending on this channel
        }
        if let Some((assembly, _)) = &self.assembly {
            if assembly.cid == cid {
                self.assembly = None;
                return self.hid_error(cid, err::INVALID_SEQ);
            }
            return self.hid_error(cid, err::CHANNEL_BUSY);
        }
        if self.pending.is_some() {
            return self.hid_error(cid, err::CHANNEL_BUSY);
        }
        if bcnt > ctaphid::MAX_MESSAGE {
            return self.hid_error(cid, err::INVALID_LEN);
        }
        let assembly = Assembly::start(cid, command, bcnt, data);
        if assembly.complete() {
            self.dispatch(assembly, now);
        } else {
            self.assembly = Some((assembly, now));
        }
    }

    fn on_cont_packet(&mut self, cid: u32, seq: u8, data: &[u8], now: Instant) {
        let Some((assembly, _)) = self.assembly.as_mut() else { return };
        if assembly.cid != cid {
            return; // spurious continuation from another channel
        }
        if !assembly.push(seq, data) {
            self.assembly = None;
            return self.hid_error(cid, err::INVALID_SEQ);
        }
        if assembly.complete() {
            let (assembly, _) = self.assembly.take().expect("checked above");
            self.dispatch(assembly, now);
        }
    }

    fn on_init_command(&mut self, cid: u32, bcnt: usize, data: &[u8], now: Instant) {
        if bcnt != 8 {
            return self.hid_error(cid, err::INVALID_LEN);
        }
        let nonce = data[..8].to_vec();
        let (reply_on, channel) = if cid == ctaphid::BROADCAST_CID {
            let new = self.next_cid;
            self.next_cid = self.next_cid.wrapping_add(1).max(1);
            self.channels.insert(new);
            (cid, new)
        } else if self.channels.contains(&cid) {
            // Re-synchronise this channel: abort its transaction without answering it.
            if self.assembly.as_ref().is_some_and(|(a, _)| a.cid == cid) {
                self.assembly = None;
            }
            if self.pending.as_ref().is_some_and(|p| p.cid == cid) {
                self.log(format!("INIT on channel {cid:#x} aborts its pending request"));
                self.abort_pending_silently(now);
            }
            (cid, cid)
        } else {
            return self.hid_error(cid, err::INVALID_CHANNEL);
        };
        let mut payload = nonce;
        payload.extend_from_slice(&channel.to_be_bytes());
        payload.extend_from_slice(&[2, 0, 1, 0, ctaphid::CAPABILITY_CBOR | ctaphid::CAPABILITY_NMSG]);
        self.hid(reply_on, cmd::INIT, &payload);
    }

    fn dispatch(&mut self, assembly: Assembly, now: Instant) {
        let Assembly { cid, cmd: command, data, .. } = assembly;
        match command {
            cmd::PING => self.hid(cid, cmd::PING, &data),
            cmd::CBOR => self.on_cbor(cid, &data, now),
            _ => self.hid_error(cid, err::INVALID_CMD), // MSG (no U2F), WINK, LOCK, unknown
        }
    }

    fn on_cbor(&mut self, cid: u32, data: &[u8], now: Instant) {
        let Some((&command, params)) = data.split_first() else {
            return self.hid_error(cid, err::INVALID_LEN);
        };
        if command != ctap::GET_NEXT_ASSERTION {
            self.next_assertions = None;
        }
        match command {
            ctap::GET_INFO => {
                let info = self.get_info.clone();
                self.cbor_reply(cid, ctap::OK, &info);
            }
            ctap::CLIENT_PIN => {
                let status_and_body = match parse_map(params) {
                    None => (ctap::INVALID_CBOR, Vec::new()),
                    Some(map) if map_get_uint(&map, 2) == Some(0x07) => {
                        // getUVRetries: must be above zero or clients skip built-in UV.
                        let mut body = Vec::new();
                        let reply = Value::Map(vec![(Value::Integer(5.into()), Value::Integer(3.into()))]);
                        ciborium::into_writer(&reply, &mut body).expect("static map encodes");
                        (ctap::OK, body)
                    }
                    Some(_) => (ctap::UNSUPPORTED_OPTION, Vec::new()),
                };
                self.log(format!("clientPIN answered locally with status {:#04x}", status_and_body.0));
                self.cbor_reply(cid, status_and_body.0, &status_and_body.1);
            }
            ctap::GET_NEXT_ASSERTION => {
                let fresh = self.next_assertions.as_ref().is_some_and(|n| now - n.at <= NEXT_ASSERTION_TTL);
                match self.next_assertions.as_mut().filter(|_| fresh).and_then(|n| n.remaining.pop_front()) {
                    Some(body) => {
                        if let Some(n) = self.next_assertions.as_mut() {
                            n.at = now;
                        }
                        self.cbor_reply(cid, ctap::OK, &body);
                    }
                    None => {
                        self.next_assertions = None;
                        self.cbor_reply(cid, ctap::NOT_ALLOWED, &[]);
                    }
                }
            }
            ctap::MAKE_CREDENTIAL | ctap::GET_ASSERTION => {
                if parse_map(params).is_none() {
                    return self.cbor_reply(cid, ctap::INVALID_CBOR, &[]);
                }
                self.log(format!("browser request {command:#04x} on channel {cid:#x}, {} bytes", params.len()));
                self.pending = Some(Pending {
                    cid,
                    command,
                    params: params.to_vec(),
                    received: now,
                    sent: None,
                    last_keepalive: now,
                });
                self.hid(cid, cmd::KEEPALIVE, &[ctaphid::KEEPALIVE_UPNEEDED]);
                self.forward_if_armed(now);
            }
            _ => self.cbor_reply(cid, ctap::INVALID_COMMAND, &[]),
        }
    }

    fn finish_pending(&mut self, status: u8, body: &[u8], now: Instant) {
        if let Some(pending) = self.pending.take() {
            let elapsed = now - pending.received;
            self.log(format!("answered browser with status {status:#04x} after {} ms", elapsed.as_millis()));
            self.cbor_reply(pending.cid, status, body);
            if self.phone.is_some() {
                self.send_state(now);
            }
        }
    }

    fn cancel_pending(&mut self, status: u8, now: Instant) {
        if let Some((id, _)) = self.pending.as_ref().and_then(|p| p.sent) {
            self.phone_send(json!({"type": "cancel", "request_id": id}), now);
        }
        self.finish_pending(status, &[], now);
    }

    fn abort_pending_silently(&mut self, now: Instant) {
        if let Some(pending) = self.pending.take() {
            if let Some((id, _)) = pending.sent {
                self.phone_send(json!({"type": "cancel", "request_id": id}), now);
            }
        }
    }

    // -------------------------------------------------------------- phone side

    fn armed(&self, now: Instant) -> bool {
        self.phone.as_ref().and_then(|p| p.armed_until).is_some_and(|until| now < until)
    }

    fn phone_send(&mut self, mut message: Json, now: Instant) {
        message["v"] = json!(PROTOCOL_VERSION);
        if let Some(phone) = self.phone.as_mut() {
            phone.last_tx = now;
            self.out.push(Output::Phone(message));
        }
    }

    fn send_state(&mut self, now: Instant) {
        let remaining = self
            .phone
            .as_ref()
            .and_then(|p| p.armed_until)
            .map(|until| until.saturating_duration_since(now).as_millis() as u64)
            .unwrap_or(0);
        let pending_id = self.pending.as_ref().and_then(|p| p.sent).map(|(id, _)| id);
        self.phone_send(
            json!({"type": "state", "armed": remaining > 0, "expires_in_ms": remaining, "pending_request_id": pending_id}),
            now,
        );
    }

    fn forward_if_armed(&mut self, now: Instant) {
        if !self.armed(now) {
            return;
        }
        let Some(pending) = self.pending.as_mut().filter(|p| p.sent.is_none()) else { return };
        let id = self.next_request_id;
        self.next_request_id += 1;
        pending.sent = Some((id, now));
        let message = json!({
            "type": "request",
            "request_id": id,
            "ctap_command": pending.command,
            "ctap_params": B64.encode(&pending.params),
            "deadline_ms": REQUEST_DEADLINE.as_millis() as u64,
        });
        self.log(format!("forwarded request {id} to the phone"));
        self.phone_send(message, now);
    }

    pub fn phone_connected(&mut self, now: Instant) -> Vec<Output> {
        if self.phone.is_some() {
            self.phone_lost(now);
        }
        self.phone = Some(PhoneState { hello: false, armed_until: None, last_rx: now, last_tx: now });
        self.log("phone connected");
        self.take()
    }

    pub fn phone_disconnected(&mut self, now: Instant) -> Vec<Output> {
        if self.phone.is_some() {
            self.log("phone disconnected");
            self.phone_lost(now);
        }
        self.take()
    }

    /// The session ended: answer a forwarded request with a timeout, and disarm.
    fn phone_lost(&mut self, now: Instant) {
        self.phone = None;
        if self.pending.as_ref().is_some_and(|p| p.sent.is_some()) {
            self.finish_pending(ctap::USER_ACTION_TIMEOUT, &[], now);
        }
    }

    fn protocol_error(&mut self, code: &str, message: &str, now: Instant) {
        self.log(format!("protocol error from phone: {code}"));
        self.phone_send(json!({"type": "error", "code": code, "message": message}), now);
        self.out.push(Output::ClosePhone);
        self.phone_lost(now);
    }

    pub fn phone_message(&mut self, message: &Json, now: Instant) -> Vec<Output> {
        let Some(phone) = self.phone.as_mut() else { return self.take() };
        phone.last_rx = now;
        let hello_done = phone.hello;
        if message.get("v").and_then(Json::as_u64) != Some(PROTOCOL_VERSION) {
            self.protocol_error("version", "expected v=1", now);
            return self.take();
        }
        let kind = message.get("type").and_then(Json::as_str).unwrap_or("");
        if !hello_done && kind != "hello" {
            self.protocol_error("unexpected", "hello must come first", now);
            return self.take();
        }
        match kind {
            "hello" => {
                if message.get("role").and_then(Json::as_str) != Some("phone") {
                    self.protocol_error("unexpected", "expected role phone", now);
                } else {
                    if let Some(p) = self.phone.as_mut() {
                        p.hello = true;
                    }
                    self.phone_send(
                        json!({"type": "hello", "role": "receiver", "app_version": concat!("keyrelay-receiver ", env!("CARGO_PKG_VERSION"))}),
                        now,
                    );
                }
            }
            "ping" => {}
            "arm" => match message.get("ttl_ms").and_then(Json::as_u64) {
                Some(ttl) if (1_000..=900_000).contains(&ttl) => {
                    if let Some(p) = self.phone.as_mut() {
                        p.armed_until = Some(now + Duration::from_millis(ttl));
                    }
                    self.log(format!("armed for {} s", ttl / 1000));
                    self.send_state(now);
                    self.forward_if_armed(now);
                }
                _ => self.protocol_error("malformed", "ttl_ms must be 1000..=900000", now),
            },
            "disarm" => {
                if let Some(p) = self.phone.as_mut() {
                    p.armed_until = None;
                }
                self.log("disarmed");
                self.send_state(now);
            }
            "response" => self.on_response(message, now),
            "error" => {
                self.log("phone reported an error and is closing");
                self.out.push(Output::ClosePhone);
                self.phone_lost(now);
            }
            _ => self.protocol_error("unexpected", "unknown message type", now),
        }
        self.take()
    }

    fn on_response(&mut self, message: &Json, now: Instant) {
        let id = message.get("request_id").and_then(Json::as_u64);
        let expected = self.pending.as_ref().and_then(|p| p.sent).map(|(id, _)| id);
        if id.is_none() || id != expected {
            self.log(format!("discarded response for request {id:?}; pending is {expected:?}"));
            return;
        }
        let status = message.get("status").and_then(Json::as_u64).filter(|s| *s <= 0xFF);
        let results: Option<Vec<Vec<u8>>> = message
            .get("results")
            .and_then(Json::as_array)
            .and_then(|items| items.iter().map(|r| r.as_str().and_then(|s| B64.decode(s).ok())).collect());
        let (Some(status), Some(mut results)) = (status, results) else {
            return self.protocol_error("malformed", "bad response fields", now);
        };
        if (status == 0) == results.is_empty() {
            return self.protocol_error("malformed", "status and results disagree", now);
        }
        if status != 0 {
            return self.finish_pending(status as u8, &[], now);
        }
        let first = results.remove(0);
        let is_assertion = self.pending.as_ref().is_some_and(|p| p.command == ctap::GET_ASSERTION);
        if is_assertion && !results.is_empty() {
            self.next_assertions = Some(NextAssertions { remaining: results.into(), at: now });
        }
        self.finish_pending(ctap::OK, &first, now);
    }

    // ------------------------------------------------------------------ timers

    pub fn tick(&mut self, now: Instant) -> Vec<Output> {
        if let Some((assembly, started)) = &self.assembly {
            if now - *started > CONTINUATION_TIMEOUT {
                let cid = assembly.cid;
                self.assembly = None;
                self.hid_error(cid, err::MSG_TIMEOUT);
            }
        }

        if let Some(pending) = &self.pending {
            match pending.sent {
                None if now - pending.received > ARM_WAIT => {
                    self.log("no armed phone within 30 s");
                    self.finish_pending(ctap::USER_ACTION_TIMEOUT, &[], now);
                }
                Some((id, sent_at)) if now - sent_at > REQUEST_DEADLINE => {
                    self.log(format!("request {id} passed its deadline"));
                    self.phone_send(json!({"type": "cancel", "request_id": id}), now);
                    self.finish_pending(ctap::USER_ACTION_TIMEOUT, &[], now);
                }
                _ if now - pending.last_keepalive >= KEEPALIVE_EVERY => {
                    let cid = pending.cid;
                    if let Some(p) = self.pending.as_mut() {
                        p.last_keepalive = now;
                    }
                    self.hid(cid, cmd::KEEPALIVE, &[ctaphid::KEEPALIVE_UPNEEDED]);
                }
                _ => {}
            }
        }

        if let Some(phone) = &self.phone {
            let expired = phone.armed_until.is_some_and(|until| now >= until);
            let silent = now - phone.last_rx > PHONE_SILENCE_LIMIT;
            let idle = now - phone.last_tx >= PING_AFTER;
            if expired {
                if let Some(p) = self.phone.as_mut() {
                    p.armed_until = None;
                }
                self.log("arming expired");
                self.send_state(now);
            }
            if silent {
                self.log("phone silent for 15 s; closing");
                self.out.push(Output::ClosePhone);
                self.phone_lost(now);
            } else if idle {
                self.phone_send(json!({"type": "ping"}), now);
            }
        }

        if self.next_assertions.as_ref().is_some_and(|n| now - n.at > NEXT_ASSERTION_TTL) {
            self.next_assertions = None;
        }
        self.take()
    }
}

fn parse_map(bytes: &[u8]) -> Option<Vec<(Value, Value)>> {
    let mut reader = bytes;
    match ciborium::from_reader::<Value, _>(&mut reader) {
        Ok(Value::Map(map)) if reader.is_empty() => Some(map),
        _ => None,
    }
}

fn map_get_uint(map: &[(Value, Value)], key: u64) -> Option<u64> {
    map.iter().find(|(k, _)| k.as_integer().and_then(|i| u64::try_from(i).ok()) == Some(key)).and_then(|(_, v)| {
        v.as_integer().and_then(|i| u64::try_from(i).ok())
    })
}
