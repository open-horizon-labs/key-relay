use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use ciborium::cbor;
use serde_json::{json, Value as Json};

use crate::core::{Core, Output};
use crate::ctaphid::{self, cmd, err, Packet, Report};
use crate::keyinfo::test_key_info;

const NONCE: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

struct Bench {
    core: Core,
    now: Instant,
}

/// A decoded CTAPHID response message.
#[derive(Debug, PartialEq)]
struct Message {
    cid: u32,
    cmd: u8,
    data: Vec<u8>,
}

fn reassemble(outputs: &[Output]) -> Vec<Message> {
    let mut messages = Vec::new();
    let mut current: Option<(Message, usize)> = None;
    for output in outputs {
        let Output::Hid(report) = output else { continue };
        match ctaphid::parse(report) {
            Packet::Init { cid, cmd, bcnt, data } => {
                let take = bcnt.min(data.len());
                let message = Message { cid, cmd, data: data[..take].to_vec() };
                if take == bcnt {
                    messages.push(message);
                } else {
                    current = Some((message, bcnt));
                }
            }
            Packet::Cont { data, .. } => {
                let (message, bcnt) = current.as_mut().expect("continuation without init");
                let take = (*bcnt - message.data.len()).min(data.len());
                message.data.extend_from_slice(&data[..take]);
                if message.data.len() == *bcnt {
                    messages.push(current.take().unwrap().0);
                }
            }
        }
    }
    messages
}

fn phone_messages(outputs: &[Output]) -> Vec<Json> {
    outputs.iter().filter_map(|o| if let Output::Phone(m) = o { Some(m.clone()) } else { None }).collect()
}

fn of_type<'a>(messages: &'a [Json], kind: &str) -> Vec<&'a Json> {
    messages.iter().filter(|m| m["type"] == kind).collect()
}

fn cbor<T: serde::Serialize>(value: &T) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).unwrap();
    out
}

impl Bench {
    fn new() -> Self {
        Bench { core: Core::new(test_key_info().get_info_cbor().unwrap()), now: Instant::now() }
    }

    fn advance(&mut self, ms: u64) -> Vec<Output> {
        self.now += Duration::from_millis(ms);
        self.core.tick(self.now)
    }

    fn send(&mut self, cid: u32, command: u8, payload: &[u8]) -> Vec<Output> {
        let mut outputs = Vec::new();
        for report in ctaphid::frame(cid, command, payload) {
            outputs.extend(self.core.handle_report(&report, self.now));
        }
        outputs
    }

    fn open_channel(&mut self) -> u32 {
        let messages = reassemble(&self.send(ctaphid::BROADCAST_CID, cmd::INIT, &NONCE));
        u32::from_be_bytes(messages[0].data[8..12].try_into().unwrap())
    }

    fn ctap(&mut self, cid: u32, command: u8, params: &[u8]) -> Vec<Output> {
        let mut payload = vec![command];
        payload.extend_from_slice(params);
        self.send(cid, cmd::CBOR, &payload)
    }

    fn connect_phone(&mut self, arm: bool) -> Vec<Output> {
        let mut outputs = self.core.phone_connected(self.now);
        outputs.extend(self.core.phone_message(&json!({"type": "hello", "role": "phone", "app_version": "t", "v": 1}), self.now));
        if arm {
            outputs.extend(self.core.phone_message(&json!({"type": "arm", "ttl_ms": 300_000, "v": 1}), self.now));
        }
        outputs
    }

    fn phone(&mut self, message: Json) -> Vec<Output> {
        self.core.phone_message(&message, self.now)
    }
}

fn cbor_status(messages: &[Message]) -> Vec<(u8, Vec<u8>)> {
    messages.iter().filter(|m| m.cmd == cmd::CBOR).map(|m| (m.data[0], m.data[1..].to_vec())).collect()
}

fn mc_params() -> Vec<u8> {
    cbor(&cbor!({1 => ciborium::value::Value::Bytes(vec![0; 32]), 2 => {"id" => "localhost"}}).unwrap())
}

// ---- CTAPHID basics

#[test]
fn broadcast_init_allocates_a_channel() {
    let mut b = Bench::new();
    let messages = reassemble(&b.send(ctaphid::BROADCAST_CID, cmd::INIT, &NONCE));
    assert_eq!(messages.len(), 1);
    let m = &messages[0];
    assert_eq!((m.cid, m.cmd, m.data.len()), (ctaphid::BROADCAST_CID, cmd::INIT, 17));
    assert_eq!(&m.data[..8], &NONCE);
    assert_ne!(&m.data[8..12], &[0, 0, 0, 0]);
    assert_eq!(m.data[12], 2, "CTAPHID protocol version");
    assert_eq!(m.data[16], 0x0C, "CBOR | NMSG");
}

#[test]
fn unknown_channel_is_rejected() {
    let mut b = Bench::new();
    let messages = reassemble(&b.send(0x1234, cmd::PING, b"hi"));
    assert_eq!(messages, [Message { cid: 0x1234, cmd: cmd::ERROR, data: vec![err::INVALID_CHANNEL] }]);
}

#[test]
fn ping_echoes_across_continuation_packets() {
    let mut b = Bench::new();
    let cid = b.open_channel();
    let payload: Vec<u8> = (0..300).map(|i| i as u8).collect();
    let messages = reassemble(&b.send(cid, cmd::PING, &payload));
    assert_eq!(messages, [Message { cid, cmd: cmd::PING, data: payload }]);
}

#[test]
fn u2f_wink_and_lock_are_refused() {
    let mut b = Bench::new();
    let cid = b.open_channel();
    for command in [cmd::MSG, cmd::WINK, cmd::LOCK] {
        let messages = reassemble(&b.send(cid, command, &[0]));
        assert_eq!(messages[0].data, [err::INVALID_CMD]);
    }
}

#[test]
fn sequence_error_and_continuation_timeout() {
    let mut b = Bench::new();
    let cid = b.open_channel();
    let reports = ctaphid::frame(cid, cmd::PING, &[7; 200]);
    b.core.handle_report(&reports[0], b.now);
    let mut wrong = reports[2]; // seq 1 instead of 0
    wrong[4] = 1;
    let messages = reassemble(&b.core.handle_report(&wrong, b.now));
    assert_eq!(messages[0].data, [err::INVALID_SEQ]);

    b.core.handle_report(&reports[0], b.now);
    let messages = reassemble(&b.advance(3_100));
    assert_eq!(messages[0].data, [err::MSG_TIMEOUT]);
}

// ---- Commands answered locally

#[test]
fn get_info_is_answered_from_the_template() {
    let mut b = Bench::new();
    let cid = b.open_channel();
    let replies = cbor_status(&reassemble(&b.ctap(cid, 0x04, &[])));
    assert_eq!(replies, [(0x00, test_key_info().get_info_cbor().unwrap())]);
}

#[test]
fn client_pin_only_answers_get_uv_retries() {
    let mut b = Bench::new();
    let cid = b.open_channel();
    let uv_retries = cbor(&cbor!({1 => 1, 2 => 7}).unwrap());
    let replies = cbor_status(&reassemble(&b.ctap(cid, 0x06, &uv_retries)));
    assert_eq!(replies, [(0x00, cbor(&cbor!({5 => 3}).unwrap()))]);

    let key_agreement = cbor(&cbor!({1 => 1, 2 => 2}).unwrap());
    assert_eq!(cbor_status(&reassemble(&b.ctap(cid, 0x06, &key_agreement)))[0].0, 0x2B);
    assert_eq!(cbor_status(&reassemble(&b.ctap(cid, 0x06, &[0xFF])))[0].0, 0x12);
}

#[test]
fn selection_and_other_commands_are_invalid() {
    let mut b = Bench::new();
    let cid = b.open_channel();
    for command in [0x0B, 0x07, 0x0A] {
        assert_eq!(cbor_status(&reassemble(&b.ctap(cid, command, &[])))[0], (0x01, vec![]));
    }
}

// ---- Relayed requests

#[test]
fn make_credential_round_trip_through_the_phone() {
    let mut b = Bench::new();
    let cid = b.open_channel();
    b.connect_phone(true);
    let params = mc_params();
    let outputs = b.ctap(cid, 0x01, &params);
    let keepalives = reassemble(&outputs);
    assert_eq!(keepalives[0], Message { cid, cmd: cmd::KEEPALIVE, data: vec![0x02] });
    let phone = phone_messages(&outputs);
    let request = of_type(&phone, "request")[0];
    assert_eq!(request["ctap_command"], 1);
    assert_eq!(B64.decode(request["ctap_params"].as_str().unwrap()).unwrap(), params);
    assert_eq!(request["v"], 1);

    let id = request["request_id"].clone();
    let body = vec![0xA1, 0x01, 0x64, b'n', b'o', b'n', b'e'];
    let outputs = b.phone(json!({"type": "response", "request_id": id, "status": 0, "results": [B64.encode(&body)], "v": 1}));
    assert_eq!(cbor_status(&reassemble(&outputs)), [(0x00, body)]);
    assert_eq!(of_type(&phone_messages(&outputs), "state").len(), 1);
}

#[test]
fn keepalives_flow_every_100_ms_while_waiting() {
    let mut b = Bench::new();
    let cid = b.open_channel();
    b.connect_phone(true);
    b.ctap(cid, 0x01, &mc_params());
    for _ in 0..10 {
        let messages = reassemble(&b.advance(90));
        assert_eq!(messages, [Message { cid, cmd: cmd::KEEPALIVE, data: vec![0x02] }]);
    }
}

#[test]
fn request_waits_for_arming_then_times_out() {
    let mut b = Bench::new();
    let cid = b.open_channel();
    b.connect_phone(false);
    let outputs = b.ctap(cid, 0x01, &mc_params());
    assert!(of_type(&phone_messages(&outputs), "request").is_empty(), "not armed, not forwarded");

    let outputs = b.phone(json!({"type": "arm", "ttl_ms": 60_000, "v": 1}));
    assert_eq!(of_type(&phone_messages(&outputs), "request").len(), 1, "forwarded once armed");

    let mut b = Bench::new();
    let cid = b.open_channel();
    b.ctap(cid, 0x01, &mc_params());
    let mut statuses = Vec::new();
    for _ in 0..40 {
        statuses.extend(cbor_status(&reassemble(&b.advance(1_000))));
    }
    assert_eq!(statuses, [(0x2F, vec![])]);
}

#[test]
fn get_assertion_extra_results_serve_get_next_assertion() {
    let mut b = Bench::new();
    let cid = b.open_channel();
    b.connect_phone(true);
    let params = cbor(&cbor!({1 => "localhost", 2 => ciborium::value::Value::Bytes(vec![0; 32])}).unwrap());
    let outputs = b.ctap(cid, 0x02, &params);
    let id = of_type(&phone_messages(&outputs), "request")[0]["request_id"].clone();
    let results = [vec![0xA0], vec![0xA1, 0x01, 0x01], vec![0xA1, 0x01, 0x02]];
    let outputs = b.phone(json!({"type": "response", "request_id": id, "status": 0,
        "results": results.iter().map(|r| B64.encode(r)).collect::<Vec<_>>(), "v": 1}));
    assert_eq!(cbor_status(&reassemble(&outputs)), [(0x00, results[0].clone())]);
    assert_eq!(cbor_status(&reassemble(&b.ctap(cid, 0x08, &[]))), [(0x00, results[1].clone())]);
    assert_eq!(cbor_status(&reassemble(&b.ctap(cid, 0x08, &[]))), [(0x00, results[2].clone())]);
    assert_eq!(cbor_status(&reassemble(&b.ctap(cid, 0x08, &[]))), [(0x30, vec![])]);
}

#[test]
fn intervening_command_or_30_seconds_ends_get_next_assertion() {
    for interrupt in ["getInfo", "wait"] {
        let mut b = Bench::new();
        let cid = b.open_channel();
        b.connect_phone(true);
        let params = cbor(&cbor!({1 => "localhost", 2 => ciborium::value::Value::Bytes(vec![0; 32])}).unwrap());
        let outputs = b.ctap(cid, 0x02, &params);
        let id = of_type(&phone_messages(&outputs), "request")[0]["request_id"].clone();
        b.phone(json!({"type": "response", "request_id": id, "status": 0, "results": ["oA", "oA"], "v": 1}));
        if interrupt == "getInfo" {
            b.ctap(cid, 0x04, &[]);
        } else {
            b.advance(31_000);
            b.phone(json!({"type": "ping", "v": 1}));
        }
        assert_eq!(cbor_status(&reassemble(&b.ctap(cid, 0x08, &[])))[0].0, 0x30, "{interrupt}");
    }
}

#[test]
fn cancel_from_owner_channel_only() {
    let mut b = Bench::new();
    let cid = b.open_channel();
    let other = b.open_channel();
    b.connect_phone(true);
    let outputs = b.ctap(cid, 0x01, &mc_params());
    let id = of_type(&phone_messages(&outputs), "request")[0]["request_id"].clone();

    assert!(reassemble(&b.send(other, cmd::CANCEL, &[])).is_empty(), "other channel ignored");
    let outputs = b.send(cid, cmd::CANCEL, &[]);
    assert_eq!(cbor_status(&reassemble(&outputs)), [(0x2D, vec![])]);
    let cancels = phone_messages(&outputs);
    assert_eq!(of_type(&cancels, "cancel")[0]["request_id"], id);
}

#[test]
fn second_channel_is_busy_while_a_request_is_pending() {
    let mut b = Bench::new();
    let cid = b.open_channel();
    let other = b.open_channel();
    b.connect_phone(true);
    b.ctap(cid, 0x01, &mc_params());
    let messages = reassemble(&b.ctap(other, 0x04, &[]));
    assert_eq!(messages, [Message { cid: other, cmd: cmd::ERROR, data: vec![err::CHANNEL_BUSY] }]);
    // Broadcast INIT still works while busy.
    assert_eq!(reassemble(&b.send(ctaphid::BROADCAST_CID, cmd::INIT, &NONCE))[0].cmd, cmd::INIT);
}

#[test]
fn init_on_owner_channel_aborts_without_answering() {
    let mut b = Bench::new();
    let cid = b.open_channel();
    b.connect_phone(true);
    b.ctap(cid, 0x01, &mc_params());
    let outputs = b.send(cid, cmd::INIT, &NONCE);
    let messages = reassemble(&outputs);
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].cmd, cmd::INIT);
    assert_eq!(of_type(&phone_messages(&outputs), "cancel").len(), 1);
    assert_eq!(cbor_status(&reassemble(&b.ctap(cid, 0x04, &[])))[0].0, 0x00, "channel usable again");
}

#[test]
fn stale_responses_are_discarded() {
    let mut b = Bench::new();
    let cid = b.open_channel();
    b.connect_phone(true);
    b.ctap(cid, 0x01, &mc_params());
    let outputs = b.phone(json!({"type": "response", "request_id": 999, "status": 0x27, "results": [], "v": 1}));
    assert!(cbor_status(&reassemble(&outputs)).is_empty());
}

#[test]
fn phone_loss_during_a_request_times_it_out() {
    let mut b = Bench::new();
    let cid = b.open_channel();
    b.connect_phone(true);
    b.ctap(cid, 0x01, &mc_params());
    let outputs = b.core.phone_disconnected(b.now);
    assert_eq!(cbor_status(&reassemble(&outputs)), [(0x2F, vec![])]);
}

#[test]
fn new_phone_session_replaces_the_old_one() {
    let mut b = Bench::new();
    let cid = b.open_channel();
    b.connect_phone(true);
    b.ctap(cid, 0x01, &mc_params());
    let outputs = b.core.phone_connected(b.now);
    assert_eq!(cbor_status(&reassemble(&outputs)), [(0x2F, vec![])]);
    let outputs = b.ctap(cid, 0x01, &mc_params());
    assert!(of_type(&phone_messages(&outputs), "request").is_empty(), "arming does not survive reconnect");
}

#[test]
fn deadline_cancels_the_phone_request() {
    let mut b = Bench::new();
    let cid = b.open_channel();
    b.connect_phone(true);
    b.ctap(cid, 0x01, &mc_params());
    let mut outputs = Vec::new();
    for _ in 0..13 {
        b.phone(json!({"type": "ping", "v": 1}));
        outputs.extend(b.advance(10_000));
    }
    assert_eq!(cbor_status(&reassemble(&outputs)), [(0x2F, vec![])]);
    assert_eq!(of_type(&phone_messages(&outputs), "cancel").len(), 1);
}

// ---- Phone protocol hygiene

#[test]
fn version_mismatch_and_missing_hello_close_the_session() {
    let mut b = Bench::new();
    b.core.phone_connected(b.now);
    let outputs = b.phone(json!({"type": "hello", "role": "phone", "v": 2}));
    assert_eq!(phone_messages(&outputs)[0]["code"], "version");
    assert!(outputs.contains(&Output::ClosePhone));

    let mut b = Bench::new();
    b.core.phone_connected(b.now);
    let outputs = b.phone(json!({"type": "arm", "ttl_ms": 60_000, "v": 1}));
    assert_eq!(phone_messages(&outputs)[0]["code"], "unexpected");
}

#[test]
fn arm_ttl_bounds_are_enforced() {
    let mut b = Bench::new();
    b.connect_phone(false);
    let outputs = b.phone(json!({"type": "arm", "ttl_ms": 900_001, "v": 1}));
    assert!(outputs.contains(&Output::ClosePhone));
}

#[test]
fn status_and_results_must_agree() {
    let mut b = Bench::new();
    let cid = b.open_channel();
    b.connect_phone(true);
    let outputs = b.ctap(cid, 0x01, &mc_params());
    let id = of_type(&phone_messages(&outputs), "request")[0]["request_id"].clone();
    let outputs = b.phone(json!({"type": "response", "request_id": id, "status": 0, "results": [], "v": 1}));
    assert!(outputs.contains(&Output::ClosePhone));
    assert_eq!(cbor_status(&reassemble(&outputs)), [(0x2F, vec![])]);
}

#[test]
fn liveness_pings_and_silence_limit() {
    let mut b = Bench::new();
    b.connect_phone(false);
    let outputs = b.advance(5_000);
    assert_eq!(of_type(&phone_messages(&outputs), "ping").len(), 1);
    let outputs = b.advance(10_100);
    assert!(outputs.contains(&Output::ClosePhone));
}

#[test]
fn arming_expires() {
    let mut b = Bench::new();
    b.connect_phone(false);
    b.phone(json!({"type": "arm", "ttl_ms": 2_000, "v": 1}));
    b.phone(json!({"type": "ping", "v": 1}));
    let outputs = b.advance(2_100);
    let states = phone_messages(&outputs);
    assert_eq!(of_type(&states, "state")[0]["armed"], false);
}

#[test]
fn logs_never_contain_request_bytes() {
    let mut b = Bench::new();
    let cid = b.open_channel();
    b.connect_phone(true);
    let params = mc_params();
    let encoded = B64.encode(&params);
    let outputs = b.ctap(cid, 0x01, &params);
    for output in outputs {
        if let Output::Log(line) = output {
            assert!(!line.contains(&encoded) && !line.contains("localhost"), "{line}");
        }
    }
}

#[allow(dead_code)]
fn _assert_report_type(_: Report) {}
