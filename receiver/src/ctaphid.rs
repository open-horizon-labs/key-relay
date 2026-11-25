//! CTAPHID packet framing (CTAP 2.2, USB HID transport).

pub const REPORT_SIZE: usize = 64;
pub const INIT_DATA: usize = REPORT_SIZE - 7; // 57
pub const CONT_DATA: usize = REPORT_SIZE - 5; // 59
pub const MAX_MESSAGE: usize = INIT_DATA + 128 * CONT_DATA; // 7609
pub const BROADCAST_CID: u32 = 0xFFFF_FFFF;

pub mod cmd {
    pub const PING: u8 = 0x01;
    pub const MSG: u8 = 0x03;
    pub const LOCK: u8 = 0x04;
    pub const INIT: u8 = 0x06;
    pub const WINK: u8 = 0x08;
    pub const CBOR: u8 = 0x10;
    pub const CANCEL: u8 = 0x11;
    pub const KEEPALIVE: u8 = 0x3B;
    pub const ERROR: u8 = 0x3F;
}

pub mod err {
    pub const INVALID_CMD: u8 = 0x01;
    pub const INVALID_LEN: u8 = 0x03;
    pub const INVALID_SEQ: u8 = 0x04;
    pub const MSG_TIMEOUT: u8 = 0x05;
    pub const CHANNEL_BUSY: u8 = 0x06;
    pub const INVALID_CHANNEL: u8 = 0x0B;
}

pub const CAPABILITY_CBOR: u8 = 0x04;
pub const CAPABILITY_NMSG: u8 = 0x08;
pub const KEEPALIVE_UPNEEDED: u8 = 0x02;

pub type Report = [u8; REPORT_SIZE];

/// A received HID output report, classified.
#[derive(Debug, PartialEq, Eq)]
pub enum Packet<'a> {
    Init { cid: u32, cmd: u8, bcnt: usize, data: &'a [u8] },
    Cont { cid: u32, seq: u8, data: &'a [u8] },
}

pub fn parse(report: &Report) -> Packet<'_> {
    let cid = u32::from_be_bytes([report[0], report[1], report[2], report[3]]);
    if report[4] & 0x80 != 0 {
        let bcnt = usize::from(report[5]) << 8 | usize::from(report[6]);
        Packet::Init { cid, cmd: report[4] & 0x7F, bcnt, data: &report[7..] }
    } else {
        Packet::Cont { cid, seq: report[4], data: &report[5..] }
    }
}

/// Splits a response message into input reports, zero-padded.
pub fn frame(cid: u32, command: u8, payload: &[u8]) -> Vec<Report> {
    assert!(payload.len() <= MAX_MESSAGE, "response too large for CTAPHID");
    let mut reports = Vec::new();
    let mut first = [0u8; REPORT_SIZE];
    first[..4].copy_from_slice(&cid.to_be_bytes());
    first[4] = command | 0x80;
    first[5] = (payload.len() >> 8) as u8;
    first[6] = payload.len() as u8;
    let head = payload.len().min(INIT_DATA);
    first[7..7 + head].copy_from_slice(&payload[..head]);
    reports.push(first);
    for (seq, chunk) in payload[head..].chunks(CONT_DATA).enumerate() {
        let mut report = [0u8; REPORT_SIZE];
        report[..4].copy_from_slice(&cid.to_be_bytes());
        report[4] = seq as u8;
        report[5..5 + chunk.len()].copy_from_slice(chunk);
        reports.push(report);
    }
    reports
}

/// Reassembles one request message from init and continuation packets.
#[derive(Debug)]
pub struct Assembly {
    pub cid: u32,
    pub cmd: u8,
    pub expected: usize,
    pub data: Vec<u8>,
    pub next_seq: u8,
}

impl Assembly {
    pub fn start(cid: u32, cmd: u8, bcnt: usize, data: &[u8]) -> Self {
        let take = bcnt.min(data.len());
        Assembly { cid, cmd, expected: bcnt, data: data[..take].to_vec(), next_seq: 0 }
    }

    pub fn complete(&self) -> bool {
        self.data.len() >= self.expected
    }

    /// Adds a continuation packet. Returns false on a sequence error.
    pub fn push(&mut self, seq: u8, data: &[u8]) -> bool {
        if seq != self.next_seq || seq > 0x7F {
            return false;
        }
        self.next_seq += 1;
        let take = (self.expected - self.data.len()).min(data.len());
        self.data.extend_from_slice(&data[..take]);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_and_reassemble_round_trip() {
        let payload: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
        let reports = frame(0x0102_0304, cmd::CBOR, &payload);
        assert_eq!(reports.len(), 1 + (1000 - 57 + 58) / 59);
        let Packet::Init { cid, cmd, bcnt, data } = parse(&reports[0]) else { panic!() };
        assert_eq!((cid, cmd, bcnt), (0x0102_0304, cmd::CBOR, 1000));
        let mut assembly = Assembly::start(cid, cmd, bcnt, data);
        for report in &reports[1..] {
            let Packet::Cont { seq, data, .. } = parse(report) else { panic!() };
            assert!(assembly.push(seq, data));
        }
        assert!(assembly.complete());
        assert_eq!(assembly.data, payload);
    }

    #[test]
    fn maximum_message_is_7609_bytes() {
        assert_eq!(MAX_MESSAGE, 7609);
        assert_eq!(frame(1, cmd::CBOR, &vec![0; MAX_MESSAGE]).len(), 129);
    }

    #[test]
    fn sequence_errors_are_detected() {
        let mut assembly = Assembly::start(1, cmd::CBOR, 100, &[0; 57]);
        assert!(!assembly.push(1, &[0; 59]));
        assert!(assembly.push(0, &[0; 59]));
        assert!(assembly.complete());
    }
}
