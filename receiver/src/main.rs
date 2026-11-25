//! KeyRelay receiver process: HID gadget device on one side, phone TCP session on
//! the other, `core::Core` in between.
//!
//! Usage: keyrelay-receiver <config.json>
//!
//! Bench build: interface B is plain TCP (decision D2 pending). Listen only on a
//! private network such as a tailnet.
//!
//! `hid_device` is normally the gadget device `/dev/hidg0`. For bench tests on a Mac
//! it may be `tcp-listen:<addr>`: a test client then connects and exchanges raw
//! 64-byte reports, standing in for the USB host.

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use keyrelay_receiver::core::{Core, Output};
use keyrelay_receiver::ctaphid::{Report, REPORT_SIZE};
use keyrelay_receiver::keyinfo::KeyInfo;
use serde::Deserialize;
use serde_json::Value as Json;

const MAX_FRAME: usize = 64 * 1024;

#[derive(Deserialize)]
struct Config {
    /// Address the phone connects to, e.g. "100.x.y.z:47100".
    listen: String,
    /// HID gadget device, normally /dev/hidg0.
    hid_device: String,
    /// The paired key's getInfo fields. Without them the receiver does not start.
    key_info: KeyInfo,
}

enum Event {
    Report(Report),
    HidClosed(String),
    PhoneConnected(u64, TcpStream),
    PhoneMessage(u64, Json),
    PhoneClosed(u64),
}

fn log(line: &str) {
    let t = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0);
    eprintln!("[{t:.3}] {line}");
}

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: keyrelay-receiver <config.json>");
        std::process::exit(2);
    });
    let config: Config = serde_json::from_str(&std::fs::read_to_string(&path).unwrap_or_else(|e| {
        eprintln!("cannot read {path}: {e}");
        std::process::exit(2);
    }))
    .unwrap_or_else(|e| {
        eprintln!("invalid config {path}: {e}");
        std::process::exit(2);
    });
    let get_info = config.key_info.get_info_cbor().unwrap_or_else(|e| {
        eprintln!("invalid key_info: {e}");
        std::process::exit(2);
    });

    let hid_out: HidOut = Arc::new(Mutex::new(None));
    let listener = TcpListener::bind(&config.listen).unwrap_or_else(|e| {
        eprintln!("cannot listen on {}: {e}", config.listen);
        std::process::exit(1);
    });
    log(&format!("receiver {} on {}, HID {}", env!("CARGO_PKG_VERSION"), config.listen, config.hid_device));

    let (tx, rx) = mpsc::channel();
    if let Some(addr) = config.hid_device.strip_prefix("tcp-listen:") {
        spawn_tcp_hid(addr, hid_out.clone(), tx.clone());
    } else {
        let hid = OpenOptions::new().read(true).write(true).open(&config.hid_device).unwrap_or_else(|e| {
            eprintln!("cannot open {}: {e} (is the USB gadget configured?)", config.hid_device);
            std::process::exit(1);
        });
        *hid_out.lock().unwrap() = Some(Box::new(hid.try_clone().expect("clone HID handle")));
        spawn_hid_reader(Box::new(hid), tx.clone());
    }
    spawn_listener(listener, tx);

    let mut core = Core::new(get_info);
    let mut phone: Option<(u64, TcpStream)> = None;
    // Connections that have not yet sent a valid hello. Only a hello makes a
    // connection the active phone session, so a stray connection (a port scan,
    // say) cannot displace the real phone.
    let mut candidates: HashMap<u64, TcpStream> = HashMap::new();

    loop {
        let now = Instant::now();
        let outputs = match rx.recv_timeout(Duration::from_millis(20)) {
            Ok(Event::Report(report)) => core.handle_report(&report, now),
            Ok(Event::HidClosed(reason)) => {
                log(&format!("HID device closed: {reason}"));
                std::process::exit(1);
            }
            Ok(Event::PhoneConnected(id, stream)) => {
                candidates.insert(id, stream);
                Vec::new()
            }
            Ok(Event::PhoneMessage(id, message)) if phone.as_ref().is_some_and(|(p, _)| *p == id) => {
                core.phone_message(&message, now)
            }
            Ok(Event::PhoneMessage(id, message)) if candidates.contains_key(&id) => {
                let stream = candidates.remove(&id).expect("checked");
                let is_hello = message.get("type").and_then(Json::as_str) == Some("hello")
                    && message.get("role").and_then(Json::as_str) == Some("phone");
                if is_hello {
                    if let Some((_, old)) = phone.take() {
                        let _ = old.shutdown(Shutdown::Both);
                    }
                    phone = Some((id, stream));
                    let mut outputs = core.phone_connected(now);
                    outputs.extend(core.phone_message(&message, now));
                    outputs
                } else {
                    log(&format!("connection {id} did not start with a phone hello; closed"));
                    let _ = stream.shutdown(Shutdown::Both);
                    Vec::new()
                }
            }
            Ok(Event::PhoneClosed(id)) if phone.as_ref().is_some_and(|(p, _)| *p == id) => {
                phone = None;
                core.phone_disconnected(now)
            }
            Ok(Event::PhoneClosed(id)) => {
                candidates.remove(&id);
                Vec::new()
            }
            Ok(_) => Vec::new(), // events from a replaced connection
            Err(RecvTimeoutError::Timeout) => Vec::new(),
            Err(RecvTimeoutError::Disconnected) => break,
        };
        let mut outputs = outputs;
        outputs.extend(core.tick(Instant::now()));
        for output in outputs {
            match output {
                Output::Hid(report) => {
                    if let Some(out) = hid_out.lock().unwrap().as_mut() {
                        if let Err(e) = out.write_all(&report) {
                            log(&format!("HID write failed: {e}"));
                        }
                    }
                }
                Output::Phone(message) => {
                    let Some((_, stream)) = phone.as_mut() else { continue };
                    if let Err(e) = write_frame(stream, &message) {
                        log(&format!("phone write failed: {e}"));
                        let _ = stream.shutdown(Shutdown::Both);
                    }
                }
                Output::ClosePhone => {
                    if let Some((_, stream)) = phone.take() {
                        let _ = stream.shutdown(Shutdown::Both);
                    }
                }
                Output::Log(line) => log(&line),
            }
        }
    }
}

type HidOut = Arc<Mutex<Option<Box<dyn Write + Send>>>>;

fn spawn_hid_reader(mut hid: Box<dyn Read + Send>, tx: Sender<Event>) {
    thread::spawn(move || loop {
        let mut report = [0u8; REPORT_SIZE];
        match hid.read(&mut report) {
            Ok(n) if n == REPORT_SIZE => {
                if tx.send(Event::Report(report)).is_err() {
                    return;
                }
            }
            Ok(0) => {
                let _ = tx.send(Event::HidClosed("end of file".into()));
                return;
            }
            Ok(n) => log(&format!("ignored a {n}-byte HID report")),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => {
                // ESHUTDOWN while the host is detached: wait and retry.
                log(&format!("HID read error: {e}; retrying"));
                thread::sleep(Duration::from_millis(500));
            }
        }
    });
}

/// Bench stand-in for the USB host: one TCP client at a time sends and receives
/// raw 64-byte reports. A new client replaces the previous one, like a re-plug.
fn spawn_tcp_hid(addr: &str, hid_out: HidOut, tx: Sender<Event>) {
    let listener = TcpListener::bind(addr).unwrap_or_else(|e| {
        eprintln!("cannot listen for the bench HID client on {addr}: {e}");
        std::process::exit(1);
    });
    log(&format!("bench HID: waiting for a test client on {addr}"));
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let _ = stream.set_nodelay(true);
            let Ok(writer) = stream.try_clone() else { continue };
            *hid_out.lock().unwrap() = Some(Box::new(writer));
            log("bench HID: test client attached");
            let mut report = [0u8; REPORT_SIZE];
            while stream.read_exact(&mut report).is_ok() {
                if tx.send(Event::Report(report)).is_err() {
                    return;
                }
            }
            *hid_out.lock().unwrap() = None;
            log("bench HID: test client detached");
        }
    });
}

fn spawn_listener(listener: TcpListener, tx: Sender<Event>) {
    thread::spawn(move || {
        for (id, stream) in listener.incoming().enumerate() {
            let Ok(stream) = stream else { continue };
            let id = id as u64;
            if let Ok(peer) = stream.peer_addr() {
                log(&format!("phone connection {id} from {peer}"));
            }
            let _ = stream.set_nodelay(true);
            // A phone that stops reading must not stall the event loop.
            let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
            let Ok(reader) = stream.try_clone() else { continue };
            if tx.send(Event::PhoneConnected(id, stream)).is_err() {
                return;
            }
            let tx = tx.clone();
            thread::spawn(move || read_phone(id, reader, tx));
        }
    });
}

fn read_phone(id: u64, mut stream: TcpStream, tx: Sender<Event>) {
    loop {
        let mut header = [0u8; 4];
        if stream.read_exact(&mut header).is_err() {
            break;
        }
        let length = u32::from_be_bytes(header) as usize;
        if length > MAX_FRAME {
            log(&format!("phone connection {id}: frame of {length} bytes refused"));
            break;
        }
        let mut body = vec![0u8; length];
        if stream.read_exact(&mut body).is_err() {
            break;
        }
        match serde_json::from_slice::<Json>(&body) {
            Ok(message) if message.is_object() => {
                if tx.send(Event::PhoneMessage(id, message)).is_err() {
                    return;
                }
            }
            _ => {
                log(&format!("phone connection {id}: malformed frame"));
                break;
            }
        }
    }
    let _ = tx.send(Event::PhoneClosed(id));
}

fn write_frame(stream: &mut TcpStream, message: &Json) -> std::io::Result<()> {
    let body = serde_json::to_vec(message)?;
    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(&body);
    stream.write_all(&frame)
}
