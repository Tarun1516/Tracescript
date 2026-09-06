//! Runtime engine: reads packet captures and log files, decodes network events, and
//! dispatches them into the interpreter.
//!
//! The runtime is intentionally passive — it only opens offline `.pcap` files and
//! offline log files supplied by the analyst. No live capture, no injection, no
//! traffic generation. All functionality is for forensic analysis of already-captured
//! lab traffic.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use pcap_file::pcap::{PcapReader, PcapWriter};
use pcap_file::PcapError;

use crate::error::{Result, TraceError};

/// Per-frame metadata extracted during decoding. Used by [`crate::filter`] to
/// match BPF-style filter expressions.
#[derive(Debug, Clone, Default)]
pub struct PktInfo {
    /// L4 protocol number (6 = TCP, 17 = UDP, 1 = ICMP, …) when known.
    pub l4_proto: Option<u8>,
    /// TCP/UDP source port, if present.
    pub src_port: Option<u16>,
    /// TCP/UDP destination port, if present.
    pub dst_port: Option<u16>,
    /// IPv4 source address as raw bytes, when known.
    pub src_ip: Option<[u8; 4]>,
    /// IPv4 destination address as raw bytes, when known.
    pub dst_ip: Option<[u8; 4]>,
    /// Total length of the IP packet (header + payload).
    pub length: u32,
}
use crate::interp::value::Value;

/// One decoded packet or log entry ready to be turned into an event.
///
/// The runtime produces these by reading the source, the [`interor::Interpreter`] or
/// [`bytecode::vm::VM`] consumes them through `dispatch_event`.
pub trait EventSink {
    fn dispatch_event(&mut self, name: &str, fields: HashMap<String, Value>) -> Result<()>;
}

impl EventSink for crate::interp::Interpreter {
    fn dispatch_event(&mut self, name: &str, fields: HashMap<String, Value>) -> Result<()> {
        crate::interp::Interpreter::dispatch_event(self, name, fields)
    }
}

impl EventSink for crate::bytecode::vm::VM {
    fn dispatch_event(&mut self, name: &str, fields: HashMap<String, Value>) -> Result<()> {
        crate::bytecode::vm::VM::dispatch_event(self, name, fields)
    }
}

/// Read a `.pcap` file, decode frames, and dispatch events for every DNS query,
/// TCP connection, and HTTP request seen. Returns the total number of events.
pub fn run_pcap<S: EventSink>(path: &Path, sink: &mut S) -> Result<usize> {
    run_pcap_with_filter(path, sink, &None)
}

pub fn run_pcap_with_filter<S: EventSink>(
    path: &Path,
    sink: &mut S,
    filter: &Option<crate::filter::Filter>,
) -> Result<usize> {
    run_pcap_with_filter_and_grep(path, sink, filter, &None)
}

pub fn run_pcap_with_filter_and_grep<S: EventSink>(
    path: &Path,
    sink: &mut S,
    filter: &Option<crate::filter::Filter>,
    grep: &Option<String>,
) -> Result<usize> {
    let f = File::open(path).map_err(|e| TraceError::Io {
        msg: format!("opening {}: {}", path.display(), e),
    })?;
    let mut reader = PcapReader::new(f).map_err(|e| TraceError::Io {
        msg: format!("reading pcap header from {}: {}", path.display(), e),
    })?;

    let mut events = 0usize;
    while let Some(pkt) = reader.next() {
        let pkt = pkt.map_err(|e| TraceError::Io {
            msg: format!("reading packet: {}", e),
        })?;
        let data = pkt.data;
        let ts = pkt.header.ts_sec as i64;
        for ev in decode_frame_with_filter_and_grep(&data, ts, filter, grep) {
            if let Some(needle) = grep {
                if !event_matches_grep(&ev, needle) {
                    continue;
                }
            }
            sink.dispatch_event(&ev.0, ev.1)?;
            events += 1;
        }
    }
    Ok(events)
}

/// Walk a pcap file and write the bytes of every frame that matches the filter
/// to a new pcap file. The header is preserved. Useful for extracting a
/// forensic subset ("just the DNS for this host") for downstream tooling.
///
/// `grep` further narrows the selection to frames that produced at least one
/// decoded event matching the substring (case-insensitive).
pub fn extract_matching_frames(
    input: &Path,
    output: &Path,
    filter: &Option<crate::filter::Filter>,
    grep: &Option<String>,
) -> Result<usize> {
    let f = File::open(input).map_err(|e| TraceError::Io {
        msg: format!("opening {}: {}", input.display(), e),
    })?;
    let mut reader = PcapReader::new(f).map_err(|e| TraceError::Io {
        msg: format!("reading pcap header from {}: {}", input.display(), e),
    })?;
    let mut writer = PcapWriter::new(File::create(output).map_err(|e| TraceError::Io {
        msg: format!("creating {}: {}", output.display(), e),
    })?)
    .map_err(pcap_err_to_trace)?;

    let mut written = 0usize;
    while let Some(pkt) = reader.next() {
        let pkt = pkt.map_err(|e| TraceError::Io {
            msg: format!("reading packet: {}", e),
        })?;
        let ts = pkt.header.ts_sec as i64;
        let events = decode_frame_with_filter_and_grep(&pkt.data, ts, filter, grep);
        if events.is_empty() {
            continue;
        }
        if let Some(needle) = grep {
            if !events.iter().any(|ev| event_matches_grep(ev, needle)) {
                continue;
            }
        }
        writer
            .write(
                pkt.header.ts_sec,
                pkt.header.ts_nsec,
                &pkt.data,
                pkt.header.orig_len,
            )
            .map_err(pcap_err_to_trace)?;
        written += 1;
    }
    Ok(written)
}

fn pcap_err_to_trace(e: PcapError) -> TraceError {
    TraceError::Io {
        msg: format!("pcap: {}", e),
    }
}

fn event_matches_grep(event: &(String, HashMap<String, Value>), needle: &str) -> bool {
    let lc_needle = needle.to_lowercase();
    for v in event.1.values() {
        let s = v.to_string().to_lowercase();
        if s.contains(&lc_needle) {
            return true;
        }
    }
    false
}

/// Decode a single Ethernet frame and return zero or more events. Multiple events
/// can fire for the same frame — e.g. a DNS query over TCP also counts as a TCP
/// connection.
pub fn decode_frame(frame: &[u8], ts_sec: i64) -> Vec<(String, HashMap<String, Value>)> {
    decode_frame_with_filter(frame, ts_sec, &None)
}

/// Like [`decode_frame`], but applies an optional BPF-style filter and only
/// emits events for matching frames. Returns the events together with the
/// per-frame `PktInfo` (for downstream consumers that want raw access to ports
/// and addresses).
pub fn decode_frame_with_filter(
    frame: &[u8],
    ts_sec: i64,
    filter: &Option<crate::filter::Filter>,
) -> Vec<(String, HashMap<String, Value>)> {
    decode_frame_with_filter_and_grep(frame, ts_sec, filter, &None)
}

pub fn decode_frame_with_filter_and_grep(
    frame: &[u8],
    ts_sec: i64,
    filter: &Option<crate::filter::Filter>,
    grep: &Option<String>,
) -> Vec<(String, HashMap<String, Value>)> {
    let mut out = Vec::new();
    let (ip_start, _eth_type_offset) = match frame.get(12) {
        Some(0x08) => match frame.get(13) {
            Some(0x00) => (14usize, 12usize),
            Some(0x06) => return out,
            _ => return out,
        },
        Some(0x81) => match frame.get(17) {
            Some(0x00) => (18usize, 16usize),
            _ => return out,
        },
        _ => return out,
    };
    if frame.len() < ip_start + 20 {
        return out;
    }
    let version_ihl = frame[ip_start];
    if version_ihl >> 4 != 4 {
        return out;
    }
    let ihl = ((version_ihl & 0x0f) as usize) * 4;
    if ihl < 20 || frame.len() < ip_start + ihl {
        return out;
    }
    let protocol = frame[ip_start + 9];
    let src_ip_bytes = {
        let mut b = [0u8; 4];
        b.copy_from_slice(&frame[ip_start + 12..ip_start + 16]);
        b
    };
    let dst_ip_bytes = {
        let mut b = [0u8; 4];
        b.copy_from_slice(&frame[ip_start + 16..ip_start + 20]);
        b
    };
    let src_ip = ip_to_string(&src_ip_bytes);
    let dst_ip = ip_to_string(&dst_ip_bytes);
    let ip_payload = &frame[ip_start + ihl..];

    // Build a PktInfo first so we can apply the filter before emitting events.
    let mut info = PktInfo {
        l4_proto: Some(protocol),
        src_ip: Some(src_ip_bytes),
        dst_ip: Some(dst_ip_bytes),
        length: ip_payload.len() as u32 + ihl as u32,
        ..Default::default()
    };

    if let Some(filt) = filter {
        // Pre-compute L4 ports so the filter can see them. We re-parse the L4
        // header only for matching purposes; the events still go through the
        // full decoder below.
        match protocol {
            6 => {
                if let Some((_, l4)) = decode_tcp(ip_payload) {
                    info.src_port = Some(l4.src_port);
                    info.dst_port = Some(l4.dst_port);
                }
            }
            17 => {
                if let Some((_, l4)) = decode_udp(ip_payload) {
                    info.src_port = Some(l4.src_port);
                    info.dst_port = Some(l4.dst_port);
                }
            }
            _ => {}
        }
        if !filt.matches(&info) {
            return out;
        }
    }

    // packet-level event — fires for every IPv4 frame we recognise.
    let packet_id = events_hash(ts_sec, &src_ip, &dst_ip, ip_payload.len() as i64);
    let packet_ev = || {
        let mut m = HashMap::new();
        m.insert("time".into(), Value::Str(format_ts(ts_sec)));
        m.insert("src_ip".into(), Value::Str(src_ip.clone()));
        m.insert("dst_ip".into(), Value::Str(dst_ip.clone()));
        m.insert("length".into(), Value::Int(ip_payload.len() as i64));
        m.insert("protocol".into(), Value::Str(proto_name(protocol).into()));
        m.insert("packet_id".into(), Value::Int(packet_id));
        m
    };
    out.push(("packet".into(), packet_ev()));

    match protocol {
        6 => {
            // TCP
            if let Some((tcp_payload, l4)) = decode_tcp(ip_payload) {
                let mut m = HashMap::new();
                m.insert("time".into(), Value::Str(format_ts(ts_sec)));
                m.insert("src_ip".into(), Value::Str(src_ip.clone()));
                m.insert("dst_ip".into(), Value::Str(dst_ip.clone()));
                m.insert("src_port".into(), Value::Int(l4.src_port as i64));
                m.insert("dst_port".into(), Value::Int(l4.dst_port as i64));
                m.insert("seq".into(), Value::Int(l4.seq as i64));
                m.insert("ack".into(), Value::Int(l4.ack as i64));
                m.insert("flags".into(), Value::Str(tcp_flags_string(l4.flags)));
                out.push(("tcp_connection".into(), m));

                if l4.dst_port == 53 || l4.src_port == 53 {
                    if let Some(ev) = decode_dns_message(
                    tcp_payload,
                    &src_ip,
                    &dst_ip,
                    ts_sec,
                    packet_id,
                    Some(l4.src_port),
                    Some(l4.dst_port),
                ) {
                        out.push(ev);
                    }
                }
                if l4.dst_port == 80 || l4.dst_port == 8080 {
                    if let Some(ev) = decode_http_request(
                    tcp_payload,
                    &src_ip,
                    &dst_ip,
                    ts_sec,
                    packet_id,
                    Some(l4.src_port),
                    Some(l4.dst_port),
                ) {
                        out.push(ev);
                    }
                }
            }
        }
        17 => {
            // UDP
            if let Some((udp_payload, l4)) = decode_udp(ip_payload) {
                if l4.src_port == 53 || l4.dst_port == 53 {
                    if let Some(ev) = decode_dns_message(
                    udp_payload,
                    &src_ip,
                    &dst_ip,
                    ts_sec,
                    packet_id,
                    Some(l4.src_port),
                    Some(l4.dst_port),
                ) {
                        out.push(ev);
                    }
                }
            }
        }
        _ => {}
    }
    out
}

fn decode_tcp(ip_payload: &[u8]) -> Option<(&[u8], TcpHeader)> {
    if ip_payload.len() < 20 {
        return None;
    }
    let src_port = u16::from_be_bytes([ip_payload[0], ip_payload[1]]);
    let dst_port = u16::from_be_bytes([ip_payload[2], ip_payload[3]]);
    let seq = u32::from_be_bytes([ip_payload[4], ip_payload[5], ip_payload[6], ip_payload[7]]);
    let ack = u32::from_be_bytes([ip_payload[8], ip_payload[9], ip_payload[10], ip_payload[11]]);
    let data_off = ((ip_payload[12] >> 4) as usize) * 4;
    if data_off < 20 || ip_payload.len() < data_off {
        return None;
    }
    let flags = ip_payload[13];
    Some((
        &ip_payload[data_off..],
        TcpHeader {
            src_port,
            dst_port,
            seq,
            ack,
            flags,
        },
    ))
}

fn decode_udp(ip_payload: &[u8]) -> Option<(&[u8], UdpHeader)> {
    if ip_payload.len() < 8 {
        return None;
    }
    let src_port = u16::from_be_bytes([ip_payload[0], ip_payload[1]]);
    let dst_port = u16::from_be_bytes([ip_payload[2], ip_payload[3]]);
    Some((&ip_payload[8..], UdpHeader { src_port, dst_port }))
}

#[derive(Debug, Clone, Copy)]
struct TcpHeader {
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
}

#[derive(Debug, Clone, Copy)]
struct UdpHeader {
    src_port: u16,
    dst_port: u16,
}

fn tcp_flags_string(flags: u8) -> String {
    let mut s = String::new();
    if flags & 0x01 != 0 { s.push('F'); }
    if flags & 0x02 != 0 { s.push('S'); }
    if flags & 0x04 != 0 { s.push('R'); }
    if flags & 0x08 != 0 { s.push('P'); }
    if flags & 0x10 != 0 { s.push('A'); }
    if flags & 0x20 != 0 { s.push('U'); }
    if flags & 0x40 != 0 { s.push('E'); }
    if flags & 0x80 != 0 { s.push('C'); }
    if s.is_empty() { s.push('-'); }
    s
}

fn decode_dns_message(
    payload: &[u8],
    src_ip: &str,
    dst_ip: &str,
    ts_sec: i64,
    packet_id: i64,
    src_port: Option<u16>,
    dst_port: Option<u16>,
) -> Option<(String, HashMap<String, Value>)> {
    if payload.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let qr = (flags >> 15) & 1;
    let is_response = qr == 1;
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    if qdcount == 0 {
        return None;
    }

    let mut offset = 12;
    let mut labels = Vec::new();
    loop {
        if offset >= payload.len() {
            return None;
        }
        let len = payload[offset] as usize;
        if len == 0 {
            offset += 1;
            break;
        }
        if (len & 0xc0) == 0xc0 {
            return None;
        }
        offset += 1;
        if offset + len > payload.len() {
            return None;
        }
        let label = std::str::from_utf8(&payload[offset..offset + len]).ok()?;
        labels.push(label.to_string());
        offset += len;
    }
    if labels.is_empty() {
        return None;
    }
    if offset + 4 > payload.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([payload[offset], payload[offset + 1]]);

    let query = labels.join(".");
    let mut m = HashMap::new();
    m.insert("time".into(), Value::Str(format_ts(ts_sec)));
    m.insert("src_ip".into(), Value::Str(src_ip.to_string()));
    m.insert("dst_ip".into(), Value::Str(dst_ip.to_string()));
    m.insert("query".into(), Value::Str(query));
    m.insert("qtype".into(), Value::Str(qtype_to_string(qtype).to_string()));
    m.insert("packet_id".into(), Value::Int(packet_id));
    m.insert("is_response".into(), Value::Bool(is_response));
    if let Some(sp) = src_port {
        m.insert("src_port".into(), Value::Int(sp as i64));
    }
    if let Some(dp) = dst_port {
        m.insert("dst_port".into(), Value::Int(dp as i64));
    }
    let event = if is_response { "dns_response" } else { "dns_query" };
    Some((event.into(), m))
}

fn decode_http_request(
    payload: &[u8],
    src_ip: &str,
    dst_ip: &str,
    ts_sec: i64,
    packet_id: i64,
    src_port: Option<u16>,
    dst_port: Option<u16>,
) -> Option<(String, HashMap<String, Value>)> {
    // Only ASCII printable plus CR/LF counts as HTTP for the prototype.
    if payload.len() < 14 {
        return None;
    }
    let head = &payload[..payload.len().min(2048)];
    if !head.iter().all(|&b| b == b'\r' || b == b'\n' || b == b'\t' || (0x20..0x7f).contains(&b)) {
        return None;
    }
    let text = match std::str::from_utf8(head) {
        Ok(s) => s,
        Err(_) => return None,
    };
    let mut lines = text.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?;
    let uri = parts.next()?;
    let version = parts.next()?;
    let method = method.to_string();
    let uri = uri.to_string();
    let version = version.to_string();
    if !method.chars().all(|c| c.is_ascii_uppercase()) {
        return None;
    }
    if !version.starts_with("HTTP/") {
        return None;
    }
    // Pull Host and User-Agent headers if present.
    let mut host = String::new();
    let mut user_agent = String::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (k, v) = match line.split_once(':') {
            Some(kv) => kv,
            None => continue,
        };
        let k_lc = k.trim().to_lowercase();
        let v = v.trim().to_string();
        if k_lc == "host" {
            host = v;
        } else if k_lc == "user-agent" {
            user_agent = v;
        }
    }
    let mut m = HashMap::new();
    m.insert("time".into(), Value::Str(format_ts(ts_sec)));
    m.insert("src_ip".into(), Value::Str(src_ip.to_string()));
    m.insert("dst_ip".into(), Value::Str(dst_ip.to_string()));
    m.insert("method".into(), Value::Str(method));
    m.insert("uri".into(), Value::Str(uri));
    m.insert("version".into(), Value::Str(version));
    m.insert("host".into(), Value::Str(host));
    m.insert("user_agent".into(), Value::Str(user_agent));
    if let Some(sp) = src_port {
        m.insert("src_port".into(), Value::Int(sp as i64));
    }
    if let Some(dp) = dst_port {
        m.insert("dst_port".into(), Value::Int(dp as i64));
    }
    m.insert("packet_id".into(), Value::Int(packet_id));
    Some(("http_request".into(), m))
}

fn ip_to_string(b: &[u8]) -> String {
    if b.len() < 4 {
        return "0.0.0.0".into();
    }
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

fn proto_name(p: u8) -> &'static str {
    match p {
        1 => "icmp",
        2 => "igmp",
        6 => "tcp",
        17 => "udp",
        41 => "ipv6",
        47 => "gre",
        50 => "esp",
        51 => "ah",
        89 => "ospf",
        132 => "sctp",
        _ => "other",
    }
}

fn qtype_to_string(q: u16) -> &'static str {
    match q {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        65 => "HTTPS",
        _ => "OTHER",
    }
}

fn format_ts(secs: i64) -> String {
    let days_since_epoch = secs.div_euclid(86_400);
    let secs_in_day = secs.rem_euclid(86_400);
    let hour = secs_in_day / 3600;
    let minute = (secs_in_day % 3600) / 60;
    let second = secs_in_day % 60;
    let (y, m, d) = days_to_ymd(days_since_epoch);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y, m, d, hour, minute, second
    )
}

fn days_to_ymd(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

fn events_hash(ts: i64, src: &str, dst: &str, len: i64) -> i64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    ts.hash(&mut h);
    src.hash(&mut h);
    dst.hash(&mut h);
    len.hash(&mut h);
    h.finish() as i64
}

// ---------------------------------------------------------------------------
// Log file sources: JSONL and CSV. Each line becomes a `log_entry` event whose
// fields are derived from the row's columns.

/// Read a JSONL log file (one JSON object per line). Each row fires a `log_entry`
/// event with the object's key/value pairs as fields.
pub fn run_jsonl<S: EventSink>(path: &Path, sink: &mut S) -> Result<usize> {
    let f = File::open(path).map_err(|e| TraceError::Io {
        msg: format!("opening {}: {}", path.display(), e),
    })?;
    let reader = BufReader::new(f);
    let mut events = 0usize;
    for (i, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| TraceError::Io { msg: e.to_string() })?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(line).map_err(|e| TraceError::Runtime {
            msg: format!("{}:{}: {}", path.display(), i + 1, e),
            pos: None,
        })?;
        let mut fields = HashMap::new();
        if let serde_json::Value::Object(map) = v {
            for (k, val) in map {
                fields.insert(k, json_to_value(val));
            }
        }
        sink.dispatch_event("log_entry", fields)?;
        events += 1;
    }
    Ok(events)
}

/// Read a CSV file with a header row. Each subsequent row fires a `log_entry` event.
pub fn run_csv<S: EventSink>(path: &Path, sink: &mut S) -> Result<usize> {
    let f = File::open(path).map_err(|e| TraceError::Io {
        msg: format!("opening {}: {}", path.display(), e),
    })?;
    let mut rdr = csv::Reader::from_reader(BufReader::new(f));
    let headers: Vec<String> = rdr
        .headers()
        .map(|h| h.iter().map(|s| s.to_string()).collect())
        .unwrap_or_default();
    let mut events = 0usize;
    for result in rdr.records() {
        let record = result.map_err(|e| TraceError::Io { msg: e.to_string() })?;
        let mut fields = HashMap::new();
        for (i, name) in headers.iter().enumerate() {
            if let Some(v) = record.get(i) {
                fields.insert(name.clone(), Value::Str(v.to_string()));
            }
        }
        sink.dispatch_event("log_entry", fields)?;
        events += 1;
    }
    Ok(events)
}

fn json_to_value(v: serde_json::Value) -> Value {
    match v {
        serde_json::Value::Null => Value::Unit,
        serde_json::Value::Bool(b) => Value::Bool(b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Int(i)
            } else if let Some(f) = n.as_f64() {
                Value::Float(f)
            } else {
                Value::Str(n.to_string())
            }
        }
        serde_json::Value::String(s) => Value::Str(s),
        other => Value::Str(other.to_string()),
    }
}

/// Top-level entry point used by the CLI's `run` command. Picks the right source
/// reader based on the file extension and runs the script through the supplied sink.
pub fn run_script<S: EventSink>(
    sink: &mut S,
    source_path: Option<&str>,
    pcap_override: Option<&str>,
) -> Result<()> {
    run_script_with_filter(sink, source_path, pcap_override, &None)
}

pub fn run_script_with_filter<S: EventSink>(
    sink: &mut S,
    source_path: Option<&str>,
    pcap_override: Option<&str>,
    filter: &Option<crate::filter::Filter>,
) -> Result<()> {
    run_script_with_filter_and_grep(sink, source_path, pcap_override, filter, &None)
}

pub fn run_script_with_filter_and_grep<S: EventSink>(
    sink: &mut S,
    source_path: Option<&str>,
    pcap_override: Option<&str>,
    filter: &Option<crate::filter::Filter>,
    grep: &Option<String>,
) -> Result<()> {
    let path = match pcap_override {
        Some(p) => p.to_string(),
        None => match source_path {
            Some(p) => p.to_string(),
            None => {
                return Err(TraceError::Runtime {
                    msg: "no source declared in script and no override given".into(),
                    pos: None,
                });
            }
        },
    };
    let p = Path::new(&path);
    let lower = path.to_lowercase();
    if lower.ends_with(".pcap") || lower.ends_with(".pcapng") {
        run_pcap_with_filter_and_grep(p, sink, filter, grep)?;
    } else if lower.ends_with(".jsonl") || lower.ends_with(".ndjson") {
        run_jsonl(p, sink)?;
    } else if lower.ends_with(".csv") {
        run_csv(p, sink)?;
    } else {
        return Err(TraceError::Runtime {
            msg: format!(
                "unrecognised source extension on '{}' (expected .pcap, .jsonl, or .csv)",
                path
            ),
            pos: None,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_eth_ip_udp_dns(qname: &str) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0; 6]);
        frame.extend_from_slice(&[0; 6]);
        frame.extend_from_slice(&[0x08, 0x00]);
        frame.push(0x45);
        frame.push(0x00);
        let dns = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
        let udp_len: u16 = (8 + dns.len()) as u16;
        let total_len: u16 = (20 + 8 + dns.len()) as u16;
        frame.extend_from_slice(&total_len.to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x00]);
        frame.extend_from_slice(&[0x40, 0x00]);
        frame.push(64);
        frame.push(17);
        frame.extend_from_slice(&[0x00, 0x00]);
        frame.extend_from_slice(&[192, 168, 1, 10]);
        frame.extend_from_slice(&[192, 168, 1, 1]);
        frame.extend_from_slice(&12321u16.to_be_bytes());
        frame.extend_from_slice(&53u16.to_be_bytes());
        frame.extend_from_slice(&udp_len.to_be_bytes());
        frame.extend_from_slice(&[0, 0]);
        frame.extend_from_slice(dns);
        frame
    }

    fn build_eth_ip_tcp_http_get(uri: &str, host: &str) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0; 6]);
        frame.extend_from_slice(&[0; 6]);
        frame.extend_from_slice(&[0x08, 0x00]);
        let payload = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: trace-test\r\n\r\n",
            uri, host
        );
        let payload_b = payload.as_bytes();
        let total_len: u16 = (20 + 20 + payload_b.len()) as u16;
        frame.push(0x45);
        frame.push(0x00);
        frame.extend_from_slice(&total_len.to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x00]);
        frame.extend_from_slice(&[0x40, 0x00]);
        frame.push(64);
        frame.push(6);
        frame.extend_from_slice(&[0x00, 0x00]);
        frame.extend_from_slice(&[192, 168, 1, 10]);
        frame.extend_from_slice(&[10, 0, 0, 1]);
        frame.extend_from_slice(&54321u16.to_be_bytes());
        frame.extend_from_slice(&80u16.to_be_bytes());
        frame.extend_from_slice(&1u32.to_be_bytes());
        frame.extend_from_slice(&1u32.to_be_bytes());
        frame.push(0x50); // data off = 5 words
        frame.push(0x18); // PSH + ACK
        frame.extend_from_slice(&[0xff, 0xff]);
        frame.extend_from_slice(&[0x00, 0x00]);
        frame.extend_from_slice(&[0x00, 0x00]);
        frame.extend_from_slice(payload_b);
        frame
    }

    #[test]
    fn decodes_dns_query_event() {
        let frame = build_eth_ip_udp_dns("example.com");
        let events = decode_frame(&frame, 1_700_000_000);
        let kinds: Vec<&str> = events.iter().map(|(k, _)| k.as_str()).collect();
        assert!(kinds.contains(&"packet"));
        assert!(kinds.contains(&"dns_query"));
        let dns = events.iter().find(|(k, _)| k == "dns_query").unwrap().1.clone();
        assert_eq!(dns.get("query").unwrap().as_str().unwrap(), "example.com");
    }

    #[test]
    fn decodes_http_request_event() {
        let frame = build_eth_ip_tcp_http_get("/index.html", "example.com");
        let events = decode_frame(&frame, 1_700_000_010);
        let kinds: Vec<&str> = events.iter().map(|(k, _)| k.as_str()).collect();
        assert!(kinds.contains(&"http_request"));
        let http = events.iter().find(|(k, _)| k == "http_request").unwrap().1.clone();
        assert_eq!(http.get("method").unwrap().as_str().unwrap(), "GET");
        assert_eq!(http.get("uri").unwrap().as_str().unwrap(), "/index.html");
        assert_eq!(http.get("host").unwrap().as_str().unwrap(), "example.com");
    }

    #[test]
    fn decodes_tcp_connection_event() {
        let frame = build_eth_ip_tcp_http_get("/x", "example.com");
        let events = decode_frame(&frame, 1_700_000_010);
        let kinds: Vec<&str> = events.iter().map(|(k, _)| k.as_str()).collect();
        assert!(kinds.contains(&"tcp_connection"));
    }
}