//! NOXTRACE Rust engine: safely inventory classic PCAP capture metadata offline.
//! No packet injection, replay, or live interface capture is implemented.
use std::{env, fs, process};
const MAX_CAPTURE_BYTES: u64 = 512 * 1024 * 1024;

fn read_u16(bytes: &[u8], offset: usize, little: bool) -> Option<u16> {
    let part = bytes.get(offset..offset + 2)?;
    let array: [u8; 2] = part.try_into().ok()?;
    Some(if little { u16::from_le_bytes(array) } else { u16::from_be_bytes(array) })
}
fn read_u32(bytes: &[u8], offset: usize, little: bool) -> Option<u32> {
    let part = bytes.get(offset..offset + 4)?;
    let array: [u8; 4] = part.try_into().ok()?;
    Some(if little { u32::from_le_bytes(array) } else { u32::from_be_bytes(array) })
}
fn escape_json(input: &str) -> String {
    use std::fmt::Write as _;
    let mut output = String::new();
    for ch in input.chars() {
        match ch {
            '\"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            value if value.is_control() => { let _ = write!(&mut output, "\\u{:04x}", value as u32); }
            value => output.push(value),
        }
    }
    output
}
fn inspect(path: &str) -> Result<String, String> {
    let metadata = fs::metadata(path).map_err(|e| format!("could not read file metadata: {e}"))?;
    if metadata.len() > MAX_CAPTURE_BYTES { return Err("capture exceeds the 512 MiB in-memory safety limit".into()); }
    let bytes = fs::read(path).map_err(|e| format!("could not read file: {e}"))?;
    if bytes.len() < 24 { return Err("file is too short to contain a classic PCAP global header".into()); }
    let magic = &bytes[0..4];
    let (little, precision) = match magic {
        [0xd4, 0xc3, 0xb2, 0xa1] => (true, "microsecond"),
        [0xa1, 0xb2, 0xc3, 0xd4] => (false, "microsecond"),
        [0x4d, 0x3c, 0xb2, 0xa1] => (true, "nanosecond"),
        [0xa1, 0xb2, 0x3c, 0x4d] => (false, "nanosecond"),
        _ => return Err("unsupported file magic; this engine supports classic PCAP, not PCAPNG".into()),
    };
    let major = read_u16(&bytes, 4, little).ok_or("bad PCAP header")?;
    let minor = read_u16(&bytes, 6, little).ok_or("bad PCAP header")?;
    let snaplen = read_u32(&bytes, 16, little).ok_or("bad PCAP header")?;
    let linktype = read_u32(&bytes, 20, little).ok_or("bad PCAP header")?;
    let mut offset = 24usize; let mut packets = 0u64; let mut captured = 0u64; let mut original = 0u64; let mut truncated = false;
    while offset < bytes.len() {
        if bytes.len() - offset < 16 { truncated = true; break; }
        let included = read_u32(&bytes, offset + 8, little).ok_or("bad packet record")? as usize;
        let original_len = read_u32(&bytes, offset + 12, little).ok_or("bad packet record")? as u64;
        offset += 16;
        if included > bytes.len() - offset { truncated = true; break; }
        packets += 1; captured += included as u64; original += original_len; offset += included;
    }
    let path_escaped = escape_json(path);
    Ok(format!("{{\n  \"file\": \"{}\",\n  \"format\": \"classic-pcap\",\n  \"byte_order\": \"{}\",\n  \"timestamp_precision\": \"{}\",\n  \"version\": \"{}.{}\",\n  \"snapshot_length\": {},\n  \"link_type\": {},\n  \"packets_parsed\": {},\n  \"captured_bytes\": {},\n  \"original_packet_bytes\": {},\n  \"truncated_or_partial_record\": {},\n  \"network_activity\": false\n}}", path_escaped, if little {"little-endian"} else {"big-endian"}, precision, major, minor, snaplen, linktype, packets, captured, original, truncated))
}
fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 || args[1] != "pcap" { eprintln!("NOXTRACE Rust engine\nUsage: noxtrace-rs pcap FILE.pcap\nOffline classic-PCAP metadata only; PCAPNG is not supported."); process::exit(2); }
    match inspect(&args[2]) { Ok(output) => println!("{output}"), Err(error) => { eprintln!("NOXTRACE PCAP error: {error}"); process::exit(1); } }
}
