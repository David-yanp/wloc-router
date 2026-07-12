use flate2::read::GzDecoder;
use std::io::Read;

use crate::config::Location;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PatchStats {
    pub wifi: u32,
    pub cell: u32,
    pub locations: u32,
    pub skipped: u32,
}

#[derive(Debug, Clone)]
struct Field {
    field_no: u64,
    wire_type: u8,
    value: Vec<u8>,
    raw: Vec<u8>,
}

pub fn patch_response_body(body: &[u8], location: Location) -> anyhow::Result<(Vec<u8>, PatchStats)> {
    let input = if is_gzip(body) {
        let mut decoder = GzDecoder::new(body);
        let mut decoded = Vec::new();
        decoder.read_to_end(&mut decoded)?;
        decoded
    } else {
        body.to_vec()
    };

    patch_wloc(&input, location)
}

fn patch_wloc(body: &[u8], location: Location) -> anyhow::Result<(Vec<u8>, PatchStats)> {
    if body.len() < 10 {
        anyhow::bail!("body too short: {}", body.len());
    }

    let mut stats = PatchStats::default();
    let mut offsets = vec![0usize, 2, 4, 6, 8, 10, 12, 14, 16];
    let scan_limit = std::cmp::min(96, body.len().saturating_sub(10));
    for i in 0..=scan_limit {
        if !offsets.contains(&i) {
            offsets.push(i);
        }
    }

    let mut errors = Vec::new();
    for offset in offsets {
        let before = stats;
        match patch_frame(body, offset, location, &mut stats) {
            Ok(data) => return Ok((data, stats)),
            Err(err) => {
                stats = before;
                if errors.len() < 6 {
                    errors.push(format!("@{offset}:{err}"));
                }
            }
        }
    }

    let before = stats;
    match patch_raw(body, location, &mut stats) {
        Ok(data) => Ok((data, stats)),
        Err(err) => {
            stats = before;
            errors.push(format!("raw:{err}"));
            anyhow::bail!("no patchable wloc payload found; {}", errors.join(" | "));
        }
    }
}

fn patch_frame(
    body: &[u8],
    base: usize,
    location: Location,
    stats: &mut PatchStats,
) -> anyhow::Result<Vec<u8>> {
    if body.len() < base + 10 {
        anyhow::bail!("body too short: {}, base={}", body.len(), base);
    }
    let len = ((body[base + 8] as usize) << 8) | body[base + 9] as usize;
    if len == 0 {
        anyhow::bail!("invalid empty frame length at {base}");
    }
    if base + 10 + len > body.len() {
        anyhow::bail!("invalid frame length {len} at {base} for {}", body.len());
    }

    let before = *stats;
    let payload = &body[base + 10..base + 10 + len];
    let patched = patch_top_level(payload, location, stats)?;
    let changed = stats.locations - before.locations + stats.wifi - before.wifi + stats.cell - before.cell;
    if changed == 0 || patched == payload {
        *stats = before;
        anyhow::bail!("frame parsed but no patchable wloc payload at {base}");
    }
    if patched.len() > u16::MAX as usize {
        anyhow::bail!("patched payload too large: {}", patched.len());
    }

    let mut out = Vec::with_capacity(body.len() - len + patched.len());
    out.extend_from_slice(&body[..base + 8]);
    out.push((patched.len() >> 8) as u8);
    out.push((patched.len() & 0xff) as u8);
    out.extend_from_slice(&patched);
    out.extend_from_slice(&body[base + 10 + len..]);
    Ok(out)
}

fn patch_raw(body: &[u8], location: Location, stats: &mut PatchStats) -> anyhow::Result<Vec<u8>> {
    let scan_limit = std::cmp::min(256, body.len());
    let mut errors = Vec::new();
    for offset in 0..=scan_limit {
        let before = *stats;
        match patch_top_level(&body[offset..], location, stats) {
            Ok(patched) => {
                let changed =
                    stats.locations - before.locations + stats.wifi - before.wifi + stats.cell - before.cell;
                if changed > 0 && patched != body[offset..] {
                    let mut out = Vec::with_capacity(offset + patched.len());
                    out.extend_from_slice(&body[..offset]);
                    out.extend_from_slice(&patched);
                    return Ok(out);
                }
                *stats = before;
            }
            Err(err) => {
                *stats = before;
                if errors.len() < 6 {
                    errors.push(format!("raw@{offset}:{err}"));
                }
            }
        }
    }
    anyhow::bail!("raw protobuf scan failed; {}", errors.join(" | "));
}

fn patch_top_level(data: &[u8], location: Location, stats: &mut PatchStats) -> anyhow::Result<Vec<u8>> {
    let fields = parse_fields(data)?;
    let mut out = Vec::new();
    for field in fields {
        if field.field_no == 2 && field.wire_type == 2 {
            out.extend(encode_field(
                field.field_no,
                field.wire_type,
                &patch_wifi(&field.value, location, stats)?,
            )?);
        } else if field.wire_type == 2 && (field.field_no == 22 || field.field_no == 24) {
            out.extend(encode_field(
                field.field_no,
                field.wire_type,
                &patch_cell(&field.value, location, stats)?,
            )?);
        } else {
            out.extend(field.raw);
        }
    }
    Ok(out)
}

fn patch_wifi(data: &[u8], location: Location, stats: &mut PatchStats) -> anyhow::Result<Vec<u8>> {
    let fields = parse_fields(data)?;
    let has_bssid = fields.iter().any(|f| {
        f.field_no == 1
            && f.wire_type == 2
            && std::str::from_utf8(&f.value)
                .map(|v| is_mac_address(v))
                .unwrap_or(false)
    });
    if !has_bssid {
        return Ok(data.to_vec());
    }

    let mut changed = false;
    let mut out = Vec::new();
    for field in fields {
        if field.field_no == 2 && field.wire_type == 2 {
            match patch_location(&field.value, location, stats) {
                Ok(patched) => {
                    changed |= patched != field.value;
                    out.extend(encode_field(field.field_no, field.wire_type, &patched)?);
                }
                Err(_) => {
                    stats.skipped += 1;
                    out.extend(field.raw);
                }
            }
        } else {
            out.extend(field.raw);
        }
    }
    if changed {
        stats.wifi += 1;
    }
    Ok(out)
}

fn patch_cell(data: &[u8], location: Location, stats: &mut PatchStats) -> anyhow::Result<Vec<u8>> {
    let fields = parse_fields(data)?;
    let mut changed = false;
    let mut out = Vec::new();
    for field in fields {
        if field.field_no == 5 && field.wire_type == 2 {
            match patch_location(&field.value, location, stats) {
                Ok(patched) => {
                    changed |= patched != field.value;
                    out.extend(encode_field(field.field_no, field.wire_type, &patched)?);
                }
                Err(_) => {
                    stats.skipped += 1;
                    out.extend(field.raw);
                }
            }
        } else {
            out.extend(field.raw);
        }
    }
    if changed {
        stats.cell += 1;
    }
    Ok(out)
}

fn patch_location(data: &[u8], location: Location, stats: &mut PatchStats) -> anyhow::Result<Vec<u8>> {
    let fields = parse_fields(data)?;
    let has_lat = fields.iter().any(|f| f.field_no == 1 && f.wire_type == 0);
    let has_lon = fields.iter().any(|f| f.field_no == 2 && f.wire_type == 0);
    if !has_lat || !has_lon {
        return Ok(data.to_vec());
    }

    let mut out = Vec::new();
    for field in fields {
        match (field.field_no, field.wire_type) {
            (1, 0) => out.extend(encode_varint_field(1, (location.latitude * 1e8).round() as i64)),
            (2, 0) => out.extend(encode_varint_field(2, (location.longitude * 1e8).round() as i64)),
            (3, 0) => out.extend(encode_varint_field(3, location.accuracy as i64)),
            _ => out.extend(field.raw),
        }
    }
    stats.locations += 1;
    Ok(out)
}

fn parse_fields(data: &[u8]) -> anyhow::Result<Vec<Field>> {
    let mut fields = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let start = pos;
        let (key, next) = read_varint(data, pos)?;
        pos = next;
        let field_no = key / 8;
        let wire_type = (key & 7) as u8;
        if field_no == 0 {
            anyhow::bail!("invalid protobuf field 0 at {start}");
        }

        let value = match wire_type {
            0 => {
                let value_start = pos;
                let (_, next) = read_varint(data, pos)?;
                pos = next;
                data[value_start..pos].to_vec()
            }
            1 => {
                ensure(data, pos, 8)?;
                let v = data[pos..pos + 8].to_vec();
                pos += 8;
                v
            }
            2 => {
                let (len, next) = read_varint(data, pos)?;
                pos = next;
                let len = usize::try_from(len)?;
                ensure(data, pos, len)?;
                let v = data[pos..pos + len].to_vec();
                pos += len;
                v
            }
            5 => {
                ensure(data, pos, 4)?;
                let v = data[pos..pos + 4].to_vec();
                pos += 4;
                v
            }
            _ => anyhow::bail!("unsupported wire type {wire_type}"),
        };

        fields.push(Field {
            field_no,
            wire_type,
            value,
            raw: data[start..pos].to_vec(),
        });
    }
    Ok(fields)
}

fn read_varint(data: &[u8], mut pos: usize) -> anyhow::Result<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0u32;
    while pos < data.len() {
        let b = data[pos];
        pos += 1;
        if shift < 64 {
            value |= ((b & 0x7f) as u64) << shift;
        }
        if b & 0x80 == 0 {
            return Ok((value, pos));
        }
        shift += 7;
        if shift >= 70 {
            anyhow::bail!("varint too long at {pos}");
        }
    }
    anyhow::bail!("truncated varint")
}

fn encode_field(field_no: u64, wire_type: u8, value: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut out = encode_varint((field_no << 3) | wire_type as u64);
    match wire_type {
        0 | 1 | 5 => out.extend_from_slice(value),
        2 => {
            out.extend(encode_varint(value.len() as u64));
            out.extend_from_slice(value);
        }
        _ => anyhow::bail!("cannot encode wire type {wire_type}"),
    }
    Ok(out)
}

fn encode_varint_field(field_no: u64, value: i64) -> Vec<u8> {
    let mut out = encode_varint(field_no << 3);
    out.extend(encode_signed_varint(value));
    out
}

fn encode_varint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    while value >= 0x80 {
        out.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
    out
}

fn encode_signed_varint(value: i64) -> Vec<u8> {
    encode_varint(value as u64)
}

fn is_gzip(data: &[u8]) -> bool {
    data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b
}

fn is_mac_address(value: &str) -> bool {
    let parts: Vec<&str> = value.split(':').collect();
    parts.len() == 6
        && parts
            .iter()
            .all(|p| (1..=2).contains(&p.len()) && p.chars().all(|c| c.is_ascii_hexdigit()))
}

fn ensure(data: &[u8], pos: usize, len: usize) -> anyhow::Result<()> {
    if pos + len <= data.len() {
        Ok(())
    } else {
        anyhow::bail!("truncated field")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(field_no: u64, wire_type: u8, value: &[u8]) -> Vec<u8> {
        encode_field(field_no, wire_type, value).unwrap()
    }

    #[test]
    fn rewrites_location_message() {
        let mut msg = Vec::new();
        msg.extend(encode_varint_field(1, 1));
        msg.extend(encode_varint_field(2, 2));
        msg.extend(encode_varint_field(3, 5));

        let loc = Location {
            longitude: 113.94114,
            latitude: 22.544577,
            accuracy: 25,
        };
        let mut stats = PatchStats::default();
        let out = patch_location(&msg, loc, &mut stats).unwrap();
        assert_ne!(msg, out);
        assert_eq!(stats.locations, 1);
    }

    #[test]
    fn rewrites_wifi_nested_location() {
        let mut location = Vec::new();
        location.extend(encode_varint_field(1, 1));
        location.extend(encode_varint_field(2, 2));

        let mut wifi = Vec::new();
        wifi.extend(field(1, 2, b"aa:bb:cc:dd:ee:ff"));
        wifi.extend(field(2, 2, &location));

        let loc = Location {
            longitude: -74.0,
            latitude: 40.0,
            accuracy: 30,
        };
        let mut stats = PatchStats::default();
        let out = patch_wifi(&wifi, loc, &mut stats).unwrap();
        assert_ne!(wifi, out);
        assert_eq!(stats.wifi, 1);
        assert_eq!(stats.locations, 1);
    }

    #[test]
    fn non_matching_wifi_is_unchanged() {
        let data = field(1, 2, b"not-a-mac");
        let loc = Location {
            longitude: 1.0,
            latitude: 2.0,
            accuracy: 3,
        };
        let mut stats = PatchStats::default();
        assert_eq!(patch_wifi(&data, loc, &mut stats).unwrap(), data);
        assert_eq!(stats, PatchStats::default());
    }
}
