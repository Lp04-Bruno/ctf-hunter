use std::io::Read;

use base64::{Engine as _, engine::general_purpose};
use bzip2::read::BzDecoder;
use data_encoding::{BASE32, BASE32_NOPAD};
use flate2::read::{GzDecoder, ZlibDecoder};

pub const MIN_DETECTION_SCORE: u8 = 60;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DecoderKind {
    Base64,
    Base64Url,
    Base32,
    Hex,
    Percent,
    Jwt,
    Gzip,
    Zlib,
    Bzip2,
    DecimalAscii,
    Rot13,
    Caesar,
    Utf16Le,
    Utf16Be,
    HtmlEntities,
    UnicodeEscapes,
    Reverse,
}

impl DecoderKind {
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Base64 => "base64",
            Self::Base64Url => "base64url",
            Self::Base32 => "base32",
            Self::Hex => "hex",
            Self::Percent => "percent",
            Self::Jwt => "jwt",
            Self::Gzip => "gzip",
            Self::Zlib => "zlib",
            Self::Bzip2 => "bzip2",
            Self::DecimalAscii => "decimal_ascii",
            Self::Rot13 => "rot13",
            Self::Caesar => "caesar",
            Self::Utf16Le => "utf16le",
            Self::Utf16Be => "utf16be",
            Self::HtmlEntities => "html_entities",
            Self::UnicodeEscapes => "unicode_escapes",
            Self::Reverse => "reverse",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DetectionScore(u8);

impl DetectionScore {
    #[must_use]
    pub const fn new(value: u8) -> Self {
        Self(if value > 100 { 100 } else { value })
    }

    #[must_use]
    pub const fn value(self) -> u8 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Detection {
    kind: DecoderKind,
    score: DetectionScore,
}

impl Detection {
    #[must_use]
    pub const fn kind(self) -> DecoderKind {
        self.kind
    }

    #[must_use]
    pub const fn score(self) -> DetectionScore {
        self.score
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedValue {
    transformation: String,
    data: Vec<u8>,
}

impl DecodedValue {
    #[must_use]
    pub fn transformation(&self) -> &str {
        &self.transformation
    }

    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    InvalidData,
    OutputLimit { max_bytes: usize },
}

#[derive(Clone, Debug, Default)]
pub struct DecoderSet;

impl DecoderSet {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    #[must_use]
    pub fn detect(&self, input: &[u8]) -> Vec<Detection> {
        let mut detections = Vec::new();
        for kind in [
            DecoderKind::Gzip,
            DecoderKind::Zlib,
            DecoderKind::Bzip2,
            DecoderKind::Jwt,
            DecoderKind::Base64Url,
            DecoderKind::Base64,
            DecoderKind::Base32,
            DecoderKind::Hex,
            DecoderKind::Percent,
            DecoderKind::DecimalAscii,
            DecoderKind::Utf16Le,
            DecoderKind::Utf16Be,
            DecoderKind::HtmlEntities,
            DecoderKind::UnicodeEscapes,
            DecoderKind::Rot13,
            DecoderKind::Caesar,
            DecoderKind::Reverse,
        ] {
            if let Some(score) = detect_kind(kind, input)
                && score.value() >= MIN_DETECTION_SCORE
            {
                detections.push(Detection { kind, score });
            }
        }
        detections.sort_by_key(|detection| std::cmp::Reverse(detection.score));
        detections
    }

    pub fn decode(
        &self,
        detection: Detection,
        input: &[u8],
        max_output_bytes: usize,
    ) -> Result<Vec<DecodedValue>, DecodeError> {
        let outputs = decode_kind(detection.kind, input, max_output_bytes)?;
        let mut unique = Vec::<DecodedValue>::with_capacity(outputs.len());
        for output in outputs {
            if output.data != input && !unique.iter().any(|value| value.data == output.data) {
                unique.push(output);
            }
        }
        Ok(unique)
    }

    #[must_use]
    pub fn decode_likely(&self, input: &[u8], max_output_bytes: usize) -> Vec<DecodedValue> {
        let mut output = Vec::new();
        for detection in self.detect(input) {
            if let Ok(values) = self.decode(detection, input, max_output_bytes) {
                for value in values {
                    if !output
                        .iter()
                        .any(|existing: &DecodedValue| existing.data == value.data)
                    {
                        output.push(value);
                    }
                }
            }
        }
        output
    }
}

fn detect_kind(kind: DecoderKind, input: &[u8]) -> Option<DetectionScore> {
    match kind {
        DecoderKind::Gzip => input
            .starts_with(&[0x1f, 0x8b])
            .then(|| DetectionScore::new(100)),
        DecoderKind::Zlib => is_zlib(input).then(|| DetectionScore::new(95)),
        DecoderKind::Bzip2 => input.starts_with(b"BZh").then(|| DetectionScore::new(100)),
        DecoderKind::Utf16Le => detect_utf16(input, true),
        DecoderKind::Utf16Be => detect_utf16(input, false),
        _ => {
            let text = std::str::from_utf8(input).ok()?.trim();
            match kind {
                DecoderKind::Base64 => detect_base64(text, false),
                DecoderKind::Base64Url => detect_base64(text, true),
                DecoderKind::Base32 => detect_base32(text),
                DecoderKind::Hex => detect_hex(text),
                DecoderKind::Percent => text.contains('%').then(|| {
                    decode_percent(text).map_or(DetectionScore::new(0), |_| DetectionScore::new(85))
                }),
                DecoderKind::Jwt => detect_jwt(text),
                DecoderKind::DecimalAscii => detect_decimal_ascii(text),
                DecoderKind::Rot13 => detect_rot13(text),
                DecoderKind::Caesar => detect_caesar(text),
                DecoderKind::HtmlEntities => {
                    contains_html_entity(text).then(|| DetectionScore::new(85))
                }
                DecoderKind::UnicodeEscapes => {
                    contains_unicode_escape(text).then(|| DetectionScore::new(90))
                }
                DecoderKind::Reverse => detect_reverse(text),
                DecoderKind::Gzip
                | DecoderKind::Zlib
                | DecoderKind::Bzip2
                | DecoderKind::Utf16Le
                | DecoderKind::Utf16Be => None,
            }
        }
    }
}

fn decode_kind(
    kind: DecoderKind,
    input: &[u8],
    max_output_bytes: usize,
) -> Result<Vec<DecodedValue>, DecodeError> {
    let text = std::str::from_utf8(input).ok().map(str::trim);
    let values = match kind {
        DecoderKind::Base64 => single(
            kind.id(),
            decode_base64(text.ok_or(DecodeError::InvalidData)?, false)?,
        ),
        DecoderKind::Base64Url => single(
            kind.id(),
            decode_base64(text.ok_or(DecodeError::InvalidData)?, true)?,
        ),
        DecoderKind::Base32 => single(
            kind.id(),
            decode_base32(text.ok_or(DecodeError::InvalidData)?)?,
        ),
        DecoderKind::Hex => single(
            kind.id(),
            decode_hex(text.ok_or(DecodeError::InvalidData)?)?,
        ),
        DecoderKind::Percent => single(
            kind.id(),
            decode_percent(text.ok_or(DecodeError::InvalidData)?)
                .ok_or(DecodeError::InvalidData)?,
        ),
        DecoderKind::Jwt => decode_jwt(text.ok_or(DecodeError::InvalidData)?)?,
        DecoderKind::Gzip => single(
            kind.id(),
            read_limited(GzDecoder::new(input), max_output_bytes)?,
        ),
        DecoderKind::Zlib => single(
            kind.id(),
            read_limited(ZlibDecoder::new(input), max_output_bytes)?,
        ),
        DecoderKind::Bzip2 => single(
            kind.id(),
            read_limited(BzDecoder::new(input), max_output_bytes)?,
        ),
        DecoderKind::DecimalAscii => single(
            kind.id(),
            decode_decimal_ascii(text.ok_or(DecodeError::InvalidData)?)?,
        ),
        DecoderKind::Rot13 => single(
            kind.id(),
            rot13(text.ok_or(DecodeError::InvalidData)?).into_bytes(),
        ),
        DecoderKind::Caesar => decode_caesar(text.ok_or(DecodeError::InvalidData)?),
        DecoderKind::Utf16Le => single(kind.id(), decode_utf16(input, true)?),
        DecoderKind::Utf16Be => single(kind.id(), decode_utf16(input, false)?),
        DecoderKind::HtmlEntities => single(
            kind.id(),
            decode_html_entities(text.ok_or(DecodeError::InvalidData)?)?,
        ),
        DecoderKind::UnicodeEscapes => single(
            kind.id(),
            decode_unicode_escapes(text.ok_or(DecodeError::InvalidData)?)?,
        ),
        DecoderKind::Reverse => single(
            kind.id(),
            text.ok_or(DecodeError::InvalidData)?
                .chars()
                .rev()
                .collect::<String>()
                .into_bytes(),
        ),
    };
    if values
        .iter()
        .any(|value| value.data.len() > max_output_bytes)
    {
        return Err(DecodeError::OutputLimit {
            max_bytes: max_output_bytes,
        });
    }
    Ok(values)
}

fn single(transformation: &str, data: Vec<u8>) -> Vec<DecodedValue> {
    vec![DecodedValue {
        transformation: transformation.to_owned(),
        data,
    }]
}

fn detect_base64(input: &str, url_safe: bool) -> Option<DetectionScore> {
    let decoded = decode_base64(input, url_safe).ok()?;
    let mut score = 50;
    if input.ends_with('=') {
        score += 10;
    }
    if printable_ratio(&decoded) >= 85 || has_known_magic(&decoded) {
        score += 30;
    }
    Some(DetectionScore::new(score))
}

fn decode_base64(input: &str, url_safe: bool) -> Result<Vec<u8>, DecodeError> {
    if input.len() < 8 || input.len() % 4 == 1 || !valid_padding(input, 2) {
        return Err(DecodeError::InvalidData);
    }
    let valid = if url_safe {
        input
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'='))
            && input.bytes().any(|byte| matches!(byte, b'-' | b'_'))
    } else {
        input
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
    };
    if !valid {
        return Err(DecodeError::InvalidData);
    }
    let padded = pad_to_multiple(input, 4);
    let engine = if url_safe {
        &general_purpose::URL_SAFE
    } else {
        &general_purpose::STANDARD
    };
    let decoded = engine
        .decode(padded.as_bytes())
        .map_err(|_| DecodeError::InvalidData)?;
    let canonical = engine.encode(&decoded);
    if canonical.trim_end_matches('=') != input.trim_end_matches('=') {
        return Err(DecodeError::InvalidData);
    }
    Ok(decoded)
}

fn detect_base32(input: &str) -> Option<DetectionScore> {
    let decoded = decode_base32(input).ok()?;
    let score = 50 + u8::from(printable_ratio(&decoded) >= 85 || has_known_magic(&decoded)) * 30;
    Some(DetectionScore::new(score))
}

fn decode_base32(input: &str) -> Result<Vec<u8>, DecodeError> {
    if input.len() < 8 || !valid_padding(input, 6) {
        return Err(DecodeError::InvalidData);
    }
    let uppercase = input.to_ascii_uppercase();
    if !uppercase
        .bytes()
        .all(|byte| matches!(byte, b'A'..=b'Z' | b'2'..=b'7' | b'='))
    {
        return Err(DecodeError::InvalidData);
    }
    let decoded = if uppercase.contains('=') {
        BASE32.decode(uppercase.as_bytes())
    } else {
        BASE32_NOPAD.decode(uppercase.as_bytes())
    }
    .map_err(|_| DecodeError::InvalidData)?;
    let canonical = if uppercase.contains('=') {
        BASE32.encode(&decoded)
    } else {
        BASE32_NOPAD.encode(&decoded)
    };
    if canonical != uppercase {
        return Err(DecodeError::InvalidData);
    }
    Ok(decoded)
}

fn detect_hex(input: &str) -> Option<DetectionScore> {
    let decoded = decode_hex(input).ok()?;
    let score = 55 + u8::from(printable_ratio(&decoded) >= 85 || has_known_magic(&decoded)) * 30;
    Some(DetectionScore::new(score))
}

fn decode_hex(input: &str) -> Result<Vec<u8>, DecodeError> {
    if input.len() < 8
        || !input.len().is_multiple_of(2)
        || !input.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(DecodeError::InvalidData);
    }
    let mut output = Vec::with_capacity(input.len() / 2);
    for pair in input.as_bytes().as_chunks::<2>().0 {
        output.push((hex_value(pair[0])? << 4) | hex_value(pair[1])?);
    }
    let canonical: String = output.iter().map(|byte| format!("{byte:02x}")).collect();
    if canonical != input.to_ascii_lowercase() {
        return Err(DecodeError::InvalidData);
    }
    Ok(output)
}

fn decode_percent(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut position = 0;
    let mut decoded_any = false;
    while position < bytes.len() {
        if bytes[position] == b'%' {
            let high = hex_value(*bytes.get(position + 1)?).ok()?;
            let low = hex_value(*bytes.get(position + 2)?).ok()?;
            output.push((high << 4) | low);
            decoded_any = true;
            position += 3;
        } else {
            output.push(bytes[position]);
            position += 1;
        }
    }
    decoded_any.then_some(output)
}

fn detect_jwt(input: &str) -> Option<DetectionScore> {
    let parts: Vec<_> = input.split('.').collect();
    if parts.len() != 3 || parts[0].is_empty() || parts[1].is_empty() {
        return None;
    }
    let header = decode_base64url_segment(parts[0]).ok()?;
    let payload = decode_base64url_segment(parts[1]).ok()?;
    (serde_json_like(&header) && serde_json_like(&payload)).then(|| DetectionScore::new(100))
}

fn decode_jwt(input: &str) -> Result<Vec<DecodedValue>, DecodeError> {
    let parts: Vec<_> = input.split('.').collect();
    if parts.len() != 3 {
        return Err(DecodeError::InvalidData);
    }
    Ok(vec![
        DecodedValue {
            transformation: "jwt_header".into(),
            data: decode_base64url_segment(parts[0])?,
        },
        DecodedValue {
            transformation: "jwt_payload".into(),
            data: decode_base64url_segment(parts[1])?,
        },
    ])
}

fn decode_base64url_segment(input: &str) -> Result<Vec<u8>, DecodeError> {
    general_purpose::URL_SAFE_NO_PAD
        .decode(input.trim_end_matches('=').as_bytes())
        .map_err(|_| DecodeError::InvalidData)
}

fn detect_decimal_ascii(input: &str) -> Option<DetectionScore> {
    let decoded = decode_decimal_ascii(input).ok()?;
    (printable_ratio(&decoded) >= 90).then(|| DetectionScore::new(85))
}

fn decode_decimal_ascii(input: &str) -> Result<Vec<u8>, DecodeError> {
    let values: Vec<_> = input
        .split(|character: char| character.is_whitespace() || character == ',')
        .filter(|value| !value.is_empty())
        .map(|value| value.parse::<u8>().map_err(|_| DecodeError::InvalidData))
        .collect::<Result<_, _>>()?;
    if values.len() < 4 {
        return Err(DecodeError::InvalidData);
    }
    Ok(values)
}

fn detect_rot13(input: &str) -> Option<DetectionScore> {
    let decoded = rot13(input);
    (input.len() >= 4 && input.is_ascii() && language_rank(&decoded) > language_rank(input) + 50)
        .then(|| DetectionScore::new(85))
}

fn detect_caesar(input: &str) -> Option<DetectionScore> {
    if input.len() < 4
        || !input.is_ascii()
        || !input.bytes().any(|byte| byte.is_ascii_alphabetic())
        || !input.contains(['{', '}'])
    {
        return None;
    }
    let input_rank = language_rank(input);
    (1..=25)
        .map(|shift| language_rank(&caesar(input, shift)))
        .max()
        .filter(|best| *best > input_rank + 50)
        .map(|_| DetectionScore::new(80))
}

fn decode_caesar(input: &str) -> Vec<DecodedValue> {
    let output: Vec<_> = (1..=25)
        .map(|shift| {
            let decoded = caesar(input, shift);
            let rank = language_rank(&decoded);
            (
                rank,
                DecodedValue {
                    transformation: format!("caesar_{shift}"),
                    data: decoded.into_bytes(),
                },
            )
        })
        .collect();
    let best = output
        .iter()
        .map(|(rank, _)| *rank)
        .max()
        .unwrap_or_default();
    output
        .into_iter()
        .filter(|(rank, _)| *rank == best)
        .map(|(_, value)| value)
        .collect()
}

fn rot13(input: &str) -> String {
    caesar(input, 13)
}

fn caesar(input: &str, shift: u8) -> String {
    input
        .bytes()
        .map(|byte| match byte {
            b'a'..=b'z' => b'a' + (byte - b'a' + 26 - shift) % 26,
            b'A'..=b'Z' => b'A' + (byte - b'A' + 26 - shift) % 26,
            _ => byte,
        })
        .map(char::from)
        .collect()
}

fn detect_utf16(input: &[u8], little_endian: bool) -> Option<DetectionScore> {
    if input.len() < 4 || !input.len().is_multiple_of(2) {
        return None;
    }
    let bom = if little_endian {
        [0xff, 0xfe]
    } else {
        [0xfe, 0xff]
    };
    if input.starts_with(&bom) {
        return Some(DetectionScore::new(100));
    }
    let zero_offset = usize::from(little_endian);
    let pairs = input.as_chunks::<2>().0;
    let zeros = pairs.iter().filter(|pair| pair[zero_offset] == 0).count();
    (zeros * 100 / pairs.len() >= 60).then(|| DetectionScore::new(80))
}

fn decode_utf16(input: &[u8], little_endian: bool) -> Result<Vec<u8>, DecodeError> {
    if !input.len().is_multiple_of(2) {
        return Err(DecodeError::InvalidData);
    }
    let mut start = 0;
    if input.starts_with(&[0xff, 0xfe]) || input.starts_with(&[0xfe, 0xff]) {
        start = 2;
    }
    let words: Vec<_> = input[start..]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            if little_endian {
                u16::from_le_bytes(*pair)
            } else {
                u16::from_be_bytes(*pair)
            }
        })
        .collect();
    String::from_utf16(&words)
        .map(String::into_bytes)
        .map_err(|_| DecodeError::InvalidData)
}

fn contains_html_entity(input: &str) -> bool {
    input
        .match_indices('&')
        .any(|(position, _)| input[position..].find(';').is_some_and(|end| end <= 12))
}

fn decode_html_entities(input: &str) -> Result<Vec<u8>, DecodeError> {
    let mut output = String::with_capacity(input.len());
    let mut rest = input;
    let mut decoded_any = false;
    while let Some(position) = rest.find('&') {
        output.push_str(&rest[..position]);
        let entity_start = &rest[position + 1..];
        let Some(end) = entity_start.find(';').filter(|end| *end <= 12) else {
            output.push('&');
            rest = entity_start;
            continue;
        };
        let entity = &entity_start[..end];
        if let Some(character) = decode_entity(entity) {
            output.push(character);
            decoded_any = true;
        } else {
            output.push('&');
            output.push_str(entity);
            output.push(';');
        }
        rest = &entity_start[end + 1..];
    }
    output.push_str(rest);
    decoded_any
        .then(|| output.into_bytes())
        .ok_or(DecodeError::InvalidData)
}

fn decode_entity(entity: &str) -> Option<char> {
    match entity {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        value if value.starts_with("#x") || value.starts_with("#X") => {
            char::from_u32(u32::from_str_radix(&value[2..], 16).ok()?)
        }
        value if value.starts_with('#') => char::from_u32(value[1..].parse().ok()?),
        _ => None,
    }
}

fn contains_unicode_escape(input: &str) -> bool {
    input.as_bytes().windows(6).any(|window| {
        window.starts_with(b"\\u") && window[2..].iter().all(|byte| byte.is_ascii_hexdigit())
    })
}

fn decode_unicode_escapes(input: &str) -> Result<Vec<u8>, DecodeError> {
    let bytes = input.as_bytes();
    let mut output = String::with_capacity(input.len());
    let mut position = 0;
    let mut decoded_any = false;
    while position < bytes.len() {
        if bytes[position..].starts_with(b"\\u") && position + 6 <= bytes.len() {
            let first = parse_hex_u16(&bytes[position + 2..position + 6])?;
            let (character, consumed) = if (0xd800..=0xdbff).contains(&first)
                && position + 12 <= bytes.len()
                && bytes[position + 6..].starts_with(b"\\u")
            {
                let second = parse_hex_u16(&bytes[position + 8..position + 12])?;
                if !(0xdc00..=0xdfff).contains(&second) {
                    return Err(DecodeError::InvalidData);
                }
                let codepoint = 0x1_0000
                    + ((u32::from(first) - 0xd800) << 10)
                    + (u32::from(second)
                        .checked_sub(0xdc00)
                        .ok_or(DecodeError::InvalidData)?);
                (
                    char::from_u32(codepoint).ok_or(DecodeError::InvalidData)?,
                    12,
                )
            } else {
                (
                    char::from_u32(u32::from(first)).ok_or(DecodeError::InvalidData)?,
                    6,
                )
            };
            output.push(character);
            decoded_any = true;
            position += consumed;
        } else {
            let character = input[position..]
                .chars()
                .next()
                .ok_or(DecodeError::InvalidData)?;
            output.push(character);
            position += character.len_utf8();
        }
    }
    decoded_any
        .then(|| output.into_bytes())
        .ok_or(DecodeError::InvalidData)
}

fn detect_reverse(input: &str) -> Option<DetectionScore> {
    let reversed: String = input.chars().rev().collect();
    (input.len() >= 4 && input != reversed && language_rank(&reversed) > language_rank(input) + 50)
        .then(|| DetectionScore::new(80))
}

fn language_rank(input: &str) -> i32 {
    let lowercase = input.to_ascii_lowercase();
    let mut score = 0;
    for marker in ["flag", "ctf", "pico", "htb", "dbh", "challenge"] {
        if lowercase.contains(marker) {
            score += 100;
        }
    }
    for marker in ["the", "ing", "ion", "er", "an"] {
        if lowercase.contains(marker) {
            score += 5;
        }
    }
    score
}

fn read_limited(reader: impl Read, max_bytes: usize) -> Result<Vec<u8>, DecodeError> {
    let limit = u64::try_from(max_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut output = Vec::new();
    reader
        .take(limit)
        .read_to_end(&mut output)
        .map_err(|_| DecodeError::InvalidData)?;
    if output.len() > max_bytes {
        return Err(DecodeError::OutputLimit { max_bytes });
    }
    Ok(output)
}

fn is_zlib(input: &[u8]) -> bool {
    input.len() >= 2
        && input[0] == 0x78
        && u16::from_be_bytes([input[0], input[1]]).is_multiple_of(31)
}

fn has_known_magic(value: &[u8]) -> bool {
    value.starts_with(&[0x1f, 0x8b]) || value.starts_with(b"BZh") || is_zlib(value)
}

#[must_use]
pub fn printable_ratio(value: &[u8]) -> u8 {
    let Ok(text) = std::str::from_utf8(value) else {
        return 0;
    };
    let total = text.chars().count();
    if total == 0 {
        return 0;
    }
    let printable = text
        .chars()
        .filter(|character| !character.is_control() || matches!(character, '\n' | '\r' | '\t'))
        .count();
    u8::try_from(printable * 100 / total).unwrap_or(100)
}

fn serde_json_like(value: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(value).is_ok()
}

fn valid_padding(input: &str, max: usize) -> bool {
    let Some(first) = input.find('=') else {
        return true;
    };
    input[first..].bytes().all(|byte| byte == b'=') && input.len() - first <= max
}

fn pad_to_multiple(input: &str, multiple: usize) -> String {
    let missing = (multiple - input.len() % multiple) % multiple;
    let mut output = String::with_capacity(input.len() + missing);
    output.push_str(input);
    output.extend(std::iter::repeat_n('=', missing));
    output
}

fn hex_value(byte: u8) -> Result<u8, DecodeError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(DecodeError::InvalidData),
    }
}

fn parse_hex_u16(value: &[u8]) -> Result<u16, DecodeError> {
    let text = std::str::from_utf8(value).map_err(|_| DecodeError::InvalidData)?;
    u16::from_str_radix(text, 16).map_err(|_| DecodeError::InvalidData)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use bzip2::{Compression as BzipCompression, write::BzEncoder};
    use flate2::{
        Compression,
        write::{GzEncoder, ZlibEncoder},
    };

    use super::*;

    fn decoded(input: &[u8], transformation: &str) -> Option<Vec<u8>> {
        DecoderSet::new()
            .decode_likely(input, 1024 * 1024)
            .into_iter()
            .find(|value| value.transformation() == transformation)
            .map(|value| value.data)
    }

    #[test]
    fn detection_is_separate_sorted_and_canonical() {
        let detections = DecoderSet::new().detect(b"RkxBR3t0ZXN0fQ==");
        assert_eq!(detections[0].kind(), DecoderKind::Base64);
        assert!(detections[0].score().value() >= 90);
        assert!(DecoderSet::new().detect(b"RkxBR3t0ZXN0fQ==junk").is_empty());
    }

    #[test]
    fn decodes_text_encodings_and_transforms() {
        let cases: &[(&[u8], &str, &[u8])] = &[
            (b"RkxBR3t0ZXN0fQ==", "base64", b"FLAG{test}"),
            (b"IZGECR33ORSXG5D5", "base32", b"FLAG{test}"),
            (b"464c41477b746573747d", "hex", b"FLAG{test}"),
            (b"FLAG%7Btest%7D", "percent", b"FLAG{test}"),
            (
                b"70 76 65 71 123 116 101 115 116 125",
                "decimal_ascii",
                b"FLAG{test}",
            ),
            (b"SYNT{grfg}", "rot13", b"FLAG{test}"),
            (b"IODJ{whvw}", "caesar_3", b"FLAG{test}"),
            (b"FLAG&#123;test&#125;", "html_entities", b"FLAG{test}"),
            (
                b"FLAG&#123;test&#125;&unknown;",
                "html_entities",
                b"FLAG{test}&unknown;",
            ),
            (
                b"\\u0046\\u004c\\u0041\\u0047\\u007btest\\u007d",
                "unicode_escapes",
                b"FLAG{test}",
            ),
            (b"}tset{GALF", "reverse", b"FLAG{test}"),
        ];
        for (input, transformation, expected) in cases {
            assert_eq!(
                decoded(input, transformation).as_deref(),
                Some(*expected),
                "{transformation}"
            );
        }
    }

    #[test]
    fn decodes_jwt_header_and_payload_without_validating_signature() {
        let token = b"eyJhbGciOiJub25lIn0.eyJmbGFnIjoiRkxBR3tqd3R9In0.signature";
        assert_eq!(
            decoded(token, "jwt_header"),
            Some(br#"{"alg":"none"}"#.to_vec())
        );
        assert_eq!(
            decoded(token, "jwt_payload"),
            Some(br#"{"flag":"FLAG{jwt}"}"#.to_vec())
        );
    }

    #[test]
    fn decodes_utf16_in_both_byte_orders() {
        let text: Vec<u16> = "FLAG{utf16}".encode_utf16().collect();
        let little: Vec<_> = [
            vec![0xff, 0xfe],
            text.iter().flat_map(|word| word.to_le_bytes()).collect(),
        ]
        .concat();
        let big: Vec<_> = [
            vec![0xfe, 0xff],
            text.iter().flat_map(|word| word.to_be_bytes()).collect(),
        ]
        .concat();
        assert_eq!(decoded(&little, "utf16le"), Some(b"FLAG{utf16}".to_vec()));
        assert_eq!(decoded(&big, "utf16be"), Some(b"FLAG{utf16}".to_vec()));
    }

    #[test]
    fn decodes_compression_and_enforces_expansion_limits() {
        let mut gzip = GzEncoder::new(Vec::new(), Compression::default());
        gzip.write_all(b"FLAG{gzip}").expect("gzip write");
        let gzip = gzip.finish().expect("gzip finish");
        assert_eq!(decoded(&gzip, "gzip"), Some(b"FLAG{gzip}".to_vec()));

        let mut zlib = ZlibEncoder::new(Vec::new(), Compression::default());
        zlib.write_all(b"FLAG{zlib}").expect("zlib write");
        let zlib = zlib.finish().expect("zlib finish");
        assert_eq!(decoded(&zlib, "zlib"), Some(b"FLAG{zlib}".to_vec()));

        let mut bzip = BzEncoder::new(Vec::new(), BzipCompression::default());
        bzip.write_all(b"FLAG{bzip2}").expect("bzip2 write");
        let bzip = bzip.finish().expect("bzip2 finish");
        assert_eq!(decoded(&bzip, "bzip2"), Some(b"FLAG{bzip2}".to_vec()));

        let detection = DecoderSet::new().detect(&gzip)[0];
        assert_eq!(
            DecoderSet::new().decode(detection, &gzip, 4),
            Err(DecodeError::OutputLimit { max_bytes: 4 })
        );
    }

    #[test]
    fn rejects_false_positive_and_malformed_tokens() {
        for input in [
            b"administrator".as_slice(),
            b"configuration",
            b"deadbeef",
            b"550e8400-e29b-41d4-a716-446655440000",
            b"abc=def=",
            b"not.jwt",
            b"one.two.three",
        ] {
            assert!(DecoderSet::new().detect(input).is_empty(), "{:?}", input);
        }
    }

    #[test]
    fn malformed_text_transformations_fail_safely() {
        let decoder = DecoderSet::new();
        for input in [b"\\uD800".as_slice(), b"FLAG&#xZZ;test"] {
            let detection = decoder.detect(input)[0];
            assert_eq!(
                decoder.decode(detection, input, 1_024),
                Err(DecodeError::InvalidData)
            );
        }
    }
}
