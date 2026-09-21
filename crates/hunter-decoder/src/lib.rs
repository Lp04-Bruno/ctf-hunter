use base64::{Engine as _, engine::general_purpose};
use data_encoding::{BASE32, BASE32_NOPAD};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedValue {
    transformation: &'static str,
    data: Vec<u8>,
}

impl DecodedValue {
    #[must_use]
    pub const fn transformation(&self) -> &'static str {
        self.transformation
    }

    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

#[derive(Clone, Debug, Default)]
pub struct DecoderSet;

impl DecoderSet {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    #[must_use]
    pub fn decode(&self, input: &[u8]) -> Vec<DecodedValue> {
        let Ok(text) = std::str::from_utf8(input) else {
            return Vec::new();
        };
        let text = text.trim();
        let mut decoded = Vec::with_capacity(4);

        if let Some(value) = decode_base64(text, false) {
            push_unique(&mut decoded, "base64", input, value);
        }
        if let Some(value) = decode_base64(text, true) {
            push_unique(&mut decoded, "base64url", input, value);
        }
        if let Some(value) = decode_base32(text) {
            push_unique(&mut decoded, "base32", input, value);
        }
        if let Some(value) = decode_hex(text) {
            push_unique(&mut decoded, "hex", input, value);
        }
        if let Some(value) = decode_percent(text) {
            push_unique(&mut decoded, "percent", input, value);
        }

        decoded
    }
}

fn decode_base64(input: &str, url_safe: bool) -> Option<Vec<u8>> {
    if input.len() < 8 || input.len() % 4 == 1 {
        return None;
    }
    let alphabet_is_valid = if url_safe {
        input
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'='))
            && input.bytes().any(|byte| matches!(byte, b'-' | b'_'))
    } else {
        input
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
    };
    if !alphabet_is_valid || !valid_padding(input, 2) {
        return None;
    }

    let padded = pad_to_multiple(input, 4);
    let engine = if url_safe {
        &general_purpose::URL_SAFE
    } else {
        &general_purpose::STANDARD
    };
    engine
        .decode(padded.as_bytes())
        .ok()
        .filter(|value| is_useful(value))
}

fn decode_base32(input: &str) -> Option<Vec<u8>> {
    if input.len() < 8 || !valid_padding(input, 6) {
        return None;
    }
    let uppercase = input.to_ascii_uppercase();
    if !uppercase
        .bytes()
        .all(|byte| matches!(byte, b'A'..=b'Z' | b'2'..=b'7' | b'='))
    {
        return None;
    }

    let result = if uppercase.contains('=') {
        BASE32.decode(uppercase.as_bytes()).ok()
    } else {
        BASE32_NOPAD.decode(uppercase.as_bytes()).ok()
    };
    result.filter(|value| is_useful(value))
}

fn decode_hex(input: &str) -> Option<Vec<u8>> {
    if input.len() < 8 || !input.len().is_multiple_of(2) || !input.bytes().all(is_hex) {
        return None;
    }
    let mut output = Vec::with_capacity(input.len() / 2);
    for pair in input.as_bytes().as_chunks::<2>().0 {
        output.push((hex_value(pair[0])? << 4) | hex_value(pair[1])?);
    }
    is_useful(&output).then_some(output)
}

fn decode_percent(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut position = 0;
    let mut decoded_any = false;

    while position < bytes.len() {
        if bytes[position] == b'%' && position + 2 < bytes.len() {
            let high = hex_value(bytes[position + 1])?;
            let low = hex_value(bytes[position + 2])?;
            output.push((high << 4) | low);
            decoded_any = true;
            position += 3;
        } else {
            output.push(bytes[position]);
            position += 1;
        }
    }

    (decoded_any && is_useful(&output)).then_some(output)
}

fn push_unique(
    output: &mut Vec<DecodedValue>,
    transformation: &'static str,
    input: &[u8],
    value: Vec<u8>,
) {
    if value != input && !output.iter().any(|existing| existing.data == value) {
        output.push(DecodedValue {
            transformation,
            data: value,
        });
    }
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

fn is_hex(byte: u8) -> bool {
    byte.is_ascii_hexdigit()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn is_useful(value: &[u8]) -> bool {
    if value.is_empty() {
        return false;
    }
    let Ok(text) = std::str::from_utf8(value) else {
        return false;
    };
    let printable = text
        .chars()
        .filter(|character| !character.is_control() || matches!(character, '\n' | '\r' | '\t'))
        .count();
    let total = text.chars().count();
    total > 0 && printable * 100 / total >= 85
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decoded(input: &str, transformation: &str) -> Option<Vec<u8>> {
        DecoderSet::new()
            .decode(input.as_bytes())
            .into_iter()
            .find(|value| value.transformation() == transformation)
            .map(|value| value.data)
    }

    #[test]
    fn decodes_required_encodings() {
        assert_eq!(
            decoded("RkxBR3t0ZXN0fQ==", "base64"),
            Some(b"FLAG{test}".to_vec())
        );
        assert_eq!(
            decoded("IZGECR33ORSXG5D5", "base32"),
            Some(b"FLAG{test}".to_vec())
        );
        assert_eq!(
            decoded("464c41477b746573747d", "hex"),
            Some(b"FLAG{test}".to_vec())
        );
        assert_eq!(
            decoded("FLAG%7Btest%7D", "percent"),
            Some(b"FLAG{test}".to_vec())
        );
    }

    #[test]
    fn decodes_url_safe_base64_only_with_url_alphabet_evidence() {
        assert_eq!(decoded("Pz8-Pj4_", "base64url"), Some(b"??>>>?".to_vec()));
        assert!(decoded("RkxBR3t0ZXN0fQ==", "base64url").is_none());
    }

    #[test]
    fn rejects_short_words_invalid_padding_and_binary_results() {
        for input in ["abcdef", "deadbeef", "administrator", "abc=def="] {
            assert!(
                DecoderSet::new().decode(input.as_bytes()).is_empty(),
                "{input}"
            );
        }
    }
}
