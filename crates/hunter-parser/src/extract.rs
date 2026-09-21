use hunter_types::CandidatePath;
use serde_json::Value;
use thiserror::Error;

pub const DEFAULT_MAX_EXTRACTED_VALUES: usize = 4_096;
pub const DEFAULT_MAX_EXTRACTED_VALUE_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExtractionLimits {
    pub max_values: usize,
    pub max_value_bytes: usize,
}

impl Default for ExtractionLimits {
    fn default() -> Self {
        Self {
            max_values: DEFAULT_MAX_EXTRACTED_VALUES,
            max_value_bytes: DEFAULT_MAX_EXTRACTED_VALUE_BYTES,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtractedValue {
    path: CandidatePath,
    data: Vec<u8>,
}

impl ExtractedValue {
    #[must_use]
    pub const fn new(path: CandidatePath, data: Vec<u8>) -> Self {
        Self { path, data }
    }

    #[must_use]
    pub const fn path(&self) -> &CandidatePath {
        &self.path
    }

    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ExtractionError {
    #[error("candidate extraction exceeded the maximum of {max_values} values")]
    TooManyValues { max_values: usize },
    #[error("candidate path is invalid: {0}")]
    InvalidPath(#[from] hunter_types::ValidationError),
}

pub fn extract_candidates(
    input: &str,
    base_path: &CandidatePath,
    limits: ExtractionLimits,
) -> Result<Vec<ExtractedValue>, ExtractionError> {
    if let Ok(value) = serde_json::from_str::<Value>(input) {
        let mut output = Vec::new();
        traverse_json(&value, base_path, limits, &mut output)?;
        return Ok(output);
    }

    extract_plain_text(input, base_path, limits)
}

fn traverse_json(
    value: &Value,
    path: &CandidatePath,
    limits: ExtractionLimits,
    output: &mut Vec<ExtractedValue>,
) -> Result<(), ExtractionError> {
    match value {
        Value::Object(entries) => {
            for (key, value) in entries {
                let key_path = path.clone().with_property(key)?;
                push_value(output, key_path.clone(), key.as_bytes(), limits)?;
                traverse_json(value, &key_path, limits, output)?;
            }
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                let item_path = path.clone().with_index(index);
                traverse_json(value, &item_path, limits, output)?;
            }
        }
        Value::String(value) => push_value(output, path.clone(), value.as_bytes(), limits)?,
        Value::Number(value) => {
            push_value(output, path.clone(), value.to_string().as_bytes(), limits)?;
        }
        Value::Bool(value) => {
            push_value(output, path.clone(), value.to_string().as_bytes(), limits)?;
        }
        Value::Null => {}
    }
    Ok(())
}

fn extract_plain_text(
    input: &str,
    base_path: &CandidatePath,
    limits: ExtractionLimits,
) -> Result<Vec<ExtractedValue>, ExtractionError> {
    let mut output = Vec::new();
    for line in input.lines().map(str::trim).filter(|line| !line.is_empty()) {
        if is_decimal_ascii_sequence(line) {
            push_value(&mut output, base_path.clone(), line.as_bytes(), limits)?;
        }
    }
    for token in input.split(|character: char| character.is_whitespace() || character.is_control())
    {
        let token = token.trim_matches(|character: char| {
            matches!(character, '"' | '\'' | ',' | ';' | '(' | ')' | '[' | ']')
        });
        if token.len() >= 3 {
            push_value(&mut output, base_path.clone(), token.as_bytes(), limits)?;
        }
    }
    Ok(output)
}

fn is_decimal_ascii_sequence(value: &str) -> bool {
    let parts: Vec<_> = value
        .split(|character: char| character.is_whitespace() || character == ',')
        .filter(|part| !part.is_empty())
        .collect();
    parts.len() >= 4
        && parts.iter().all(|part| {
            part.bytes().all(|byte| byte.is_ascii_digit()) && part.parse::<u8>().is_ok()
        })
}

fn push_value(
    output: &mut Vec<ExtractedValue>,
    path: CandidatePath,
    data: &[u8],
    limits: ExtractionLimits,
) -> Result<(), ExtractionError> {
    if data.is_empty() || data.len() > limits.max_value_bytes {
        return Ok(());
    }
    if output.len() == limits.max_values {
        return Err(ExtractionError::TooManyValues {
            max_values: limits.max_values,
        });
    }
    output.push(ExtractedValue::new(path, data.to_vec()));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traverses_json_keys_values_and_arrays_with_exact_paths() {
        let input =
            r#"{"profile":{"about":{"password":"RkxBR3t0ZXN0fQ=="}},"roles":["user","admin"]}"#;
        let values = extract_candidates(input, &CandidatePath::root(), ExtractionLimits::default())
            .expect("valid JSON");

        assert!(values.iter().any(|value| {
            value.path().to_string() == "profile.about.password"
                && value.data() == b"RkxBR3t0ZXN0fQ=="
        }));
        assert!(
            values
                .iter()
                .any(|value| value.path().to_string() == "roles[1]" && value.data() == b"admin")
        );
        assert!(values.iter().any(|value| value.data() == b"password"));
    }

    #[test]
    fn extracts_plain_text_tokens_without_terminal_punctuation() {
        let values = extract_candidates(
            "result: (FLAG{test}), done",
            &CandidatePath::root(),
            ExtractionLimits::default(),
        )
        .expect("valid text");

        assert!(values.iter().any(|value| value.data() == b"FLAG{test}"));
    }

    #[test]
    fn enforces_value_count_and_size_limits() {
        let limits = ExtractionLimits {
            max_values: 1,
            max_value_bytes: 4,
        };
        let error = extract_candidates("one two", &CandidatePath::root(), limits)
            .expect_err("value limit should be enforced");
        assert_eq!(error, ExtractionError::TooManyValues { max_values: 1 });

        let values = extract_candidates("oversized ok!", &CandidatePath::root(), limits)
            .expect("oversized token should be skipped");
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].data(), b"ok!");
    }

    #[test]
    fn preserves_decimal_ascii_sequences_as_one_candidate() {
        let input = "70 76 65 71 123 116 101 115 116 125";
        let values = extract_candidates(input, &CandidatePath::root(), ExtractionLimits::default())
            .expect("valid text");

        assert!(values.iter().any(|value| value.data() == input.as_bytes()));
    }
}
