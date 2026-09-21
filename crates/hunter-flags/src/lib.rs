use std::collections::HashMap;

use hunter_types::{Confidence, FlagValue, MAX_FLAG_PATTERN_BYTES, MAX_FLAG_VALUE_BYTES};
use regex::Regex;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MatchKind {
    Known,
    GenericBrace,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlagMatch {
    value: FlagValue,
    confidence: Confidence,
    kind: MatchKind,
}

impl FlagMatch {
    #[must_use]
    pub const fn value(&self) -> &FlagValue {
        &self.value
    }

    #[must_use]
    pub const fn confidence(&self) -> Confidence {
        self.confidence
    }

    #[must_use]
    pub const fn kind(&self) -> MatchKind {
        self.kind
    }
}

#[derive(Clone, Debug)]
pub enum FlagPattern {
    Simple(String),
    Regex(String),
}

impl FlagPattern {
    #[must_use]
    pub fn simple(value: impl Into<String>) -> Self {
        Self::Simple(value.into())
    }

    #[must_use]
    pub fn regex(value: impl Into<String>) -> Self {
        Self::Regex(value.into())
    }
}

#[derive(Debug, Error)]
pub enum PatternError {
    #[error("flag pattern must not be empty")]
    Empty,
    #[error("flag pattern exceeds the maximum size of {MAX_FLAG_PATTERN_BYTES} bytes")]
    TooLong,
    #[error("invalid flag pattern: {0}")]
    Invalid(#[from] regex::Error),
}

#[derive(Clone, Debug)]
pub struct FlagDetector {
    known: Vec<Regex>,
    generic_brace: Regex,
}

impl FlagDetector {
    pub fn new(patterns: impl IntoIterator<Item = FlagPattern>) -> Result<Self, PatternError> {
        let known = patterns
            .into_iter()
            .map(compile_pattern)
            .collect::<Result<Vec<_>, _>>()?;
        let generic_brace = Regex::new(
            r"(?:^|[^A-Za-z0-9_])(?P<flag>[A-Za-z][A-Za-z0-9_]{1,31}\{[\x20-\x7e&&[^}]]{1,512}\})",
        )?;
        Ok(Self {
            known,
            generic_brace,
        })
    }

    #[must_use]
    pub fn detect(&self, text: &str) -> Vec<FlagMatch> {
        let mut matches = HashMap::<String, FlagMatch>::new();

        for pattern in &self.known {
            for matched in pattern.find_iter(text) {
                insert_match(
                    &mut matches,
                    matched.as_str(),
                    Confidence::VeryHigh,
                    MatchKind::Known,
                );
            }
        }
        for captures in self.generic_brace.captures_iter(text) {
            if let Some(matched) = captures.name("flag") {
                insert_match(
                    &mut matches,
                    matched.as_str(),
                    Confidence::Medium,
                    MatchKind::GenericBrace,
                );
            }
        }

        let mut output: Vec<_> = matches.into_values().collect();
        output.sort_by(|left, right| left.value().as_str().cmp(right.value().as_str()));
        output
    }
}

fn compile_pattern(pattern: FlagPattern) -> Result<Regex, PatternError> {
    let (value, simple) = match pattern {
        FlagPattern::Simple(value) => (value, true),
        FlagPattern::Regex(value) => (value, false),
    };
    if value.trim().is_empty() {
        return Err(PatternError::Empty);
    }
    if value.len() > MAX_FLAG_PATTERN_BYTES {
        return Err(PatternError::TooLong);
    }

    let expression = if simple {
        compile_simple_expression(&value)
    } else {
        value
    };
    Regex::new(&expression).map_err(PatternError::from)
}

fn compile_simple_expression(pattern: &str) -> String {
    let mut output = String::new();
    let mut rest = pattern;
    while !rest.is_empty() {
        if let Some(next) = rest.strip_prefix("...") {
            output.push_str(r"[^}\r\n]{1,512}");
            rest = next;
        } else {
            let Some(character) = rest.chars().next() else {
                break;
            };
            rest = &rest[character.len_utf8()..];
            if character == '*' {
                output.push_str(r"[^}\r\n]{1,512}");
            } else {
                output.push_str(&regex::escape(&character.to_string()));
            }
        }
    }
    output
}

fn insert_match(
    matches: &mut HashMap<String, FlagMatch>,
    value: &str,
    confidence: Confidence,
    kind: MatchKind,
) {
    if value.len() > MAX_FLAG_VALUE_BYTES {
        return;
    }
    let Ok(value) = FlagValue::new(value) else {
        return;
    };
    let key = value.as_str().to_owned();
    let candidate = FlagMatch {
        value,
        confidence,
        kind,
    };
    match matches.get(&key) {
        Some(current) if current.confidence() >= confidence => {}
        _ => {
            matches.insert(key, candidate);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_simple_patterns_have_precedence_over_generic_matches() {
        let detector = FlagDetector::new([FlagPattern::simple("FLAG{*}")]).expect("valid detector");
        let matches = detector.detect("result=FLAG{known_value}");

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].value().as_str(), "FLAG{known_value}");
        assert_eq!(matches[0].confidence(), Confidence::VeryHigh);
        assert_eq!(matches[0].kind(), MatchKind::Known);
    }

    #[test]
    fn supports_ellipsis_and_raw_regex_patterns() {
        let detector = FlagDetector::new([
            FlagPattern::simple("DBH{...}"),
            FlagPattern::regex(r"CTF-[A-Z0-9]{8}"),
        ])
        .expect("valid detector");

        assert_eq!(detector.detect("DBH{alpha}").len(), 1);
        assert_eq!(detector.detect("CTF-A1B2C3D4").len(), 1);
    }

    #[test]
    fn generic_detection_is_bounded_and_conservative() {
        let detector = FlagDetector::new([]).expect("valid detector");
        assert_eq!(
            detector.detect("challenge{possible_flag}")[0].confidence(),
            Confidence::Medium
        );

        for value in [
            "A{x}",
            "prefix{}",
            "prefix{line\nbreak}",
            "this_is_an_ordinary_sentence",
        ] {
            assert!(detector.detect(value).is_empty(), "{value}");
        }
    }

    #[test]
    fn rejects_invalid_patterns() {
        assert!(matches!(
            FlagDetector::new([FlagPattern::simple(" ")]),
            Err(PatternError::Empty)
        ));
        assert!(matches!(
            FlagDetector::new([FlagPattern::regex("[")]),
            Err(PatternError::Invalid(_))
        ));
    }
}
