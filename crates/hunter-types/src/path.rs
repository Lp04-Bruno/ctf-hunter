use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{ValidationError, validation::validate_text};

const MAX_PATH_KEY_BYTES: usize = 1_024;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PathKey(String);

impl PathKey {
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        validate_text(&value, "path key", MAX_PATH_KEY_BYTES)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for PathKey {
    type Error = ValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<PathKey> for String {
    fn from(value: PathKey) -> Self {
        value.0
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum PathSegment {
    Property(PathKey),
    Index(usize),
}

#[derive(Clone, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CandidatePath(Vec<PathSegment>);

impl CandidatePath {
    #[must_use]
    pub const fn root() -> Self {
        Self(Vec::new())
    }

    #[must_use]
    pub fn segments(&self) -> &[PathSegment] {
        &self.0
    }

    #[must_use]
    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    pub fn push_property(&mut self, value: impl Into<String>) -> Result<(), ValidationError> {
        self.0.push(PathSegment::Property(PathKey::new(value)?));
        Ok(())
    }

    pub fn push_index(&mut self, value: usize) {
        self.0.push(PathSegment::Index(value));
    }

    pub fn with_property(mut self, value: impl Into<String>) -> Result<Self, ValidationError> {
        self.push_property(value)?;
        Ok(self)
    }

    #[must_use]
    pub fn with_index(mut self, value: usize) -> Self {
        self.push_index(value);
        self
    }
}

impl fmt::Display for CandidatePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_root() {
            return formatter.write_str("$");
        }

        for (position, segment) in self.0.iter().enumerate() {
            match segment {
                PathSegment::Property(key) if is_identifier(key.as_str()) => {
                    if position > 0 {
                        formatter.write_str(".")?;
                    }
                    formatter.write_str(key.as_str())?;
                }
                PathSegment::Property(key) => write!(formatter, "[{:?}]", key.as_str())?,
                PathSegment::Index(index) => write!(formatter, "[{index}]")?,
            }
        }

        Ok(())
    }
}

fn is_identifier(value: &str) -> bool {
    let mut characters = value.chars();
    let Some(first) = characters.next() else {
        return false;
    };

    (first == '_' || first.is_ascii_alphabetic())
        && characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_formats_properties_indexes_and_special_keys() {
        let path = CandidatePath::root()
            .with_property("profile")
            .expect("valid property")
            .with_index(2)
            .with_property("flag.value")
            .expect("valid property");

        assert_eq!(path.to_string(), "profile[2][\"flag.value\"]");
    }

    #[test]
    fn root_path_has_an_explicit_display_value() {
        assert_eq!(CandidatePath::root().to_string(), "$");
    }

    #[test]
    fn path_keys_reject_whitespace_only_values() {
        assert_eq!(
            PathKey::new(" \t"),
            Err(ValidationError::Empty { field: "path key" })
        );
    }
}
