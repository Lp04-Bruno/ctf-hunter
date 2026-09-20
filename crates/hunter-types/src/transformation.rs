use serde::{Deserialize, Serialize};

use crate::{CandidateId, Timestamp, TransformationId, ValidationError, validation::validate_text};

pub const MAX_TRANSFORMATION_NAME_BYTES: usize = 128;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TransformationName(String);

impl TransformationName {
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        validate_text(&value, "transformation name", MAX_TRANSFORMATION_NAME_BYTES)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for TransformationName {
    type Error = ValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<TransformationName> for String {
    fn from(value: TransformationName) -> Self {
        value.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Transformation {
    id: TransformationId,
    input_candidate_id: CandidateId,
    output_candidate_id: CandidateId,
    name: TransformationName,
    applied_at: Timestamp,
}

impl Transformation {
    #[must_use]
    pub const fn new(
        id: TransformationId,
        input_candidate_id: CandidateId,
        output_candidate_id: CandidateId,
        name: TransformationName,
        applied_at: Timestamp,
    ) -> Self {
        Self {
            id,
            input_candidate_id,
            output_candidate_id,
            name,
            applied_at,
        }
    }

    #[must_use]
    pub const fn id(&self) -> TransformationId {
        self.id
    }

    #[must_use]
    pub const fn input_candidate_id(&self) -> CandidateId {
        self.input_candidate_id
    }

    #[must_use]
    pub const fn output_candidate_id(&self) -> CandidateId {
        self.output_candidate_id
    }

    #[must_use]
    pub const fn name(&self) -> &TransformationName {
        &self.name
    }

    #[must_use]
    pub const fn applied_at(&self) -> Timestamp {
        self.applied_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transformation_names_reject_empty_values_during_deserialization() {
        let error = serde_json::from_str::<TransformationName>("\"  \"")
            .expect_err("empty transformation name should fail");

        assert!(error.to_string().contains("must not be empty"));
    }
}
