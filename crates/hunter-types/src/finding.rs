use std::num::NonZeroU64;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    CandidateId, CandidatePath, EventId, FindingId, SessionId, Timestamp, TransformationId,
    ValidationError, validation::validate_text,
};

pub const MAX_FLAG_VALUE_BYTES: usize = 4 * 1024;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
    VeryHigh,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct FlagValue(String);

impl FlagValue {
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        validate_text(&value, "flag value", MAX_FLAG_VALUE_BYTES)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for FlagValue {
    type Error = ValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<FlagValue> for String {
    fn from(value: FlagValue) -> Self {
        value.0
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum FindingError {
    #[error("finding occurrence count overflowed")]
    OccurrenceOverflow,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FindingProvenance {
    session_id: SessionId,
    source_event_id: EventId,
    candidate_id: CandidateId,
    path: CandidatePath,
    transformation_ids: Vec<TransformationId>,
}

impl FindingProvenance {
    #[must_use]
    pub const fn new(
        session_id: SessionId,
        source_event_id: EventId,
        candidate_id: CandidateId,
        path: CandidatePath,
        transformation_ids: Vec<TransformationId>,
    ) -> Self {
        Self {
            session_id,
            source_event_id,
            candidate_id,
            path,
            transformation_ids,
        }
    }

    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    #[must_use]
    pub const fn source_event_id(&self) -> EventId {
        self.source_event_id
    }

    #[must_use]
    pub const fn candidate_id(&self) -> CandidateId {
        self.candidate_id
    }

    #[must_use]
    pub const fn path(&self) -> &CandidatePath {
        &self.path
    }

    #[must_use]
    pub fn transformation_ids(&self) -> &[TransformationId] {
        &self.transformation_ids
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlagFinding {
    id: FindingId,
    #[serde(flatten)]
    provenance: FindingProvenance,
    value: FlagValue,
    confidence: Confidence,
    discovered_at: Timestamp,
    occurrences: NonZeroU64,
}

impl FlagFinding {
    #[must_use]
    pub fn new(
        id: FindingId,
        provenance: FindingProvenance,
        value: FlagValue,
        confidence: Confidence,
        discovered_at: Timestamp,
    ) -> Self {
        Self {
            id,
            provenance,
            value,
            confidence,
            discovered_at,
            occurrences: NonZeroU64::MIN,
        }
    }

    #[must_use]
    pub const fn id(&self) -> FindingId {
        self.id
    }

    #[must_use]
    pub const fn provenance(&self) -> &FindingProvenance {
        &self.provenance
    }

    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.provenance.session_id()
    }

    #[must_use]
    pub const fn source_event_id(&self) -> EventId {
        self.provenance.source_event_id()
    }

    #[must_use]
    pub const fn candidate_id(&self) -> CandidateId {
        self.provenance.candidate_id()
    }

    #[must_use]
    pub const fn path(&self) -> &CandidatePath {
        self.provenance.path()
    }

    #[must_use]
    pub fn transformation_ids(&self) -> &[TransformationId] {
        self.provenance.transformation_ids()
    }

    #[must_use]
    pub const fn value(&self) -> &FlagValue {
        &self.value
    }

    #[must_use]
    pub const fn confidence(&self) -> Confidence {
        self.confidence
    }

    #[must_use]
    pub const fn discovered_at(&self) -> Timestamp {
        self.discovered_at
    }

    #[must_use]
    pub const fn occurrences(&self) -> NonZeroU64 {
        self.occurrences
    }

    pub fn record_occurrence(&mut self) -> Result<NonZeroU64, FindingError> {
        let value = self
            .occurrences
            .get()
            .checked_add(1)
            .and_then(NonZeroU64::new)
            .ok_or(FindingError::OccurrenceOverflow)?;
        self.occurrences = value;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finding_starts_with_one_occurrence_and_increments() {
        let mut finding = FlagFinding::new(
            FindingId::generate(),
            FindingProvenance::new(
                SessionId::generate(),
                EventId::generate(),
                CandidateId::generate(),
                CandidatePath::root(),
                Vec::new(),
            ),
            FlagValue::new("FLAG{test}").expect("valid flag"),
            Confidence::VeryHigh,
            Timestamp::from_unix_timestamp(1_800_000_000).expect("valid timestamp"),
        );

        assert_eq!(finding.occurrences().get(), 1);
        assert_eq!(
            finding.record_occurrence().expect("should increment").get(),
            2
        );
    }

    #[test]
    fn finding_round_trips_with_provenance_references() {
        let finding = FlagFinding::new(
            FindingId::generate(),
            FindingProvenance::new(
                SessionId::generate(),
                EventId::generate(),
                CandidateId::generate(),
                CandidatePath::root()
                    .with_property("password")
                    .expect("valid path"),
                vec![TransformationId::generate()],
            ),
            FlagValue::new("DBH{found}").expect("valid flag"),
            Confidence::High,
            Timestamp::from_unix_timestamp(1_800_000_000).expect("valid timestamp"),
        );

        let encoded = serde_json::to_string(&finding).expect("finding should serialize");
        let decoded = serde_json::from_str(&encoded).expect("finding should deserialize");

        assert_eq!(finding, decoded);
    }
}
