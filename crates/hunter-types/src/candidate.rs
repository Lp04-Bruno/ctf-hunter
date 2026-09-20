use std::str;

use serde::{Deserialize, Serialize};

use crate::{CandidateId, CandidatePath, EventId, ValidationError, validation::validate_bytes};

pub const MAX_CANDIDATE_BYTES: usize = 5 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "Vec<u8>", into = "Vec<u8>")]
pub struct CandidateData(Vec<u8>);

impl CandidateData {
    pub fn new(value: impl Into<Vec<u8>>) -> Result<Self, ValidationError> {
        let value = value.into();
        validate_bytes(&value, "candidate data", MAX_CANDIDATE_BYTES)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        str::from_utf8(&self.0).ok()
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl TryFrom<Vec<u8>> for CandidateData {
    type Error = ValidationError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<CandidateData> for Vec<u8> {
    fn from(value: CandidateData) -> Self {
        value.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Candidate {
    id: CandidateId,
    source_event_id: EventId,
    parent_candidate_id: Option<CandidateId>,
    path: CandidatePath,
    data: CandidateData,
    depth: u8,
}

impl Candidate {
    #[must_use]
    pub const fn new(
        id: CandidateId,
        source_event_id: EventId,
        parent_candidate_id: Option<CandidateId>,
        path: CandidatePath,
        data: CandidateData,
        depth: u8,
    ) -> Self {
        Self {
            id,
            source_event_id,
            parent_candidate_id,
            path,
            data,
            depth,
        }
    }

    #[must_use]
    pub const fn id(&self) -> CandidateId {
        self.id
    }

    #[must_use]
    pub const fn source_event_id(&self) -> EventId {
        self.source_event_id
    }

    #[must_use]
    pub const fn parent_candidate_id(&self) -> Option<CandidateId> {
        self.parent_candidate_id
    }

    #[must_use]
    pub const fn path(&self) -> &CandidatePath {
        &self.path
    }

    #[must_use]
    pub const fn data(&self) -> &CandidateData {
        &self.data
    }

    #[must_use]
    pub const fn depth(&self) -> u8 {
        self.depth
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_exposes_text_only_for_valid_utf8() {
        let text = CandidateData::new(b"FLAG{test}".to_vec()).expect("valid data");
        let binary = CandidateData::new(vec![0xff, 0xfe]).expect("valid data");

        assert_eq!(text.as_text(), Some("FLAG{test}"));
        assert_eq!(binary.as_text(), None);
    }

    #[test]
    fn candidate_round_trips_with_parent_and_path() {
        let candidate = Candidate::new(
            CandidateId::generate(),
            EventId::generate(),
            Some(CandidateId::generate()),
            CandidatePath::root()
                .with_property("password")
                .expect("valid path"),
            CandidateData::new(b"RkxBR3t0ZXN0fQ==".to_vec()).expect("valid data"),
            1,
        );

        let encoded = serde_json::to_string(&candidate).expect("candidate should serialize");
        let decoded = serde_json::from_str(&encoded).expect("candidate should deserialize");

        assert_eq!(candidate, decoded);
    }
}
