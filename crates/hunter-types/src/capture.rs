use serde::{Deserialize, Serialize};

use crate::{
    EventId, SessionId, SourceMetadata, Timestamp, ValidationError, validation::validate_bytes,
};

pub const MAX_EVENT_PAYLOAD_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "Vec<u8>", into = "Vec<u8>")]
pub struct EventPayload(Vec<u8>);

impl EventPayload {
    pub fn new(value: impl Into<Vec<u8>>) -> Result<Self, ValidationError> {
        let value = value.into();
        validate_bytes(&value, "event payload", MAX_EVENT_PAYLOAD_BYTES)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl TryFrom<Vec<u8>> for EventPayload {
    type Error = ValidationError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<EventPayload> for Vec<u8> {
    fn from(value: EventPayload) -> Self {
        value.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CaptureEvent {
    id: EventId,
    session_id: SessionId,
    captured_at: Timestamp,
    source: SourceMetadata,
    payload: EventPayload,
}

impl CaptureEvent {
    #[must_use]
    pub const fn new(
        id: EventId,
        session_id: SessionId,
        captured_at: Timestamp,
        source: SourceMetadata,
        payload: EventPayload,
    ) -> Self {
        Self {
            id,
            session_id,
            captured_at,
            source,
            payload,
        }
    }

    #[must_use]
    pub const fn id(&self) -> EventId {
        self.id
    }

    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    #[must_use]
    pub const fn captured_at(&self) -> Timestamp {
        self.captured_at
    }

    #[must_use]
    pub const fn source(&self) -> &SourceMetadata {
        &self.source
    }

    #[must_use]
    pub const fn payload(&self) -> &EventPayload {
        &self.payload
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_enforces_empty_and_size_limits() {
        assert_eq!(
            EventPayload::new(Vec::new()),
            Err(ValidationError::Empty {
                field: "event payload"
            })
        );
        assert_eq!(
            EventPayload::new(vec![0; MAX_EVENT_PAYLOAD_BYTES + 1]),
            Err(ValidationError::TooLong {
                field: "event payload",
                max_bytes: MAX_EVENT_PAYLOAD_BYTES
            })
        );
    }

    #[test]
    fn binary_capture_event_round_trips() {
        let event = CaptureEvent::new(
            EventId::generate(),
            SessionId::generate(),
            Timestamp::from_unix_timestamp(1_800_000_000).expect("valid timestamp"),
            SourceMetadata::Manual,
            EventPayload::new(vec![0, 159, 146, 150]).expect("valid payload"),
        );

        let encoded = serde_json::to_string(&event).expect("event should serialize");
        let decoded = serde_json::from_str(&encoded).expect("event should deserialize");

        assert_eq!(event, decoded);
    }
}
