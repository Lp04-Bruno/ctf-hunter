use std::collections::HashSet;

use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use thiserror::Error;

use crate::{SessionId, Timestamp, ValidationError, validation::validate_text};

pub const MAX_SESSION_NAME_BYTES: usize = 256;
pub const MAX_FLAG_PATTERN_BYTES: usize = 1_024;
pub const MAX_FLAG_PATTERNS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Inactive,
    Monitoring,
    Paused,
    Finished,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SessionTransitionError {
    #[error("cannot {action} a session in {status:?} state")]
    InvalidState {
        action: &'static str,
        status: SessionStatus,
    },
    #[error("{field} must not be earlier than {reference}")]
    InvalidTimestamp {
        field: &'static str,
        reference: &'static str,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Session {
    id: SessionId,
    name: String,
    created_at: Timestamp,
    started_at: Option<Timestamp>,
    finished_at: Option<Timestamp>,
    status: SessionStatus,
    flag_patterns: Vec<String>,
}

#[derive(Deserialize)]
struct SessionWire {
    id: SessionId,
    name: String,
    created_at: Timestamp,
    started_at: Option<Timestamp>,
    finished_at: Option<Timestamp>,
    status: SessionStatus,
    flag_patterns: Vec<String>,
}

impl Session {
    pub fn new(
        id: SessionId,
        name: impl Into<String>,
        created_at: Timestamp,
    ) -> Result<Self, ValidationError> {
        let session = Self {
            id,
            name: name.into(),
            created_at,
            started_at: None,
            finished_at: None,
            status: SessionStatus::Inactive,
            flag_patterns: Vec::new(),
        };
        session.validate()?;
        Ok(session)
    }

    #[must_use]
    pub const fn id(&self) -> SessionId {
        self.id
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn created_at(&self) -> Timestamp {
        self.created_at
    }

    #[must_use]
    pub const fn started_at(&self) -> Option<Timestamp> {
        self.started_at
    }

    #[must_use]
    pub const fn finished_at(&self) -> Option<Timestamp> {
        self.finished_at
    }

    #[must_use]
    pub const fn status(&self) -> SessionStatus {
        self.status
    }

    #[must_use]
    pub fn flag_patterns(&self) -> &[String] {
        &self.flag_patterns
    }

    pub fn set_name(&mut self, name: impl Into<String>) -> Result<(), ValidationError> {
        let name = name.into();
        validate_text(&name, "session name", MAX_SESSION_NAME_BYTES)?;
        self.name = name;
        Ok(())
    }

    pub fn set_flag_patterns(&mut self, flag_patterns: Vec<String>) -> Result<(), ValidationError> {
        validate_flag_patterns(&flag_patterns)?;
        self.flag_patterns = flag_patterns;
        Ok(())
    }

    pub fn start(&mut self, started_at: Timestamp) -> Result<(), SessionTransitionError> {
        self.require_status("start", SessionStatus::Inactive)?;
        if started_at < self.created_at {
            return Err(SessionTransitionError::InvalidTimestamp {
                field: "started_at",
                reference: "created_at",
            });
        }

        self.started_at = Some(started_at);
        self.status = SessionStatus::Monitoring;
        Ok(())
    }

    pub fn pause(&mut self) -> Result<(), SessionTransitionError> {
        self.require_status("pause", SessionStatus::Monitoring)?;
        self.status = SessionStatus::Paused;
        Ok(())
    }

    pub fn resume(&mut self) -> Result<(), SessionTransitionError> {
        self.require_status("resume", SessionStatus::Paused)?;
        self.status = SessionStatus::Monitoring;
        Ok(())
    }

    pub fn finish(&mut self, finished_at: Timestamp) -> Result<(), SessionTransitionError> {
        if !matches!(
            self.status,
            SessionStatus::Monitoring | SessionStatus::Paused
        ) {
            return Err(SessionTransitionError::InvalidState {
                action: "finish",
                status: self.status,
            });
        }

        let Some(started_at) = self.started_at else {
            return Err(SessionTransitionError::InvalidState {
                action: "finish",
                status: self.status,
            });
        };
        if finished_at < started_at {
            return Err(SessionTransitionError::InvalidTimestamp {
                field: "finished_at",
                reference: "started_at",
            });
        }

        self.finished_at = Some(finished_at);
        self.status = SessionStatus::Finished;
        Ok(())
    }

    fn require_status(
        &self,
        action: &'static str,
        expected: SessionStatus,
    ) -> Result<(), SessionTransitionError> {
        if self.status == expected {
            return Ok(());
        }

        Err(SessionTransitionError::InvalidState {
            action,
            status: self.status,
        })
    }

    fn validate(&self) -> Result<(), ValidationError> {
        validate_text(&self.name, "session name", MAX_SESSION_NAME_BYTES)?;
        validate_flag_patterns(&self.flag_patterns)?;

        if self.started_at.is_some_and(|value| value < self.created_at) {
            return Err(ValidationError::Invalid {
                field: "started_at",
                reason: "must not be earlier than created_at",
            });
        }

        if let (Some(started_at), Some(finished_at)) = (self.started_at, self.finished_at)
            && finished_at < started_at
        {
            return Err(ValidationError::Invalid {
                field: "finished_at",
                reason: "must not be earlier than started_at",
            });
        }

        let timestamps_are_valid = match self.status {
            SessionStatus::Inactive => self.started_at.is_none() && self.finished_at.is_none(),
            SessionStatus::Monitoring | SessionStatus::Paused => {
                self.started_at.is_some() && self.finished_at.is_none()
            }
            SessionStatus::Finished => self.started_at.is_some() && self.finished_at.is_some(),
        };

        if !timestamps_are_valid {
            return Err(ValidationError::Invalid {
                field: "session status",
                reason: "does not match session timestamps",
            });
        }

        Ok(())
    }
}

impl<'de> Deserialize<'de> for Session {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = SessionWire::deserialize(deserializer)?;
        let session = Self {
            id: wire.id,
            name: wire.name,
            created_at: wire.created_at,
            started_at: wire.started_at,
            finished_at: wire.finished_at,
            status: wire.status,
            flag_patterns: wire.flag_patterns,
        };
        session.validate().map_err(D::Error::custom)?;
        Ok(session)
    }
}

fn validate_flag_patterns(flag_patterns: &[String]) -> Result<(), ValidationError> {
    if flag_patterns.len() > MAX_FLAG_PATTERNS {
        return Err(ValidationError::TooMany {
            field: "flag patterns",
            max_items: MAX_FLAG_PATTERNS,
        });
    }

    let mut unique = HashSet::with_capacity(flag_patterns.len());
    for pattern in flag_patterns {
        validate_text(pattern, "flag pattern", MAX_FLAG_PATTERN_BYTES)?;
        if !unique.insert(pattern) {
            return Err(ValidationError::Duplicate {
                field: "flag patterns",
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn timestamp(value: i64) -> Timestamp {
        Timestamp::from_unix_timestamp(value).expect("valid timestamp")
    }

    #[test]
    fn session_supports_the_valid_lifecycle() {
        let mut session =
            Session::new(SessionId::generate(), "picoCTF", timestamp(100)).expect("valid session");

        session.start(timestamp(110)).expect("session should start");
        session.pause().expect("session should pause");
        session.resume().expect("session should resume");
        session
            .finish(timestamp(120))
            .expect("session should finish");

        assert_eq!(session.status(), SessionStatus::Finished);
        assert_eq!(session.started_at(), Some(timestamp(110)));
        assert_eq!(session.finished_at(), Some(timestamp(120)));
    }

    #[test]
    fn session_rejects_invalid_transitions_without_mutating_state() {
        let mut session = Session::new(SessionId::generate(), "Local Lab", timestamp(100))
            .expect("valid session");

        assert_eq!(
            session.pause(),
            Err(SessionTransitionError::InvalidState {
                action: "pause",
                status: SessionStatus::Inactive
            })
        );
        assert_eq!(session.status(), SessionStatus::Inactive);
    }

    #[test]
    fn session_rejects_non_monotonic_timestamps() {
        let mut session = Session::new(SessionId::generate(), "Local Lab", timestamp(100))
            .expect("valid session");

        assert_eq!(
            session.start(timestamp(99)),
            Err(SessionTransitionError::InvalidTimestamp {
                field: "started_at",
                reference: "created_at"
            })
        );
        assert_eq!(session.status(), SessionStatus::Inactive);
    }

    #[test]
    fn session_rejects_duplicate_patterns() {
        let mut session = Session::new(SessionId::generate(), "Local Lab", timestamp(100))
            .expect("valid session");

        assert_eq!(
            session.set_flag_patterns(vec!["FLAG{*}".into(), "FLAG{*}".into()]),
            Err(ValidationError::Duplicate {
                field: "flag patterns"
            })
        );
    }

    #[test]
    fn session_name_can_be_changed_after_validation() {
        let mut session = Session::new(SessionId::generate(), "Local Lab", timestamp(100))
            .expect("valid session");

        session.set_name("Autumn Finals").expect("valid name");
        assert_eq!(session.name(), "Autumn Finals");
        assert!(session.set_name("   ").is_err());
        assert_eq!(session.name(), "Autumn Finals");
    }

    #[test]
    fn session_round_trips_in_a_valid_state() {
        let mut session =
            Session::new(SessionId::generate(), "HTB", timestamp(100)).expect("valid session");
        session
            .set_flag_patterns(vec!["HTB{*}".into()])
            .expect("valid patterns");
        session.start(timestamp(110)).expect("session should start");

        let encoded = serde_json::to_string(&session).expect("session should serialize");
        let decoded = serde_json::from_str(&encoded).expect("session should deserialize");

        assert_eq!(session, decoded);
    }

    #[test]
    fn deserialization_rejects_inconsistent_status_and_timestamps() {
        let value = serde_json::json!({
            "id": SessionId::generate(),
            "name": "Invalid",
            "created_at": timestamp(100),
            "started_at": null,
            "finished_at": null,
            "status": "monitoring",
            "flag_patterns": []
        });

        let error =
            serde_json::from_value::<Session>(value).expect_err("inconsistent session should fail");
        assert!(
            error
                .to_string()
                .contains("does not match session timestamps")
        );
    }
}
