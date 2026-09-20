use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

macro_rules! define_id {
    ($name:ident) => {
        #[derive(
            Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            #[must_use]
            pub fn generate() -> Self {
                Self(Uuid::new_v4())
            }

            #[must_use]
            pub const fn from_uuid(value: Uuid) -> Self {
                Self(value)
            }

            #[must_use]
            pub const fn as_uuid(&self) -> &Uuid {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl From<Uuid> for $name {
            fn from(value: Uuid) -> Self {
                Self(value)
            }
        }

        impl From<$name> for Uuid {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl FromStr for $name {
            type Err = uuid::Error;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(value).map(Self)
            }
        }
    };
}

define_id!(SessionId);
define_id!(EventId);
define_id!(CandidateId);
define_id!(TransformationId);
define_id!(FindingId);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_ids_round_trip_through_text_and_json() {
        let id = SessionId::from_uuid(
            Uuid::parse_str("018f2670-88a0-7d3a-8e8d-5efefc4f6461").expect("valid UUID"),
        );

        assert_eq!(id.to_string().parse::<SessionId>(), Ok(id));
        let encoded = serde_json::to_string(&id).expect("ID should serialize");
        let decoded = serde_json::from_str::<SessionId>(&encoded).expect("ID should deserialize");

        assert_eq!(decoded, id);
    }

    #[test]
    fn different_id_types_do_not_share_conversions() {
        let session_id = SessionId::generate();
        let event_id = EventId::from_uuid(*session_id.as_uuid());

        assert_eq!(session_id.as_uuid(), event_id.as_uuid());
    }
}
