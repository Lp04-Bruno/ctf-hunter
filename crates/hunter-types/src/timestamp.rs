use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _, ser::Error as _};
use time::{OffsetDateTime, UtcOffset, format_description::well_known::Rfc3339};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Timestamp(OffsetDateTime);

impl Timestamp {
    #[must_use]
    pub fn now() -> Self {
        Self(OffsetDateTime::now_utc())
    }

    #[must_use]
    pub fn from_datetime(value: OffsetDateTime) -> Self {
        Self(value.to_offset(UtcOffset::UTC))
    }

    #[must_use]
    pub const fn as_datetime(&self) -> OffsetDateTime {
        self.0
    }

    pub fn from_unix_timestamp(timestamp: i64) -> Result<Self, time::error::ComponentRange> {
        OffsetDateTime::from_unix_timestamp(timestamp).map(Self::from_datetime)
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = self.0.format(&Rfc3339).map_err(|_| fmt::Error)?;
        formatter.write_str(&value)
    }
}

impl FromStr for Timestamp {
    type Err = time::error::Parse;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        OffsetDateTime::parse(value, &Rfc3339).map(Self::from_datetime)
    }
}

impl Serialize for Timestamp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let value = self.0.format(&Rfc3339).map_err(S::Error::custom)?;
        serializer.serialize_str(&value)
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_uses_rfc3339_in_utc() {
        let timestamp = "2026-09-20T22:00:01-04:00"
            .parse::<Timestamp>()
            .expect("valid timestamp");

        assert_eq!(timestamp.to_string(), "2026-09-21T02:00:01Z");
        assert_eq!(
            serde_json::to_string(&timestamp).expect("timestamp should serialize"),
            "\"2026-09-21T02:00:01Z\""
        );
    }
}
