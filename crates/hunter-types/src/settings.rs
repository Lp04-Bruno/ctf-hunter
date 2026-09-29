use serde::{Deserialize, Serialize};

use crate::Confidence;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NotificationSettings {
    pub enabled: bool,
    pub minimum_confidence: Confidence,
}

impl Default for NotificationSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            minimum_confidence: Confidence::High,
        }
    }
}

impl NotificationSettings {
    #[must_use]
    pub const fn accepts(self, confidence: Confidence) -> bool {
        self.enabled && confidence as u8 >= self.minimum_confidence as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_only_accepts_high_confidence_findings() {
        let settings = NotificationSettings::default();
        assert!(!settings.accepts(Confidence::Medium));
        assert!(settings.accepts(Confidence::High));
        assert!(settings.accepts(Confidence::VeryHigh));
    }
}
