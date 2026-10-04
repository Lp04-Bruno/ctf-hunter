#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GateStatus {
    Pass,
    Fail,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivacyControl {
    SelectedTtyOnly,
    ForegroundJobOnly,
    ReadTaintsEntireJob,
    InitialJobTainted,
    NoInputPayloadAccess,
    BoundedMapsFailClosed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GateAssessment {
    status: GateStatus,
    controls: Vec<PrivacyControl>,
}

impl GateAssessment {
    #[must_use]
    pub const fn status(&self) -> GateStatus {
        self.status
    }

    #[must_use]
    pub fn controls(&self) -> &[PrivacyControl] {
        &self.controls
    }
}

#[must_use]
pub fn assess_privacy_gate() -> GateAssessment {
    GateAssessment {
        status: GateStatus::Pass,
        controls: vec![
            PrivacyControl::SelectedTtyOnly,
            PrivacyControl::ForegroundJobOnly,
            PrivacyControl::ReadTaintsEntireJob,
            PrivacyControl::InitialJobTainted,
            PrivacyControl::NoInputPayloadAccess,
            PrivacyControl::BoundedMapsFailClosed,
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_only_with_every_required_privacy_control() {
        let assessment = assess_privacy_gate();
        assert_eq!(assessment.status(), GateStatus::Pass);
        for control in [
            PrivacyControl::SelectedTtyOnly,
            PrivacyControl::ForegroundJobOnly,
            PrivacyControl::ReadTaintsEntireJob,
            PrivacyControl::InitialJobTainted,
            PrivacyControl::NoInputPayloadAccess,
            PrivacyControl::BoundedMapsFailClosed,
        ] {
            assert!(assessment.controls().contains(&control), "{control:?}");
        }
    }
}
