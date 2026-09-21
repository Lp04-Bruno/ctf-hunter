#[cfg(test)]
use ctf_hunter_common::is_blocked_comm;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GateStatus {
    Pass,
    Fail,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivacyRisk {
    UnknownInteractiveRedraw,
    ShortLivedProcessResolutionRace,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GateAssessment {
    status: GateStatus,
    unresolved: Vec<PrivacyRisk>,
}

impl GateAssessment {
    #[must_use]
    pub const fn status(&self) -> GateStatus {
        self.status
    }

    #[must_use]
    pub fn unresolved(&self) -> &[PrivacyRisk] {
        &self.unresolved
    }
}

#[must_use]
pub fn assess_privacy_gate() -> GateAssessment {
    GateAssessment {
        status: GateStatus::Fail,
        unresolved: vec![
            PrivacyRisk::UnknownInteractiveRedraw,
            PrivacyRisk::ShortLivedProcessResolutionRace,
        ],
    }
}

#[must_use]
#[cfg(test)]
pub fn known_interactive_processes_are_blocked() -> bool {
    ["zsh", "bash", "ssh", "sudo", "python3", "nvim", "tmux"]
        .into_iter()
        .all(|name| {
            let mut comm = [0; 16];
            let bytes = name.as_bytes();
            comm[..bytes.len()].copy_from_slice(bytes);
            is_blocked_comm(&comm)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fails_when_write_semantics_cannot_exclude_unknown_redraws() {
        let assessment = assess_privacy_gate();

        assert_eq!(assessment.status(), GateStatus::Fail);
        assert!(
            assessment
                .unresolved()
                .contains(&PrivacyRisk::UnknownInteractiveRedraw)
        );
    }

    #[test]
    fn blocks_required_known_interactive_classes() {
        assert!(known_interactive_processes_are_blocked());
    }
}
