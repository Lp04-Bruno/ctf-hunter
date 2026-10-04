use hunter_decoder::printable_ratio;
use hunter_flags::MatchKind;
use hunter_types::{CandidatePath, Confidence};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ScoreSignals {
    pub known_pattern: bool,
    pub generic_brace: bool,
    pub printable_text: bool,
    pub structured_text: bool,
    pub flag_path_hint: bool,
    pub password_path_hint: bool,
    pub transformed: bool,
    pub invalid_text: bool,
    pub mostly_control_bytes: bool,
    pub short_generic_value: bool,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FindingScore(i16);

impl FindingScore {
    #[must_use]
    pub const fn value(self) -> i16 {
        self.0
    }

    #[must_use]
    pub const fn confidence(self) -> Confidence {
        match self.0 {
            100.. => Confidence::VeryHigh,
            70..=99 => Confidence::High,
            40..=69 => Confidence::Medium,
            _ => Confidence::Low,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScoreResult {
    score: FindingScore,
    signals: ScoreSignals,
}

impl ScoreResult {
    #[must_use]
    pub const fn score(self) -> FindingScore {
        self.score
    }

    #[must_use]
    pub const fn signals(self) -> ScoreSignals {
        self.signals
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ScoreContext<'a> {
    pub match_kind: MatchKind,
    pub matched_value: &'a str,
    pub candidate_data: &'a [u8],
    pub path: &'a CandidatePath,
    pub transformation_count: usize,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct FindingScorer;

impl FindingScorer {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    #[must_use]
    pub fn score(&self, context: ScoreContext<'_>) -> ScoreResult {
        let text = std::str::from_utf8(context.candidate_data).ok();
        let path = context.path.to_string().to_ascii_lowercase();
        let signals = ScoreSignals {
            known_pattern: context.match_kind == MatchKind::Known,
            generic_brace: context.match_kind == MatchKind::GenericBrace,
            printable_text: printable_ratio(context.candidate_data) >= 85,
            structured_text: text
                .is_some_and(|value| serde_json::from_str::<serde_json::Value>(value).is_ok()),
            flag_path_hint: path.contains("flag"),
            password_path_hint: path.contains("password"),
            transformed: context.transformation_count > 0,
            invalid_text: text.is_none(),
            mostly_control_bytes: printable_ratio(context.candidate_data) < 30,
            short_generic_value: context.match_kind == MatchKind::GenericBrace
                && context.matched_value.len() < 8,
        };

        let mut points = 0;
        points += i16::from(signals.known_pattern) * 100;
        points += i16::from(signals.generic_brace) * 40;
        points += i16::from(signals.printable_text) * 20;
        points += i16::from(signals.structured_text) * 20;
        points += i16::from(signals.flag_path_hint) * 40;
        points += i16::from(signals.password_path_hint) * 10;
        points += i16::from(signals.transformed) * 10;
        points -= i16::from(signals.mostly_control_bytes) * 50;
        points -= i16::from(signals.invalid_text) * 30;
        points -= i16::from(signals.short_generic_value) * 20;

        ScoreResult {
            score: FindingScore(points),
            signals,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_patterns_are_very_high_confidence() {
        let result = FindingScorer::new().score(ScoreContext {
            match_kind: MatchKind::Known,
            matched_value: "FLAG{known}",
            candidate_data: b"FLAG{known}",
            path: &CandidatePath::root(),
            transformation_count: 0,
        });

        assert_eq!(result.score().confidence(), Confidence::VeryHigh);
        assert!(result.signals().known_pattern);
    }

    #[test]
    fn generic_matches_need_context_for_high_confidence() {
        let root = FindingScorer::new().score(ScoreContext {
            match_kind: MatchKind::GenericBrace,
            matched_value: "maybe{value}",
            candidate_data: b"maybe{value}",
            path: &CandidatePath::root(),
            transformation_count: 0,
        });
        let flag_path = CandidatePath::root()
            .with_property("flag")
            .expect("valid path");
        let contextual = FindingScorer::new().score(ScoreContext {
            match_kind: MatchKind::GenericBrace,
            matched_value: "maybe{value}",
            candidate_data: b"maybe{value}",
            path: &flag_path,
            transformation_count: 1,
        });

        assert_eq!(root.score().confidence(), Confidence::Medium);
        assert_eq!(contextual.score().confidence(), Confidence::VeryHigh);
        assert!(contextual.score() > root.score());
    }

    #[test]
    fn invalid_control_data_is_penalized() {
        let result = FindingScorer::new().score(ScoreContext {
            match_kind: MatchKind::GenericBrace,
            matched_value: "test{value}",
            candidate_data: &[0xff, 0x00, 0x01],
            path: &CandidatePath::root(),
            transformation_count: 0,
        });

        assert_eq!(result.score().confidence(), Confidence::Low);
        assert!(result.signals().invalid_text);
        assert!(result.signals().mostly_control_bytes);
    }
}
