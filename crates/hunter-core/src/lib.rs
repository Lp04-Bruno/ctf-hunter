use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

use hunter_decoder::DecoderSet;
use hunter_flags::{FlagDetector, FlagPattern, PatternError};
use hunter_parser::{ExtractionError, ExtractionLimits, extract_candidates, strip_ansi};
use hunter_types::{
    Candidate, CandidateData, CandidateId, CandidatePath, CaptureEvent, FindingId,
    FindingProvenance, FlagFinding, Transformation, TransformationId, TransformationName,
    ValidationError,
};
use thiserror::Error;

pub const DEFAULT_MAX_DEPTH: u8 = 5;
pub const DEFAULT_MAX_CHILDREN: usize = 10;
pub const DEFAULT_MAX_DESCENDANTS: usize = 500;
pub const DEFAULT_MAX_DECODED_BYTES: usize = 5 * 1024 * 1024;
pub const DEFAULT_MAX_ROOT_CANDIDATES: usize = 1_024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnalysisConfig {
    pub max_depth: u8,
    pub max_children_per_candidate: usize,
    pub max_descendants_per_root: usize,
    pub max_decoded_bytes_per_root: usize,
    pub max_root_candidates: usize,
    pub max_extracted_value_bytes: usize,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            max_depth: DEFAULT_MAX_DEPTH,
            max_children_per_candidate: DEFAULT_MAX_CHILDREN,
            max_descendants_per_root: DEFAULT_MAX_DESCENDANTS,
            max_decoded_bytes_per_root: DEFAULT_MAX_DECODED_BYTES,
            max_root_candidates: DEFAULT_MAX_ROOT_CANDIDATES,
            max_extracted_value_bytes: hunter_parser::DEFAULT_MAX_EXTRACTED_VALUE_BYTES,
        }
    }
}

impl AnalysisConfig {
    pub fn validate(self) -> Result<Self, AnalysisError> {
        if self.max_depth == 0 {
            return Err(AnalysisError::InvalidConfig(
                "max_depth must be greater than zero",
            ));
        }
        if self.max_children_per_candidate == 0 {
            return Err(AnalysisError::InvalidConfig(
                "max_children_per_candidate must be greater than zero",
            ));
        }
        if self.max_descendants_per_root == 0 {
            return Err(AnalysisError::InvalidConfig(
                "max_descendants_per_root must be greater than zero",
            ));
        }
        if self.max_decoded_bytes_per_root == 0 {
            return Err(AnalysisError::InvalidConfig(
                "max_decoded_bytes_per_root must be greater than zero",
            ));
        }
        if self.max_root_candidates == 0 {
            return Err(AnalysisError::InvalidConfig(
                "max_root_candidates must be greater than zero",
            ));
        }
        if self.max_extracted_value_bytes == 0 {
            return Err(AnalysisError::InvalidConfig(
                "max_extracted_value_bytes must be greater than zero",
            ));
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum BudgetLimit {
    Depth,
    Children,
    Descendants,
    DecodedBytes,
    RootCandidates,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateOccurrence {
    candidate_id: CandidateId,
    path: CandidatePath,
}

impl CandidateOccurrence {
    #[must_use]
    pub const fn candidate_id(&self) -> CandidateId {
        self.candidate_id
    }

    #[must_use]
    pub const fn path(&self) -> &CandidatePath {
        &self.path
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AnalysisStatistics {
    pub extracted_occurrences: usize,
    pub unique_root_candidates: usize,
    pub duplicate_occurrences: usize,
    pub decoded_candidates: usize,
    pub suppressed_revisits: usize,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AnalysisReport {
    normalized: Vec<u8>,
    candidates: Vec<Candidate>,
    occurrences: Vec<CandidateOccurrence>,
    transformations: Vec<Transformation>,
    findings: Vec<FlagFinding>,
    budget_limits: BTreeSet<BudgetLimit>,
    statistics: AnalysisStatistics,
}

impl AnalysisReport {
    #[must_use]
    pub fn normalized(&self) -> &[u8] {
        &self.normalized
    }

    #[must_use]
    pub fn candidates(&self) -> &[Candidate] {
        &self.candidates
    }

    #[must_use]
    pub fn occurrences(&self) -> &[CandidateOccurrence] {
        &self.occurrences
    }

    #[must_use]
    pub fn transformations(&self) -> &[Transformation] {
        &self.transformations
    }

    #[must_use]
    pub fn findings(&self) -> &[FlagFinding] {
        &self.findings
    }

    #[must_use]
    pub const fn budget_limits(&self) -> &BTreeSet<BudgetLimit> {
        &self.budget_limits
    }

    #[must_use]
    pub const fn statistics(&self) -> AnalysisStatistics {
        self.statistics
    }
}

#[derive(Debug, Error)]
pub enum AnalysisError {
    #[error("invalid analysis configuration: {0}")]
    InvalidConfig(&'static str),
    #[error(transparent)]
    Pattern(#[from] PatternError),
    #[error(transparent)]
    Extraction(#[from] ExtractionError),
    #[error(transparent)]
    Validation(#[from] ValidationError),
}

#[derive(Clone, Debug)]
pub struct Analyzer {
    config: AnalysisConfig,
    decoder: DecoderSet,
    detector: FlagDetector,
}

impl Analyzer {
    pub fn new(
        config: AnalysisConfig,
        patterns: impl IntoIterator<Item = FlagPattern>,
    ) -> Result<Self, AnalysisError> {
        Ok(Self {
            config: config.validate()?,
            decoder: DecoderSet::new(),
            detector: FlagDetector::new(patterns)?,
        })
    }

    pub fn analyze(&self, event: &CaptureEvent) -> Result<AnalysisReport, AnalysisError> {
        let normalized = strip_ansi(event.payload().as_bytes());
        let text = String::from_utf8_lossy(&normalized).into_owned();
        let limits = ExtractionLimits {
            max_values: normalized.len().saturating_add(1),
            max_value_bytes: self.config.max_extracted_value_bytes,
        };
        let mut extracted = extract_candidates(&text, &CandidatePath::root(), limits)?;
        let root_limit_reached = extracted.len() > self.config.max_root_candidates;
        extracted.truncate(self.config.max_root_candidates);

        let mut report = AnalysisReport {
            normalized,
            ..AnalysisReport::default()
        };
        if root_limit_reached {
            report.budget_limits.insert(BudgetLimit::RootCandidates);
        }
        self.analyze_extracted(event, extracted, report)
    }

    fn analyze_extracted(
        &self,
        event: &CaptureEvent,
        extracted: Vec<hunter_parser::ExtractedValue>,
        mut report: AnalysisReport,
    ) -> Result<AnalysisReport, AnalysisError> {
        report.statistics.extracted_occurrences = extracted.len();
        let roots = deduplicate_roots(extracted);
        report.statistics.unique_root_candidates = roots.len();
        report.statistics.duplicate_occurrences = report
            .statistics
            .extracted_occurrences
            .saturating_sub(roots.len());

        for root in roots {
            self.analyze_root(event, root, &mut report)?;
        }
        Ok(report)
    }

    fn analyze_root(
        &self,
        event: &CaptureEvent,
        root: RootValue,
        report: &mut AnalysisReport,
    ) -> Result<(), AnalysisError> {
        let root_id = CandidateId::generate();
        let root_candidate = Candidate::new(
            root_id,
            event.id(),
            None,
            root.paths[0].clone(),
            CandidateData::new(root.data.clone())?,
            0,
        );
        report.candidates.push(root_candidate);
        for path in &root.paths {
            report.occurrences.push(CandidateOccurrence {
                candidate_id: root_id,
                path: path.clone(),
            });
        }

        let root_hash = content_hash(&root.data);
        let mut queue = VecDeque::from([WorkItem {
            id: root_id,
            path: root.paths[0].clone(),
            data: root.data,
            depth: 0,
            transformations: Vec::new(),
            ancestors: HashSet::from([root_hash]),
            occurrences: root.paths.len(),
        }]);
        let mut seen = HashSet::from([root_hash]);
        let mut descendants = 0;
        let mut decoded_bytes: usize = 0;

        while let Some(item) = queue.pop_front() {
            let (mut children, structured, structured_limit_reached) =
                self.structured_children(&item)?;
            if structured_limit_reached {
                report.budget_limits.insert(BudgetLimit::Children);
            }
            if !structured {
                self.detect_findings(event, &item, report);
            }
            let remaining = self
                .config
                .max_children_per_candidate
                .saturating_sub(children.len());

            if item.depth == self.config.max_depth {
                if !self.decoder.decode(&item.data).is_empty() {
                    report.budget_limits.insert(BudgetLimit::Depth);
                }
            } else {
                let decoded = self.decoder.decode(&item.data);
                if decoded.len() > remaining {
                    report.budget_limits.insert(BudgetLimit::Children);
                }
                children.extend(decoded.into_iter().take(remaining).map(|value| ChildValue {
                    path: item.path.clone(),
                    data: value.data().to_vec(),
                    transformation: Some(value.transformation()),
                }));
            }

            if children.len() > self.config.max_children_per_candidate {
                children.truncate(self.config.max_children_per_candidate);
                report.budget_limits.insert(BudgetLimit::Children);
            }

            for child in children {
                if descendants == self.config.max_descendants_per_root {
                    report.budget_limits.insert(BudgetLimit::Descendants);
                    queue.clear();
                    break;
                }
                let hash = content_hash(&child.data);
                if item.ancestors.contains(&hash) || !seen.insert(hash) {
                    report.statistics.suppressed_revisits += 1;
                    continue;
                }
                if child.transformation.is_some()
                    && decoded_bytes.saturating_add(child.data.len())
                        > self.config.max_decoded_bytes_per_root
                {
                    report.budget_limits.insert(BudgetLimit::DecodedBytes);
                    continue;
                }

                let child_id = CandidateId::generate();
                let depth = item.depth + u8::from(child.transformation.is_some());
                report.candidates.push(Candidate::new(
                    child_id,
                    event.id(),
                    Some(item.id),
                    child.path.clone(),
                    CandidateData::new(child.data.clone())?,
                    depth,
                ));
                report.occurrences.push(CandidateOccurrence {
                    candidate_id: child_id,
                    path: child.path.clone(),
                });

                let mut transformations = item.transformations.clone();
                if let Some(name) = child.transformation {
                    decoded_bytes += child.data.len();
                    report.statistics.decoded_candidates += 1;
                    let transformation_id = TransformationId::generate();
                    report.transformations.push(Transformation::new(
                        transformation_id,
                        item.id,
                        child_id,
                        TransformationName::new(name)?,
                        event.captured_at(),
                    ));
                    transformations.push(transformation_id);
                }

                let mut ancestors = item.ancestors.clone();
                ancestors.insert(hash);
                queue.push_back(WorkItem {
                    id: child_id,
                    path: child.path,
                    data: child.data,
                    depth,
                    transformations,
                    ancestors,
                    occurrences: item.occurrences,
                });
                descendants += 1;
            }
        }
        Ok(())
    }

    fn structured_children(
        &self,
        item: &WorkItem,
    ) -> Result<(Vec<ChildValue>, bool, bool), AnalysisError> {
        let Ok(text) = std::str::from_utf8(&item.data) else {
            return Ok((Vec::new(), false, false));
        };
        if !matches!(text.trim_start().as_bytes().first(), Some(b'{' | b'[')) {
            return Ok((Vec::new(), false, false));
        }
        if serde_json::from_str::<serde_json::Value>(text).is_err() {
            return Ok((Vec::new(), false, false));
        }
        let mut extracted = extract_candidates(
            text,
            &item.path,
            ExtractionLimits {
                max_values: text.len().saturating_add(1),
                max_value_bytes: self.config.max_extracted_value_bytes,
            },
        )?;
        let limit_reached = extracted.len() > self.config.max_children_per_candidate;
        extracted.truncate(self.config.max_children_per_candidate);
        Ok((
            extracted
                .into_iter()
                .map(|value| ChildValue {
                    path: value.path().clone(),
                    data: value.data().to_vec(),
                    transformation: None,
                })
                .collect(),
            true,
            limit_reached,
        ))
    }

    fn detect_findings(&self, event: &CaptureEvent, item: &WorkItem, report: &mut AnalysisReport) {
        let Ok(text) = std::str::from_utf8(&item.data) else {
            return;
        };
        for matched in self.detector.detect(text) {
            let mut finding = FlagFinding::new(
                FindingId::generate(),
                FindingProvenance::new(
                    event.session_id(),
                    event.id(),
                    item.id,
                    item.path.clone(),
                    item.transformations.clone(),
                ),
                matched.value().clone(),
                matched.confidence(),
                event.captured_at(),
            );
            for _ in 1..item.occurrences {
                let _ = finding.record_occurrence();
            }
            report.findings.push(finding);
        }
    }
}

#[derive(Clone, Debug)]
struct RootValue {
    paths: Vec<CandidatePath>,
    data: Vec<u8>,
}

#[derive(Clone, Debug)]
struct WorkItem {
    id: CandidateId,
    path: CandidatePath,
    data: Vec<u8>,
    depth: u8,
    transformations: Vec<TransformationId>,
    ancestors: HashSet<[u8; 32]>,
    occurrences: usize,
}

#[derive(Clone, Debug)]
struct ChildValue {
    path: CandidatePath,
    data: Vec<u8>,
    transformation: Option<&'static str>,
}

fn deduplicate_roots(values: Vec<hunter_parser::ExtractedValue>) -> Vec<RootValue> {
    let mut positions = HashMap::<[u8; 32], usize>::new();
    let mut roots = Vec::<RootValue>::new();
    for value in values {
        let hash = content_hash(value.data());
        if let Some(&position) = positions.get(&hash) {
            roots[position].paths.push(value.path().clone());
        } else {
            positions.insert(hash, roots.len());
            roots.push(RootValue {
                paths: vec![value.path().clone()],
                data: value.data().to_vec(),
            });
        }
    }
    roots
}

fn content_hash(value: &[u8]) -> [u8; 32] {
    *blake3::hash(value).as_bytes()
}

#[cfg(test)]
mod tests {
    use hunter_types::{EventId, EventPayload, SessionId, SourceMetadata, Timestamp};

    use super::*;

    fn event(payload: &[u8]) -> CaptureEvent {
        CaptureEvent::new(
            EventId::generate(),
            SessionId::generate(),
            Timestamp::from_unix_timestamp(1_800_000_000).expect("valid timestamp"),
            SourceMetadata::Manual,
            EventPayload::new(payload.to_vec()).expect("valid payload"),
        )
    }

    #[test]
    fn rejects_zero_budgets() {
        let config = AnalysisConfig {
            max_depth: 0,
            ..AnalysisConfig::default()
        };
        assert!(matches!(
            Analyzer::new(config, []),
            Err(AnalysisError::InvalidConfig(_))
        ));
    }

    #[test]
    fn strips_ansi_before_detecting_plain_flags() {
        let analyzer = Analyzer::new(AnalysisConfig::default(), [FlagPattern::simple("FLAG{*}")])
            .expect("valid analyzer");
        let report = analyzer
            .analyze(&event(b"\x1b[31mFLAG{visible}\x1b[0m"))
            .expect("analysis should succeed");

        assert_eq!(report.normalized(), b"FLAG{visible}");
        assert_eq!(report.findings().len(), 1);
    }

    #[test]
    fn deduplicates_repeated_candidates_and_retains_occurrence_count() {
        let analyzer = Analyzer::new(AnalysisConfig::default(), [FlagPattern::simple("FLAG{*}")])
            .expect("valid analyzer");
        let input = std::iter::repeat_n("RkxBR3tkZWR1cGVkfQ==", 1_000)
            .collect::<Vec<_>>()
            .join(" ");
        let report = analyzer
            .analyze(&event(input.as_bytes()))
            .expect("analysis should succeed");

        assert_eq!(report.statistics().extracted_occurrences, 1_000);
        assert_eq!(report.statistics().unique_root_candidates, 1);
        assert_eq!(report.statistics().decoded_candidates, 1);
        assert_eq!(report.findings()[0].occurrences().get(), 1_000);
    }

    #[test]
    fn records_depth_budget_exhaustion() {
        let encoded_twice =
            "VWtWV1IxOVlWbFpVYlZaclVqQmtUMlZyY0VaWFJsbDNXa1ZrYVUxV2JGVk5WMUpIVkcxS1ZrMVZNVDA9";
        let analyzer = Analyzer::new(
            AnalysisConfig {
                max_depth: 1,
                ..AnalysisConfig::default()
            },
            [FlagPattern::simple("FLAG{*}")],
        )
        .expect("valid analyzer");
        let report = analyzer
            .analyze(&event(encoded_twice.as_bytes()))
            .expect("analysis should succeed");

        assert!(report.budget_limits().contains(&BudgetLimit::Depth));
    }

    #[test]
    fn enforces_root_child_descendant_and_byte_budgets() {
        let root_limited = Analyzer::new(
            AnalysisConfig {
                max_root_candidates: 1,
                ..AnalysisConfig::default()
            },
            [],
        )
        .expect("valid analyzer")
        .analyze(&event(b"first second"))
        .expect("analysis should succeed");
        assert!(
            root_limited
                .budget_limits()
                .contains(&BudgetLimit::RootCandidates)
        );
        assert_eq!(root_limited.statistics().unique_root_candidates, 1);

        let child_limited = Analyzer::new(
            AnalysisConfig {
                max_children_per_candidate: 1,
                ..AnalysisConfig::default()
            },
            [],
        )
        .expect("valid analyzer")
        .analyze(&event(b"eyJhIjoib25lIiwiYiI6InR3byJ9"))
        .expect("analysis should succeed");
        assert!(
            child_limited
                .budget_limits()
                .contains(&BudgetLimit::Children)
        );

        let descendant_limited = Analyzer::new(
            AnalysisConfig {
                max_descendants_per_root: 1,
                ..AnalysisConfig::default()
            },
            [],
        )
        .expect("valid analyzer")
        .analyze(&event(b"Umt4QlIzdGtaV1Z3WDJac1lXZDk="))
        .expect("analysis should succeed");
        assert!(
            descendant_limited
                .budget_limits()
                .contains(&BudgetLimit::Descendants)
        );

        let bytes_limited = Analyzer::new(
            AnalysisConfig {
                max_decoded_bytes_per_root: 5,
                ..AnalysisConfig::default()
            },
            [FlagPattern::simple("FLAG{*}")],
        )
        .expect("valid analyzer")
        .analyze(&event(b"RkxBR3t0ZXN0fQ=="))
        .expect("analysis should succeed");
        assert!(
            bytes_limited
                .budget_limits()
                .contains(&BudgetLimit::DecodedBytes)
        );
        assert!(bytes_limited.findings().is_empty());
    }

    #[test]
    fn suppresses_repeated_descendant_content() {
        let analyzer = Analyzer::new(AnalysisConfig::default(), []).expect("valid analyzer");
        let report = analyzer
            .analyze(&event(b"eyJhIjoic2FtZSIsImIiOiJzYW1lIn0="))
            .expect("analysis should succeed");

        assert!(report.statistics().suppressed_revisits > 0);
    }
}
