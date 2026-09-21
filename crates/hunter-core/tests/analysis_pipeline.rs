use hunter_core::{AnalysisConfig, Analyzer};
use hunter_flags::FlagPattern;
use hunter_types::{
    CaptureEvent, Confidence, EventId, EventPayload, SessionId, SourceMetadata, Timestamp,
};

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
fn proves_nested_json_to_base64_to_flag_with_full_provenance() {
    let input = br#"{"profile":{"about":{"password":"RkxBR3t0ZXN0fQ=="}}}"#;
    let analyzer = Analyzer::new(AnalysisConfig::default(), [FlagPattern::simple("FLAG{*}")])
        .expect("valid analyzer");
    let report = analyzer
        .analyze(&event(input))
        .expect("analysis should succeed");

    let finding = report
        .findings()
        .iter()
        .find(|finding| finding.value().as_str() == "FLAG{test}")
        .expect("flag should be found");
    assert_eq!(finding.path().to_string(), "profile.about.password");
    assert_eq!(finding.confidence(), Confidence::VeryHigh);
    assert_eq!(finding.transformation_ids().len(), 1);

    let transformation = report
        .transformations()
        .iter()
        .find(|transformation| transformation.id() == finding.transformation_ids()[0])
        .expect("transformation should exist");
    assert_eq!(transformation.name().as_str(), "base64");
    assert_eq!(transformation.output_candidate_id(), finding.candidate_id());
}

#[test]
fn recursively_decodes_double_base64() {
    let analyzer = Analyzer::new(AnalysisConfig::default(), [FlagPattern::simple("FLAG{*}")])
        .expect("valid analyzer");
    let report = analyzer
        .analyze(&event(b"Umt4QlIzdGtaV1Z3WDJac1lXZDk="))
        .expect("analysis should succeed");
    let finding = report
        .findings()
        .iter()
        .find(|finding| finding.value().as_str() == "FLAG{deep_flag}")
        .expect("nested flag should be found");

    assert_eq!(finding.transformation_ids().len(), 2);
}

#[test]
fn recursively_parses_json_produced_by_a_decoder() {
    let analyzer = Analyzer::new(AnalysisConfig::default(), [FlagPattern::simple("FLAG{*}")])
        .expect("valid analyzer");
    let report = analyzer
        .analyze(&event(b"eyJuZXN0ZWQiOnsiZmxhZyI6IkZMQUd7anNvbn0ifX0="))
        .expect("analysis should succeed");
    let finding = report
        .findings()
        .iter()
        .find(|finding| finding.value().as_str() == "FLAG{json}")
        .expect("JSON flag should be found");

    assert_eq!(finding.path().to_string(), "nested.flag");
    assert_eq!(finding.transformation_ids().len(), 1);
}

#[test]
fn common_false_positives_do_not_create_findings() {
    let analyzer = Analyzer::new(AnalysisConfig::default(), [FlagPattern::simple("FLAG{*}")])
        .expect("valid analyzer");
    let report = analyzer
        .analyze(&event(include_bytes!(
            "../../../test-data/false-positives/common.txt"
        )))
        .expect("analysis should succeed");

    assert!(report.findings().is_empty());
}

#[test]
fn arbitrary_binary_input_does_not_create_high_confidence_findings() {
    let analyzer = Analyzer::new(AnalysisConfig::default(), [FlagPattern::simple("FLAG{*}")])
        .expect("valid analyzer");
    let binary: Vec<u8> = (0_u8..=255).cycle().take(4_096).collect();
    let report = analyzer
        .analyze(&event(&binary))
        .expect("analysis should succeed");

    assert!(
        report
            .findings()
            .iter()
            .all(|finding| finding.confidence() < Confidence::High)
    );
}
