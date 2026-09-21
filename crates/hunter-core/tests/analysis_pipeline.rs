use std::io::Write;

use base64::{Engine as _, engine::general_purpose};
use flate2::{Compression, write::GzEncoder};
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

#[test]
fn resolves_base64_gzip_json_base64_with_full_provenance() {
    let nested = br#"{"profile":{"payload":"RkxBR3tkZWVwX3Byb3ZlbmFuY2V9"}}"#;
    let mut gzip = GzEncoder::new(Vec::new(), Compression::default());
    gzip.write_all(nested).expect("gzip write");
    let encoded = general_purpose::STANDARD.encode(gzip.finish().expect("gzip finish"));
    let analyzer = Analyzer::new(AnalysisConfig::default(), [FlagPattern::simple("FLAG{*}")])
        .expect("valid analyzer");
    let report = analyzer
        .analyze(&event(encoded.as_bytes()))
        .expect("analysis should succeed");
    let finding = report
        .findings()
        .iter()
        .find(|finding| finding.value().as_str() == "FLAG{deep_provenance}")
        .expect("deep flag should be found");

    assert_eq!(finding.path().to_string(), "profile.payload");
    let names: Vec<_> = finding
        .transformation_ids()
        .iter()
        .map(|id| {
            report
                .transformations()
                .iter()
                .find(|transformation| transformation.id() == *id)
                .expect("transformation should exist")
                .name()
                .as_str()
        })
        .collect();
    assert_eq!(names, ["base64", "gzip", "base64"]);
}

#[test]
fn scores_findings_independently_from_decoder_output() {
    let analyzer = Analyzer::new(AnalysisConfig::default(), [FlagPattern::simple("FLAG{*}")])
        .expect("valid analyzer");
    let report = analyzer
        .analyze(&event(b"RkxBR3tzY29yZWR9"))
        .expect("analysis should succeed");
    let finding = report.findings().first().expect("flag should be found");
    let assessment = report
        .assessments()
        .iter()
        .find(|assessment| assessment.finding_id() == finding.id())
        .expect("assessment should exist");

    assert_eq!(assessment.score().confidence(), finding.confidence());
    assert!(assessment.signals().known_pattern);
    assert!(assessment.signals().transformed);
}

#[test]
fn analyzes_jwt_numeric_ascii_and_raw_utf16_inputs() {
    let analyzer = Analyzer::new(AnalysisConfig::default(), [FlagPattern::simple("FLAG{*}")])
        .expect("valid analyzer");
    let jwt = event(b"eyJhbGciOiJub25lIn0.eyJmbGFnIjoiRkxBR3tqd3R9In0.signature");
    let jwt_report = analyzer.analyze(&jwt).expect("JWT analysis");
    assert!(
        jwt_report
            .findings()
            .iter()
            .any(|finding| finding.value().as_str() == "FLAG{jwt}")
    );

    let numeric = event(b"70 76 65 71 123 110 117 109 101 114 105 99 125");
    let numeric_report = analyzer.analyze(&numeric).expect("numeric analysis");
    assert!(
        numeric_report
            .findings()
            .iter()
            .any(|finding| finding.value().as_str() == "FLAG{numeric}")
    );

    let mut utf16 = vec![0xff, 0xfe];
    utf16.extend("FLAG{utf16}".encode_utf16().flat_map(u16::to_le_bytes));
    let utf16_report = analyzer.analyze(&event(&utf16)).expect("UTF-16 analysis");
    assert!(
        utf16_report
            .findings()
            .iter()
            .any(|finding| finding.value().as_str() == "FLAG{utf16}")
    );
}

#[test]
fn compressed_expansion_stops_at_the_decoded_byte_budget() {
    let mut gzip = GzEncoder::new(Vec::new(), Compression::default());
    gzip.write_all(&vec![b'A'; 4_096]).expect("gzip write");
    let encoded = general_purpose::STANDARD.encode(gzip.finish().expect("gzip finish"));
    let analyzer = Analyzer::new(
        AnalysisConfig {
            max_decoded_bytes_per_root: 64,
            ..AnalysisConfig::default()
        },
        [FlagPattern::simple("FLAG{*}")],
    )
    .expect("valid analyzer");
    let report = analyzer
        .analyze(&event(encoded.as_bytes()))
        .expect("analysis should succeed");

    assert!(
        report
            .budget_limits()
            .contains(&hunter_core::BudgetLimit::DecodedBytes)
    );
    assert!(report.findings().is_empty());
}

#[test]
fn reverse_transformation_terminates_without_a_loop() {
    let analyzer = Analyzer::new(AnalysisConfig::default(), [FlagPattern::simple("FLAG{*}")])
        .expect("valid analyzer");
    let report = analyzer
        .analyze(&event(b"}pool{GALF"))
        .expect("analysis should succeed");

    let finding = report
        .findings()
        .iter()
        .find(|finding| finding.value().as_str() == "FLAG{loop}")
        .expect("reversed flag should be found");
    assert_eq!(finding.transformation_ids().len(), 1);
    assert_eq!(report.transformations().len(), 1);
    assert_eq!(report.statistics().decoded_candidates, 1);
}
