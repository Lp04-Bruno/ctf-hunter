use hunter_types::{
    Candidate, CandidateData, CandidateId, CandidatePath, CaptureEvent, Confidence, EventId,
    EventPayload, FindingId, FindingProvenance, FlagFinding, FlagValue, Session, SessionId,
    SourceMetadata, SourcePath, TerminalSource, Timestamp, Transformation, TransformationId,
    TransformationName,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Snapshot {
    session: Session,
    event: CaptureEvent,
    candidates: Vec<Candidate>,
    transformation: Transformation,
    finding: FlagFinding,
}

#[test]
fn public_api_preserves_an_end_to_end_provenance_chain() {
    let created_at = Timestamp::from_unix_timestamp(1_800_000_000).expect("valid timestamp");
    let observed_at = Timestamp::from_unix_timestamp(1_800_000_010).expect("valid timestamp");

    let session_id = SessionId::generate();
    let mut session = Session::new(session_id, "Local Lab", created_at).expect("valid session");
    session
        .set_flag_patterns(vec!["FLAG{*}".into()])
        .expect("valid pattern");
    session.start(observed_at).expect("session should start");

    let event_id = EventId::generate();
    let event = CaptureEvent::new(
        event_id,
        session_id,
        observed_at,
        SourceMetadata::Terminal(
            TerminalSource::new(
                4_242,
                1_000,
                Some(1),
                "curl",
                Some(SourcePath::new("/usr/bin/curl").expect("valid path")),
                SourcePath::new("/dev/pts/2").expect("valid path"),
            )
            .expect("valid source"),
        ),
        EventPayload::new(br#"{"password":"RkxBR3t0ZXN0fQ=="}"#.to_vec()).expect("valid payload"),
    );

    let path = CandidatePath::root()
        .with_property("password")
        .expect("valid path");
    let encoded_id = CandidateId::generate();
    let encoded = Candidate::new(
        encoded_id,
        event_id,
        None,
        path.clone(),
        CandidateData::new(b"RkxBR3t0ZXN0fQ==".to_vec()).expect("valid data"),
        0,
    );
    let decoded_id = CandidateId::generate();
    let decoded = Candidate::new(
        decoded_id,
        event_id,
        Some(encoded_id),
        path.clone(),
        CandidateData::new(b"FLAG{test}".to_vec()).expect("valid data"),
        1,
    );

    let transformation_id = TransformationId::generate();
    let transformation = Transformation::new(
        transformation_id,
        encoded_id,
        decoded_id,
        TransformationName::new("base64").expect("valid transformation"),
        observed_at,
    );
    let finding = FlagFinding::new(
        FindingId::generate(),
        FindingProvenance::new(
            session_id,
            event_id,
            decoded_id,
            path,
            vec![transformation_id],
        ),
        FlagValue::new("FLAG{test}").expect("valid flag"),
        Confidence::VeryHigh,
        observed_at,
    );

    let snapshot = Snapshot {
        session,
        event,
        candidates: vec![encoded, decoded],
        transformation,
        finding,
    };
    let serialized = serde_json::to_vec(&snapshot).expect("snapshot should serialize");
    let restored = serde_json::from_slice(&serialized).expect("snapshot should deserialize");

    assert_eq!(snapshot, restored);
}
