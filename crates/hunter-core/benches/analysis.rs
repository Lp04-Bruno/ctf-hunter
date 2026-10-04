use std::{hint::black_box, time::Instant};

use base64::{Engine as _, engine::general_purpose};
use hunter_core::{AnalysisConfig, Analyzer};
use hunter_flags::FlagPattern;
use hunter_types::{CaptureEvent, EventId, EventPayload, SessionId, SourceMetadata, Timestamp};

fn event(payload: Vec<u8>) -> CaptureEvent {
    CaptureEvent::new(
        EventId::generate(),
        SessionId::generate(),
        Timestamp::from_unix_timestamp(1_800_000_000).expect("valid timestamp"),
        SourceMetadata::Manual,
        EventPayload::new(payload).expect("valid payload"),
    )
}

fn measure(name: &str, iterations: usize, task: impl Fn()) {
    let started = Instant::now();
    for _ in 0..iterations {
        task();
    }
    let elapsed = started.elapsed();
    println!("{name}: {iterations} iterations in {elapsed:?}");
}

fn main() {
    let analyzer = Analyzer::new(AnalysisConfig::default(), [FlagPattern::simple("FLAG{*}")])
        .expect("valid analyzer");

    let large = event(vec![b'a'; 60 * 1024]);
    measure("large_plain_text", 100, || {
        black_box(analyzer.analyze(black_box(&large)).expect("analysis"));
    });

    let repeated = event(
        std::iter::repeat_n("RkxBR3tiZW5jaH0=", 1_000)
            .collect::<Vec<_>>()
            .join(" ")
            .into_bytes(),
    );
    measure("repeated_candidates", 100, || {
        black_box(analyzer.analyze(black_box(&repeated)).expect("analysis"));
    });

    let mut deeply_encoded = b"FLAG{deep_benchmark}".to_vec();
    for _ in 0..5 {
        deeply_encoded = general_purpose::STANDARD
            .encode(deeply_encoded)
            .into_bytes();
    }
    let deep = event(deeply_encoded);
    measure("deep_transformations", 100, || {
        black_box(analyzer.analyze(black_box(&deep)).expect("analysis"));
    });
}
