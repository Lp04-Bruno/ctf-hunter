use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::Path,
    time::Duration,
};

use hunter_types::{
    CandidateId, CandidatePath, Confidence, EventId, FindingId, NotificationSettings, Session,
    SessionId, SourceMetadata, Timestamp, TransformationId,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_FRAME_BYTES: usize = 128 * 1024;
pub const MAX_LIST_LIMIT: usize = 100;
pub const IO_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RequestEnvelope {
    pub version: u16,
    pub request_id: u64,
    pub request: Request,
}

impl RequestEnvelope {
    #[must_use]
    pub const fn new(request_id: u64, request: Request) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            request_id,
            request,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "operation")]
pub enum Request {
    GetStatus,
    GetNotificationSettings,
    UpdateNotificationSettings {
        settings: NotificationSettings,
    },
    ListSessions,
    CreateSession {
        name: String,
        flag_patterns: Vec<String>,
    },
    UpdateSession {
        session_id: SessionId,
        name: String,
        flag_patterns: Vec<String>,
    },
    StartSession {
        session_id: SessionId,
    },
    PauseSession {
        session_id: SessionId,
    },
    ResumeSession {
        session_id: SessionId,
    },
    StopSession {
        session_id: SessionId,
    },
    AddWatchDirectory {
        session_id: SessionId,
        directory: String,
    },
    RemoveWatchDirectory {
        session_id: SessionId,
        directory: String,
    },
    ListWatchDirectories {
        session_id: SessionId,
    },
    AddTerminal {
        session_id: SessionId,
        terminal: String,
    },
    RemoveTerminal {
        session_id: SessionId,
        terminal: String,
    },
    ListTerminals {
        session_id: SessionId,
    },
    SubmitText {
        session_id: SessionId,
        text: String,
    },
    PreviewText {
        session_id: SessionId,
        text: String,
    },
    ListFindings {
        session_id: SessionId,
        offset: usize,
        limit: usize,
    },
    GetFinding {
        finding_id: FindingId,
    },
    Shutdown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ResponseEnvelope {
    pub version: u16,
    pub request_id: u64,
    pub response: Response,
}

impl ResponseEnvelope {
    #[must_use]
    pub const fn new(request_id: u64, response: Response) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            request_id,
            response,
        }
    }

    #[must_use]
    pub fn error(request_id: u64, code: ErrorCode, message: impl Into<String>) -> Self {
        Self::new(
            request_id,
            Response::Error {
                code,
                message: message.into(),
            },
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "result")]
pub enum Response {
    Status(DaemonStatus),
    NotificationSettings(NotificationSettings),
    Sessions {
        sessions: Vec<Session>,
    },
    Session(Session),
    WatchDirectories {
        session_id: SessionId,
        directories: Vec<String>,
    },
    Terminals {
        session_id: SessionId,
        terminals: Vec<String>,
    },
    Submission {
        event_id: EventId,
        finding_ids: Vec<FindingId>,
    },
    AnalysisPreview(AnalysisPreview),
    Findings {
        findings: Vec<FindingSummary>,
    },
    Finding {
        finding: Option<FindingDetail>,
    },
    Acknowledged,
    Error {
        code: ErrorCode,
        message: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidFrame,
    UnsupportedVersion,
    InvalidRequest,
    NotFound,
    InvalidState,
    Busy,
    PermissionDenied,
    Internal,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DaemonStatus {
    pub schema_version: usize,
    pub worker_count: usize,
    pub queue_capacity: usize,
    pub queue_depth: usize,
    pub accepted_connections: u64,
    pub rejected_connections: u64,
    pub completed_requests: u64,
    pub failed_requests: u64,
    pub file_collector: FileCollectorStatus,
    pub capture: CaptureStatus,
    pub analysis: AnalysisStatus,
    pub notifications: NotificationStatus,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct NotificationStatus {
    pub queue_capacity: usize,
    pub queue_depth: usize,
    pub delivered: u64,
    pub dropped: u64,
    pub errors: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct AnalysisStatus {
    pub events_analyzed: u64,
    pub candidates_extracted: u64,
    pub candidates_decoded: u64,
    pub findings_detected: u64,
    pub duplicate_events: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct FileCollectorStatus {
    pub events_received: u64,
    pub files_read: u64,
    pub duplicate_events: u64,
    pub oversized_files: u64,
    pub rate_limited_files: u64,
    pub dropped_events: u64,
    pub read_errors: u64,
    pub queue_overflows: u64,
    pub invalidated_watches: u64,
    pub analyzed_files: u64,
    pub analysis_errors: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CaptureStatus {
    pub configured_sources: usize,
    pub active_sources: usize,
    pub connected_sources: usize,
    pub connection_attempts: u64,
    pub reconnects: u64,
    pub events_received: u64,
    pub events_analyzed: u64,
    pub analysis_errors: u64,
    pub dropped_events: u64,
    pub protocol_errors: u64,
    pub helper_errors: u64,
    pub ring_dropped: u64,
    pub read_failed: u64,
    pub fail_closed: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AnalysisPreview {
    pub normalized: String,
    pub detections: Vec<PreviewDetection>,
    pub transformations: Vec<PreviewTransformation>,
    pub findings: Vec<PreviewFinding>,
    pub statistics: PreviewStatistics,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PreviewDetection {
    pub format: String,
    pub confidence: u8,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PreviewTransformation {
    pub name: String,
    pub input: String,
    pub output: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PreviewFinding {
    pub value: String,
    pub confidence: Confidence,
    pub path: CandidatePath,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PreviewStatistics {
    pub extracted_occurrences: usize,
    pub candidate_count: usize,
    pub decoded_candidates: usize,
    pub decoder_attempts: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FindingSummary {
    pub id: FindingId,
    pub session_id: SessionId,
    pub value: String,
    pub confidence: Confidence,
    pub discovered_at: Timestamp,
    pub occurrences: u64,
    pub source: Option<SourceMetadata>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransformationStep {
    pub id: TransformationId,
    pub input_candidate_id: CandidateId,
    pub output_candidate_id: CandidateId,
    pub name: String,
    pub applied_at: Timestamp,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FindingOccurrence {
    pub source_event_id: EventId,
    pub candidate_id: CandidateId,
    pub path: CandidatePath,
    pub observed_at: Timestamp,
    pub count: u64,
    pub source: SourceMetadata,
    pub candidate_text: Option<String>,
    pub candidate_original_length: usize,
    pub candidate_truncated: bool,
    pub transformations: Vec<TransformationStep>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FindingDetail {
    pub summary: FindingSummary,
    pub occurrences: Vec<FindingOccurrence>,
    pub occurrences_truncated: bool,
}

#[derive(Debug, Error)]
pub enum FrameError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("frame length {0} is invalid")]
    InvalidLength(usize),
    #[error("frame exceeds the maximum size of {MAX_FRAME_BYTES} bytes")]
    Oversized,
    #[error("frame contains invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
}

pub fn read_frame<T: DeserializeOwned>(reader: &mut impl Read) -> Result<T, FrameError> {
    let mut header = [0_u8; 4];
    reader.read_exact(&mut header)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 {
        return Err(FrameError::InvalidLength(length));
    }
    if length > MAX_FRAME_BYTES {
        return Err(FrameError::Oversized);
    }
    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload)?;
    Ok(serde_json::from_slice(&payload)?)
}

pub fn write_frame<T: Serialize>(writer: &mut impl Write, value: &T) -> Result<(), FrameError> {
    let payload = serde_json::to_vec(value)?;
    if payload.is_empty() {
        return Err(FrameError::InvalidLength(0));
    }
    if payload.len() > MAX_FRAME_BYTES {
        return Err(FrameError::Oversized);
    }
    let length = u32::try_from(payload.len()).map_err(|_| FrameError::Oversized)?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(&payload)?;
    writer.flush()?;
    Ok(())
}

pub struct IpcClient;

impl IpcClient {
    pub fn request(
        socket_path: impl AsRef<Path>,
        request: &RequestEnvelope,
    ) -> Result<ResponseEnvelope, FrameError> {
        let mut stream = UnixStream::connect(socket_path)?;
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        write_frame(&mut stream, request)?;
        read_frame(&mut stream)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn round_trips_a_versioned_frame() {
        let request = RequestEnvelope::new(42, Request::GetStatus);
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &request).expect("write");

        assert_eq!(
            read_frame::<RequestEnvelope>(&mut Cursor::new(bytes)).expect("read"),
            request
        );
    }

    #[test]
    fn rejects_zero_and_oversized_frames_before_allocating_payload() {
        let mut zero = Cursor::new(0_u32.to_be_bytes());
        assert!(matches!(
            read_frame::<RequestEnvelope>(&mut zero),
            Err(FrameError::InvalidLength(0))
        ));

        let oversized = u32::try_from(MAX_FRAME_BYTES + 1).expect("length");
        let mut bytes = Cursor::new(oversized.to_be_bytes());
        assert!(matches!(
            read_frame::<RequestEnvelope>(&mut bytes),
            Err(FrameError::Oversized)
        ));
    }

    #[test]
    fn rejects_malformed_json() {
        let payload = b"not json";
        let mut bytes = u32::try_from(payload.len())
            .expect("length")
            .to_be_bytes()
            .to_vec();
        bytes.extend_from_slice(payload);

        assert!(matches!(
            read_frame::<RequestEnvelope>(&mut Cursor::new(bytes)),
            Err(FrameError::Json(_))
        ));
    }
}
