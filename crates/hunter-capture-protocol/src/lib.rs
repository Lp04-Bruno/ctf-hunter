use std::io::{Read, Write};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_FRAME_BYTES: usize = 4 * 1024;
pub const MAX_TERMINAL_PATH_BYTES: usize = 4 * 1024;
pub const MAX_PROCESS_NAME_BYTES: usize = 16;
pub const MAX_CAPTURE_BYTES: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Envelope<T> {
    pub version: u16,
    pub message: T,
}

impl<T> Envelope<T> {
    #[must_use]
    pub const fn new(message: T) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            message,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "operation")]
pub enum ClientMessage {
    Start { terminal: String },
    Stop,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "result")]
pub enum ServerMessage {
    Ready,
    Event(CapturedOutput),
    Health(CaptureHealth),
    Error { code: ErrorCode, message: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CapturedOutput {
    pub pid: u32,
    pub uid: u32,
    pub requested_len: u32,
    pub truncated: bool,
    pub process_name: String,
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CaptureHealth {
    pub seen: u64,
    pub emitted: u64,
    pub forwarded: u64,
    pub read_marked: u64,
    pub taint_filtered: u64,
    pub initial_filtered: u64,
    pub background_filtered: u64,
    pub tty_filtered: u64,
    pub uid_filtered: u64,
    pub process_filtered: u64,
    pub structure_failed: u64,
    pub map_failed: u64,
    pub fail_closed: u64,
    pub ring_dropped: u64,
    pub read_failed: u64,
    pub truncated: u64,
    pub failure_reason: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidRequest,
    PermissionDenied,
    Busy,
    KernelUnsupported,
    Internal,
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("capture protocol frame length {0} is invalid")]
    InvalidLength(usize),
    #[error("capture protocol frame exceeds {MAX_FRAME_BYTES} bytes")]
    Oversized,
    #[error("capture protocol version {found} is unsupported")]
    UnsupportedVersion { found: u16 },
    #[error("capture protocol message is invalid: {0}")]
    InvalidMessage(&'static str),
    #[error("capture protocol frame contains invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
}

pub fn read_client(reader: &mut impl Read) -> Result<ClientMessage, ProtocolError> {
    let message: Envelope<ClientMessage> = read_frame(reader)?;
    validate_version(message.version)?;
    validate_client(&message.message)?;
    Ok(message.message)
}

pub fn write_client(writer: &mut impl Write, message: &ClientMessage) -> Result<(), ProtocolError> {
    validate_client(message)?;
    write_frame(writer, &Envelope::new(message))
}

pub fn read_server(reader: &mut impl Read) -> Result<ServerMessage, ProtocolError> {
    let message: Envelope<ServerMessage> = read_frame(reader)?;
    validate_version(message.version)?;
    validate_server(&message.message)?;
    Ok(message.message)
}

pub fn write_server(writer: &mut impl Write, message: &ServerMessage) -> Result<(), ProtocolError> {
    validate_server(message)?;
    write_frame(writer, &Envelope::new(message))
}

fn validate_client(message: &ClientMessage) -> Result<(), ProtocolError> {
    if let ClientMessage::Start { terminal } = message {
        validate_text(terminal, MAX_TERMINAL_PATH_BYTES, "terminal path")?;
    }
    Ok(())
}

fn validate_server(message: &ServerMessage) -> Result<(), ProtocolError> {
    if let ServerMessage::Event(event) = message {
        validate_text(&event.process_name, MAX_PROCESS_NAME_BYTES, "process name")?;
        if event.payload.is_empty() {
            return Err(ProtocolError::InvalidMessage("capture payload is empty"));
        }
        if event.payload.len() > MAX_CAPTURE_BYTES {
            return Err(ProtocolError::InvalidMessage(
                "capture payload is too large",
            ));
        }
    }
    Ok(())
}

fn validate_version(version: u16) -> Result<(), ProtocolError> {
    if version != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedVersion { found: version });
    }
    Ok(())
}

fn validate_text(value: &str, max_bytes: usize, field: &'static str) -> Result<(), ProtocolError> {
    if value.trim().is_empty() {
        return Err(ProtocolError::InvalidMessage(match field {
            "terminal path" => "terminal path is empty",
            "process name" => "process name is empty",
            _ => "text field is empty",
        }));
    }
    if value.len() > max_bytes {
        return Err(ProtocolError::InvalidMessage(match field {
            "terminal path" => "terminal path is too long",
            "process name" => "process name is too long",
            _ => "text field is too long",
        }));
    }
    Ok(())
}

fn read_frame<T: DeserializeOwned>(reader: &mut impl Read) -> Result<T, ProtocolError> {
    let mut header = [0_u8; 4];
    reader.read_exact(&mut header)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 {
        return Err(ProtocolError::InvalidLength(length));
    }
    if length > MAX_FRAME_BYTES {
        return Err(ProtocolError::Oversized);
    }
    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload)?;
    Ok(serde_json::from_slice(&payload)?)
}

fn write_frame<T: Serialize>(writer: &mut impl Write, value: &T) -> Result<(), ProtocolError> {
    let payload = serde_json::to_vec(value)?;
    if payload.is_empty() {
        return Err(ProtocolError::InvalidLength(0));
    }
    if payload.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::Oversized);
    }
    let length = u32::try_from(payload.len()).map_err(|_| ProtocolError::Oversized)?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(&payload)?;
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn round_trips_bounded_messages() {
        let message = ClientMessage::Start {
            terminal: "/dev/pts/7".to_owned(),
        };
        let mut encoded = Vec::new();
        write_client(&mut encoded, &message).expect("encode");
        assert_eq!(
            read_client(&mut Cursor::new(encoded)).expect("decode"),
            message
        );

        let event = ServerMessage::Event(CapturedOutput {
            pid: 42,
            uid: 1_000,
            requested_len: 4,
            truncated: false,
            process_name: "echo".to_owned(),
            payload: b"test".to_vec(),
        });
        let mut encoded = Vec::new();
        write_server(&mut encoded, &event).expect("encode");
        assert_eq!(
            read_server(&mut Cursor::new(encoded)).expect("decode"),
            event
        );
    }

    #[test]
    fn rejects_oversized_and_unbounded_messages() {
        let mut oversized = Cursor::new(((MAX_FRAME_BYTES + 1) as u32).to_be_bytes());
        assert!(matches!(
            read_client(&mut oversized),
            Err(ProtocolError::Oversized)
        ));

        let event = Envelope::new(ServerMessage::Event(CapturedOutput {
            pid: 1,
            uid: 1_000,
            requested_len: 257,
            truncated: true,
            process_name: "test".to_owned(),
            payload: vec![0; MAX_CAPTURE_BYTES + 1],
        }));
        let payload = serde_json::to_vec(&event).expect("json");
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&payload);
        assert!(matches!(
            read_server(&mut Cursor::new(encoded)),
            Err(ProtocolError::InvalidMessage(
                "capture payload is too large"
            ))
        ));
    }

    #[test]
    fn rejects_unknown_versions_and_empty_event_payloads() {
        let invalid_version = Envelope {
            version: PROTOCOL_VERSION + 1,
            message: ClientMessage::Stop,
        };
        let payload = serde_json::to_vec(&invalid_version).expect("json");
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&payload);
        assert!(matches!(
            read_client(&mut Cursor::new(encoded)),
            Err(ProtocolError::UnsupportedVersion { .. })
        ));

        let empty_event = Envelope::new(ServerMessage::Event(CapturedOutput {
            pid: 1,
            uid: 1_000,
            requested_len: 0,
            truncated: false,
            process_name: "test".to_owned(),
            payload: Vec::new(),
        }));
        let payload = serde_json::to_vec(&empty_event).expect("json");
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&payload);
        assert!(matches!(
            read_server(&mut Cursor::new(encoded)),
            Err(ProtocolError::InvalidMessage("capture payload is empty"))
        ));

        let mut encoded = Vec::new();
        assert!(matches!(
            write_server(&mut encoded, &empty_event.message),
            Err(ProtocolError::InvalidMessage("capture payload is empty"))
        ));
    }
}
