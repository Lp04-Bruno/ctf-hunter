use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{ValidationError, validation::validate_text};

const MAX_PROCESS_NAME_BYTES: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
struct ProcessName(String);

impl ProcessName {
    fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        validate_text(&value, "process name", MAX_PROCESS_NAME_BYTES)?;
        Ok(Self(value))
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ProcessName {
    type Error = ValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ProcessName> for String {
    fn from(value: ProcessName) -> Self {
        value.0
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "PathBuf", into = "PathBuf")]
pub struct SourcePath(PathBuf);

impl SourcePath {
    pub fn new(value: impl Into<PathBuf>) -> Result<Self, ValidationError> {
        let value = value.into();
        if value.as_os_str().is_empty() {
            return Err(ValidationError::Empty {
                field: "source path",
            });
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

impl TryFrom<PathBuf> for SourcePath {
    type Error = ValidationError;

    fn try_from(value: PathBuf) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<SourcePath> for PathBuf {
    fn from(value: SourcePath) -> Self {
        value.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TerminalSource {
    process_id: u32,
    user_id: u32,
    file_descriptor: Option<u32>,
    process_name: ProcessName,
    executable: Option<SourcePath>,
    tty: SourcePath,
}

impl TerminalSource {
    pub fn new(
        process_id: u32,
        user_id: u32,
        file_descriptor: Option<u32>,
        process_name: impl Into<String>,
        executable: Option<SourcePath>,
        tty: SourcePath,
    ) -> Result<Self, ValidationError> {
        let process_name = ProcessName::new(process_name)?;

        Ok(Self {
            process_id,
            user_id,
            file_descriptor,
            process_name,
            executable,
            tty,
        })
    }

    #[must_use]
    pub const fn process_id(&self) -> u32 {
        self.process_id
    }

    #[must_use]
    pub const fn user_id(&self) -> u32 {
        self.user_id
    }

    #[must_use]
    pub const fn file_descriptor(&self) -> Option<u32> {
        self.file_descriptor
    }

    #[must_use]
    pub fn process_name(&self) -> &str {
        self.process_name.as_str()
    }

    #[must_use]
    pub fn executable(&self) -> Option<&Path> {
        self.executable.as_ref().map(SourcePath::as_path)
    }

    #[must_use]
    pub fn tty(&self) -> &Path {
        self.tty.as_path()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FileSource(SourcePath);

impl FileSource {
    #[must_use]
    pub const fn new(path: SourcePath) -> Self {
        Self(path)
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        self.0.as_path()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "details")]
pub enum SourceMetadata {
    Terminal(TerminalSource),
    File(FileSource),
    Manual,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_source_round_trips_with_process_metadata() {
        let source = SourceMetadata::Terminal(
            TerminalSource::new(
                42,
                1000,
                Some(1),
                "curl",
                Some(SourcePath::new("/usr/bin/curl").expect("valid path")),
                SourcePath::new("/dev/pts/3").expect("valid path"),
            )
            .expect("valid terminal source"),
        );

        let encoded = serde_json::to_string(&source).expect("source should serialize");
        let decoded = serde_json::from_str(&encoded).expect("source should deserialize");

        assert_eq!(source, decoded);
    }

    #[test]
    fn empty_source_paths_are_rejected() {
        assert_eq!(
            SourcePath::new(PathBuf::new()),
            Err(ValidationError::Empty {
                field: "source path"
            })
        );
    }

    #[test]
    fn terminal_source_deserialization_rejects_empty_process_names() {
        let value = serde_json::json!({
            "process_id": 42,
            "user_id": 1000,
            "file_descriptor": 1,
            "process_name": "  ",
            "executable": null,
            "tty": "/dev/pts/3"
        });

        let error = serde_json::from_value::<TerminalSource>(value)
            .expect_err("empty process name should fail");
        assert!(error.to_string().contains("must not be empty"));
    }
}
