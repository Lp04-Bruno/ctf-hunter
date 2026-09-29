mod migrations;

use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use hunter_core::AnalysisReport;
use hunter_types::{
    Candidate, CandidateId, CandidatePath, CaptureEvent, Confidence, EventId, FindingId,
    NotificationSettings, Session, SessionId, SessionStatus, SourceMetadata, Timestamp,
    Transformation, TransformationId,
};
use rusqlite::{Connection, OptionalExtension as _, Transaction, params};
use thiserror::Error;

pub const MAX_STORED_CONTEXT_BYTES: usize = 16 * 1024;
pub const MAX_FINDING_PAGE_SIZE: usize = 100;
pub const MAX_FINDING_DETAIL_OCCURRENCES: usize = 16;

pub type Result<T> = std::result::Result<T, DatabaseError>;

#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error(transparent)]
    Sql(#[from] rusqlite::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("database contains invalid {field}: {value}")]
    Corrupt { field: &'static str, value: String },
    #[error("database schema version {found} is newer than supported version {supported}")]
    UnsupportedSchema { found: usize, supported: usize },
    #[error("analysis report violates persistence invariant: {0}")]
    Invariant(&'static str),
    #[error("finding page size exceeds {MAX_FINDING_PAGE_SIZE}")]
    PageTooLarge,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FindingSummary {
    pub id: FindingId,
    pub session_id: SessionId,
    pub value: String,
    pub confidence: Confidence,
    pub discovered_at: Timestamp,
    pub occurrences: u64,
    pub source: Option<SourceMetadata>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PersistedFinding {
    pub id: FindingId,
    pub created: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransformationStep {
    pub id: TransformationId,
    pub input_candidate_id: CandidateId,
    pub output_candidate_id: CandidateId,
    pub name: String,
    pub applied_at: Timestamp,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FindingOccurrence {
    pub id: i64,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FindingDetail {
    pub summary: FindingSummary,
    pub occurrences: Vec<FindingOccurrence>,
    pub occurrences_truncated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchDirectory {
    pub session_id: SessionId,
    pub directory: PathBuf,
    pub active: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalRegistration {
    pub session_id: SessionId,
    pub terminal: PathBuf,
    pub active: bool,
}

pub struct Database {
    connection: Connection,
}

impl Database {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let mut connection = Connection::open(path)?;
        configure(&connection)?;
        migrations::apply(&mut connection)?;
        Ok(Self { connection })
    }

    pub fn schema_version(&self) -> Result<usize> {
        let version: i64 = self.connection.query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
            [],
            |row| row.get(0),
        )?;
        usize::try_from(version).map_err(|_| DatabaseError::Corrupt {
            field: "schema version",
            value: version.to_string(),
        })
    }

    pub fn notification_settings(&self) -> Result<NotificationSettings> {
        let (enabled, confidence): (bool, String) = self.connection.query_row(
            "SELECT enabled, minimum_confidence FROM notification_settings WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        Ok(NotificationSettings {
            enabled,
            minimum_confidence: parse_confidence(&confidence)?,
        })
    }

    pub fn save_notification_settings(&self, settings: NotificationSettings) -> Result<()> {
        self.connection.execute(
            "UPDATE notification_settings SET enabled = ?1, minimum_confidence = ?2 WHERE id = 1",
            params![
                settings.enabled,
                confidence_name(settings.minimum_confidence)
            ],
        )?;
        Ok(())
    }

    pub fn journal_mode(&self) -> Result<String> {
        Ok(self
            .connection
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))?)
    }

    pub fn save_session(&mut self, session: &Session) -> Result<()> {
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO sessions(id, name, created_at, started_at, finished_at, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(id) DO UPDATE SET
                 name = excluded.name,
                 created_at = excluded.created_at,
                 started_at = excluded.started_at,
                 finished_at = excluded.finished_at,
                 status = excluded.status",
            params![
                session.id().to_string(),
                session.name(),
                session.created_at().to_string(),
                session.started_at().map(|value| value.to_string()),
                session.finished_at().map(|value| value.to_string()),
                status_name(session.status()),
            ],
        )?;
        transaction.execute(
            "DELETE FROM session_patterns WHERE session_id = ?1",
            [session.id().to_string()],
        )?;
        for (ordinal, pattern) in session.flag_patterns().iter().enumerate() {
            transaction.execute(
                "INSERT INTO session_patterns(session_id, ordinal, pattern)
                 VALUES (?1, ?2, ?3)",
                params![session.id().to_string(), sql_usize(ordinal)?, pattern],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn get_session(&self, id: SessionId) -> Result<Option<Session>> {
        let raw = self
            .connection
            .query_row(
                "SELECT name, created_at, started_at, finished_at, status
                 FROM sessions WHERE id = ?1",
                [id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            )
            .optional()?;
        let Some((name, created_at, started_at, finished_at, status)) = raw else {
            return Ok(None);
        };
        let mut statement = self.connection.prepare(
            "SELECT pattern FROM session_patterns WHERE session_id = ?1 ORDER BY ordinal",
        )?;
        let patterns = statement
            .query_map([id.to_string()], |row| row.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let value = serde_json::json!({
            "id": id,
            "name": name,
            "created_at": created_at,
            "started_at": started_at,
            "finished_at": finished_at,
            "status": status,
            "flag_patterns": patterns,
        });
        Ok(Some(serde_json::from_value(value)?))
    }

    pub fn list_sessions(&self) -> Result<Vec<Session>> {
        let mut statement = self
            .connection
            .prepare("SELECT id FROM sessions ORDER BY created_at DESC, id DESC")?;
        let raw_ids = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(statement);

        raw_ids
            .into_iter()
            .map(|raw_id| {
                let id = parse_id(&raw_id, "session id")?;
                self.get_session(id)?.ok_or(DatabaseError::Invariant(
                    "session disappeared while listing sessions",
                ))
            })
            .collect()
    }

    pub fn add_watch_directory(&self, session_id: SessionId, directory: &Path) -> Result<bool> {
        let directory = directory.to_str().ok_or(DatabaseError::Invariant(
            "watch directory is not valid UTF-8",
        ))?;
        Ok(self.connection.execute(
            "INSERT OR IGNORE INTO session_watch_directories(session_id, directory, created_at)
             VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
            params![session_id.to_string(), directory],
        )? == 1)
    }

    pub fn remove_watch_directory(&self, session_id: SessionId, directory: &Path) -> Result<bool> {
        let directory = directory.to_str().ok_or(DatabaseError::Invariant(
            "watch directory is not valid UTF-8",
        ))?;
        Ok(self.connection.execute(
            "DELETE FROM session_watch_directories WHERE session_id = ?1 AND directory = ?2",
            params![session_id.to_string(), directory],
        )? == 1)
    }

    pub fn list_watch_directories(&self, session_id: SessionId) -> Result<Vec<PathBuf>> {
        let mut statement = self.connection.prepare(
            "SELECT directory FROM session_watch_directories
             WHERE session_id = ?1 ORDER BY directory",
        )?;
        Ok(statement
            .query_map([session_id.to_string()], |row| {
                row.get::<_, String>(0).map(PathBuf::from)
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn all_watch_directories(&self) -> Result<Vec<WatchDirectory>> {
        let mut statement = self.connection.prepare(
            "SELECT w.session_id, w.directory, s.status
             FROM session_watch_directories w
             JOIN sessions s ON s.id = w.session_id
             ORDER BY w.directory, w.session_id",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|(session_id, directory, status)| {
                if !matches!(
                    status.as_str(),
                    "inactive" | "monitoring" | "paused" | "finished"
                ) {
                    return Err(DatabaseError::Corrupt {
                        field: "session status",
                        value: status,
                    });
                }
                Ok(WatchDirectory {
                    session_id: parse_id(&session_id, "session id")?,
                    directory: PathBuf::from(directory),
                    active: status == "monitoring",
                })
            })
            .collect()
    }

    pub fn add_terminal(&self, session_id: SessionId, terminal: &Path) -> Result<bool> {
        let terminal = terminal
            .to_str()
            .ok_or(DatabaseError::Invariant("terminal path is not valid UTF-8"))?;
        Ok(self.connection.execute(
            "INSERT OR IGNORE INTO session_terminal_sources(session_id, terminal, created_at)
             VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
            params![session_id.to_string(), terminal],
        )? == 1)
    }

    pub fn remove_terminal(&self, session_id: SessionId, terminal: &Path) -> Result<bool> {
        let terminal = terminal
            .to_str()
            .ok_or(DatabaseError::Invariant("terminal path is not valid UTF-8"))?;
        Ok(self.connection.execute(
            "DELETE FROM session_terminal_sources WHERE session_id = ?1 AND terminal = ?2",
            params![session_id.to_string(), terminal],
        )? == 1)
    }

    pub fn list_terminals(&self, session_id: SessionId) -> Result<Vec<PathBuf>> {
        let mut statement = self.connection.prepare(
            "SELECT terminal FROM session_terminal_sources
             WHERE session_id = ?1 ORDER BY terminal",
        )?;
        Ok(statement
            .query_map([session_id.to_string()], |row| {
                row.get::<_, String>(0).map(PathBuf::from)
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn all_terminals(&self) -> Result<Vec<TerminalRegistration>> {
        let mut statement = self.connection.prepare(
            "SELECT t.session_id, t.terminal, s.status
             FROM session_terminal_sources t
             JOIN sessions s ON s.id = t.session_id
             ORDER BY t.terminal, t.session_id",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|(session_id, terminal, status)| {
                if !matches!(
                    status.as_str(),
                    "inactive" | "monitoring" | "paused" | "finished"
                ) {
                    return Err(DatabaseError::Corrupt {
                        field: "session status",
                        value: status,
                    });
                }
                Ok(TerminalRegistration {
                    session_id: parse_id(&session_id, "session id")?,
                    terminal: PathBuf::from(terminal),
                    active: status == "monitoring",
                })
            })
            .collect()
    }

    pub fn persist_analysis(
        &mut self,
        event: &CaptureEvent,
        report: &AnalysisReport,
    ) -> Result<Vec<FindingId>> {
        Ok(self
            .persist_analysis_with_outcomes(event, report)?
            .into_iter()
            .map(|finding| finding.id)
            .collect())
    }

    pub fn persist_analysis_with_outcomes(
        &mut self,
        event: &CaptureEvent,
        report: &AnalysisReport,
    ) -> Result<Vec<PersistedFinding>> {
        if report.findings().is_empty() {
            return Ok(Vec::new());
        }
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO source_events(id, session_id, captured_at, source_json)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                event.id().to_string(),
                event.session_id().to_string(),
                event.captured_at().to_string(),
                serde_json::to_string(event.source())?,
            ],
        )?;

        let candidates: HashMap<_, _> = report
            .candidates()
            .iter()
            .map(|candidate| (candidate.id(), candidate))
            .collect();
        let transformations: HashMap<_, _> = report
            .transformations()
            .iter()
            .map(|transformation| (transformation.id(), transformation))
            .collect();
        let mut candidate_ids = HashSet::new();
        let mut transformation_ids = HashSet::new();
        for finding in report.findings() {
            candidate_ids.insert(finding.candidate_id());
            for id in finding.transformation_ids() {
                let transformation = transformations.get(id).ok_or(DatabaseError::Invariant(
                    "finding references missing transformation",
                ))?;
                transformation_ids.insert(*id);
                candidate_ids.insert(transformation.input_candidate_id());
                candidate_ids.insert(transformation.output_candidate_id());
            }
        }
        for id in &candidate_ids {
            let candidate = candidates.get(id).ok_or(DatabaseError::Invariant(
                "finding references missing candidate",
            ))?;
            insert_candidate(&transaction, candidate)?;
        }
        for id in &transformation_ids {
            insert_transformation(
                &transaction,
                transformations
                    .get(id)
                    .ok_or(DatabaseError::Invariant("missing transformation"))?,
            )?;
        }

        let mut stored_ids = Vec::with_capacity(report.findings().len());
        for finding in report.findings() {
            let stored = upsert_finding(&transaction, finding)?;
            transaction.execute(
                "INSERT INTO finding_occurrences(
                    finding_id, source_event_id, candidate_id, path_json, observed_at,
                    occurrence_count
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    stored.id.to_string(),
                    event.id().to_string(),
                    finding.candidate_id().to_string(),
                    serde_json::to_string(finding.path())?,
                    finding.discovered_at().to_string(),
                    sql_u64(finding.occurrences().get())?,
                ],
            )?;
            let occurrence_id = transaction.last_insert_rowid();
            for (ordinal, transformation_id) in finding.transformation_ids().iter().enumerate() {
                transaction.execute(
                    "INSERT INTO occurrence_transformations(
                        occurrence_id, ordinal, transformation_id
                     ) VALUES (?1, ?2, ?3)",
                    params![
                        occurrence_id,
                        sql_usize(ordinal)?,
                        transformation_id.to_string()
                    ],
                )?;
            }
            stored_ids.push(stored);
        }
        transaction.commit()?;
        Ok(stored_ids)
    }

    pub fn list_findings(
        &self,
        session_id: SessionId,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<FindingSummary>> {
        if limit > MAX_FINDING_PAGE_SIZE {
            return Err(DatabaseError::PageTooLarge);
        }
        let mut statement = self.connection.prepare(
            "SELECT f.id, f.session_id, f.value, f.confidence, f.discovered_at,
                    COALESCE(SUM(o.occurrence_count), 0),
                    (SELECT e.source_json
                     FROM finding_occurrences latest
                     JOIN source_events e ON e.id = latest.source_event_id
                     WHERE latest.finding_id = f.id
                     ORDER BY latest.id DESC LIMIT 1)
             FROM findings f
             LEFT JOIN finding_occurrences o ON o.finding_id = f.id
             WHERE f.session_id = ?1
             GROUP BY f.id
             ORDER BY f.discovered_at DESC, f.id
             LIMIT ?2 OFFSET ?3",
        )?;
        let rows = statement
            .query_map(
                params![
                    session_id.to_string(),
                    sql_usize(limit)?,
                    sql_usize(offset)?
                ],
                |row| {
                    Ok(RawFindingSummary {
                        id: row.get(0)?,
                        session_id: row.get(1)?,
                        value: row.get(2)?,
                        confidence: row.get(3)?,
                        discovered_at: row.get(4)?,
                        occurrences: row.get(5)?,
                        source_json: row.get(6)?,
                    })
                },
            )?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        rows.into_iter().map(parse_summary).collect()
    }

    pub fn get_finding(&self, finding_id: FindingId) -> Result<Option<FindingDetail>> {
        let summary = self
            .connection
            .query_row(
                "SELECT f.id, f.session_id, f.value, f.confidence, f.discovered_at,
                        COALESCE(SUM(o.occurrence_count), 0),
                        (SELECT e.source_json
                         FROM finding_occurrences latest
                         JOIN source_events e ON e.id = latest.source_event_id
                         WHERE latest.finding_id = f.id
                         ORDER BY latest.id DESC LIMIT 1)
                 FROM findings f
                 LEFT JOIN finding_occurrences o ON o.finding_id = f.id
                 WHERE f.id = ?1 GROUP BY f.id",
                [finding_id.to_string()],
                |row| {
                    Ok(RawFindingSummary {
                        id: row.get(0)?,
                        session_id: row.get(1)?,
                        value: row.get(2)?,
                        confidence: row.get(3)?,
                        discovered_at: row.get(4)?,
                        occurrences: row.get(5)?,
                        source_json: row.get(6)?,
                    })
                },
            )
            .optional()?;
        let Some(summary) = summary else {
            return Ok(None);
        };
        let summary = parse_summary(summary)?;
        let mut statement = self.connection.prepare(
            "SELECT o.id, o.source_event_id, o.candidate_id, o.path_json, o.observed_at,
                    o.occurrence_count, e.source_json, c.data, c.original_length, c.truncated
             FROM finding_occurrences o
             JOIN source_events e ON e.id = o.source_event_id
             JOIN candidates c ON c.id = o.candidate_id
             WHERE o.finding_id = ?1 ORDER BY o.id
             LIMIT ?2",
        )?;
        let mut raw = statement
            .query_map(
                params![
                    finding_id.to_string(),
                    sql_usize(MAX_FINDING_DETAIL_OCCURRENCES + 1)?
                ],
                |row| {
                    Ok(RawOccurrence {
                        id: row.get(0)?,
                        event_id: row.get(1)?,
                        candidate_id: row.get(2)?,
                        path_json: row.get(3)?,
                        observed_at: row.get(4)?,
                        count: row.get(5)?,
                        source_json: row.get(6)?,
                        candidate_data: row.get(7)?,
                        candidate_original_length: row.get(8)?,
                        candidate_truncated: row.get(9)?,
                    })
                },
            )?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let occurrences_truncated = raw.len() > MAX_FINDING_DETAIL_OCCURRENCES;
        raw.truncate(MAX_FINDING_DETAIL_OCCURRENCES);
        let mut occurrences = Vec::with_capacity(raw.len());
        for raw in raw {
            occurrences.push(self.parse_occurrence(raw)?);
        }
        Ok(Some(FindingDetail {
            summary,
            occurrences,
            occurrences_truncated,
        }))
    }

    fn parse_occurrence(&self, raw: RawOccurrence) -> Result<FindingOccurrence> {
        let mut statement = self.connection.prepare(
            "SELECT t.id, t.input_candidate_id, t.output_candidate_id, t.name, t.applied_at
             FROM occurrence_transformations ot
             JOIN transformations t ON t.id = ot.transformation_id
             WHERE ot.occurrence_id = ?1 ORDER BY ot.ordinal",
        )?;
        let steps = statement
            .query_map([raw.id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let transformations = steps
            .into_iter()
            .map(|(id, input, output, name, applied_at)| {
                Ok(TransformationStep {
                    id: parse_id(&id, "transformation id")?,
                    input_candidate_id: parse_id(&input, "input candidate id")?,
                    output_candidate_id: parse_id(&output, "output candidate id")?,
                    name,
                    applied_at: parse_timestamp(&applied_at, "transformation timestamp")?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(FindingOccurrence {
            id: raw.id,
            source_event_id: parse_id(&raw.event_id, "event id")?,
            candidate_id: parse_id(&raw.candidate_id, "candidate id")?,
            path: serde_json::from_str(&raw.path_json)?,
            observed_at: parse_timestamp(&raw.observed_at, "occurrence timestamp")?,
            count: u64::try_from(raw.count).map_err(|_| DatabaseError::Corrupt {
                field: "occurrence count",
                value: raw.count.to_string(),
            })?,
            source: serde_json::from_str(&raw.source_json)?,
            candidate_text: String::from_utf8(raw.candidate_data).ok(),
            candidate_original_length: usize::try_from(raw.candidate_original_length).map_err(
                |_| DatabaseError::Corrupt {
                    field: "candidate original length",
                    value: raw.candidate_original_length.to_string(),
                },
            )?,
            candidate_truncated: raw.candidate_truncated,
            transformations,
        })
    }
}

fn configure(connection: &Connection) -> Result<()> {
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "synchronous", "NORMAL")?;
    Ok(())
}

fn insert_candidate(transaction: &Transaction<'_>, candidate: &Candidate) -> Result<()> {
    let data = candidate.data().as_bytes();
    let stored_length = data.len().min(MAX_STORED_CONTEXT_BYTES);
    transaction.execute(
        "INSERT INTO candidates(
            id, source_event_id, parent_candidate_id, path_json, data, original_length,
            truncated, depth
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            candidate.id().to_string(),
            candidate.source_event_id().to_string(),
            candidate.parent_candidate_id().map(|id| id.to_string()),
            serde_json::to_string(candidate.path())?,
            &data[..stored_length],
            sql_usize(data.len())?,
            i64::from(data.len() > stored_length),
            candidate.depth(),
        ],
    )?;
    Ok(())
}

fn insert_transformation(
    transaction: &Transaction<'_>,
    transformation: &Transformation,
) -> Result<()> {
    transaction.execute(
        "INSERT INTO transformations(
            id, input_candidate_id, output_candidate_id, name, applied_at
         ) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            transformation.id().to_string(),
            transformation.input_candidate_id().to_string(),
            transformation.output_candidate_id().to_string(),
            transformation.name().as_str(),
            transformation.applied_at().to_string(),
        ],
    )?;
    Ok(())
}

fn upsert_finding(
    transaction: &Transaction<'_>,
    finding: &hunter_types::FlagFinding,
) -> Result<PersistedFinding> {
    let existing = transaction
        .query_row(
            "SELECT id, confidence FROM findings WHERE session_id = ?1 AND value = ?2",
            params![finding.session_id().to_string(), finding.value().as_str()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    if let Some((id, confidence)) = existing {
        if confidence_rank(finding.confidence()) > confidence_name_rank(&confidence)? {
            transaction.execute(
                "UPDATE findings SET confidence = ?1 WHERE id = ?2",
                params![confidence_name(finding.confidence()), id],
            )?;
        }
        return Ok(PersistedFinding {
            id: parse_id(&id, "finding id")?,
            created: false,
        });
    }
    transaction.execute(
        "INSERT INTO findings(id, session_id, value, confidence, discovered_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            finding.id().to_string(),
            finding.session_id().to_string(),
            finding.value().as_str(),
            confidence_name(finding.confidence()),
            finding.discovered_at().to_string(),
        ],
    )?;
    Ok(PersistedFinding {
        id: finding.id(),
        created: true,
    })
}

struct RawFindingSummary {
    id: String,
    session_id: String,
    value: String,
    confidence: String,
    discovered_at: String,
    occurrences: i64,
    source_json: Option<String>,
}

fn parse_summary(raw: RawFindingSummary) -> Result<FindingSummary> {
    Ok(FindingSummary {
        id: parse_id(&raw.id, "finding id")?,
        session_id: parse_id(&raw.session_id, "session id")?,
        value: raw.value,
        confidence: parse_confidence(&raw.confidence)?,
        discovered_at: parse_timestamp(&raw.discovered_at, "finding timestamp")?,
        occurrences: u64::try_from(raw.occurrences).map_err(|_| DatabaseError::Corrupt {
            field: "finding occurrence count",
            value: raw.occurrences.to_string(),
        })?,
        source: raw
            .source_json
            .map(|value| serde_json::from_str(&value))
            .transpose()?,
    })
}

struct RawOccurrence {
    id: i64,
    event_id: String,
    candidate_id: String,
    path_json: String,
    observed_at: String,
    count: i64,
    source_json: String,
    candidate_data: Vec<u8>,
    candidate_original_length: i64,
    candidate_truncated: bool,
}

fn parse_id<T>(value: &str, field: &'static str) -> Result<T>
where
    T: FromStr,
{
    value.parse().map_err(|_| DatabaseError::Corrupt {
        field,
        value: value.to_owned(),
    })
}

fn parse_timestamp(value: &str, field: &'static str) -> Result<Timestamp> {
    value.parse().map_err(|_| DatabaseError::Corrupt {
        field,
        value: value.to_owned(),
    })
}

const fn status_name(status: SessionStatus) -> &'static str {
    match status {
        SessionStatus::Inactive => "inactive",
        SessionStatus::Monitoring => "monitoring",
        SessionStatus::Paused => "paused",
        SessionStatus::Finished => "finished",
    }
}

const fn confidence_name(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Low => "low",
        Confidence::Medium => "medium",
        Confidence::High => "high",
        Confidence::VeryHigh => "very_high",
    }
}

fn parse_confidence(value: &str) -> Result<Confidence> {
    match value {
        "low" => Ok(Confidence::Low),
        "medium" => Ok(Confidence::Medium),
        "high" => Ok(Confidence::High),
        "very_high" => Ok(Confidence::VeryHigh),
        _ => Err(DatabaseError::Corrupt {
            field: "confidence",
            value: value.to_owned(),
        }),
    }
}

const fn confidence_rank(value: Confidence) -> u8 {
    match value {
        Confidence::Low => 0,
        Confidence::Medium => 1,
        Confidence::High => 2,
        Confidence::VeryHigh => 3,
    }
}

fn confidence_name_rank(value: &str) -> Result<u8> {
    Ok(confidence_rank(parse_confidence(value)?))
}

fn sql_usize(value: usize) -> Result<i64> {
    i64::try_from(value).map_err(|_| DatabaseError::Invariant("integer overflow"))
}

fn sql_u64(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| DatabaseError::Invariant("integer overflow"))
}

#[cfg(test)]
mod tests {
    use hunter_core::{AnalysisConfig, Analyzer};
    use hunter_flags::FlagPattern;
    use hunter_types::{EventPayload, SourceMetadata};
    use tempfile::tempdir;

    use super::*;

    fn session() -> Session {
        let created = Timestamp::from_unix_timestamp(1_800_000_000).expect("timestamp");
        let mut session =
            Session::new(SessionId::generate(), "Persistence test", created).expect("session");
        session
            .set_flag_patterns(vec!["FLAG{*}".to_owned()])
            .expect("patterns");
        session.start(created).expect("start");
        session
    }

    fn analyze(session: &Session, payload: &str, timestamp: i64) -> (CaptureEvent, AnalysisReport) {
        let event = CaptureEvent::new(
            EventId::generate(),
            session.id(),
            Timestamp::from_unix_timestamp(timestamp).expect("timestamp"),
            SourceMetadata::Manual,
            EventPayload::new(payload.as_bytes().to_vec()).expect("payload"),
        );
        let analyzer = Analyzer::new(AnalysisConfig::default(), [FlagPattern::simple("FLAG{*}")])
            .expect("analyzer");
        let report = analyzer.analyze(&event).expect("analysis");
        (event, report)
    }

    #[test]
    fn creates_versioned_wal_schema_without_raw_event_payloads() {
        let directory = tempdir().expect("tempdir");
        let database = Database::open(directory.path().join("hunter.db")).expect("database");

        assert_eq!(database.schema_version().expect("version"), 4);
        assert_eq!(database.journal_mode().expect("journal"), "wal");
        let columns = database
            .connection
            .prepare("SELECT name FROM pragma_table_info('source_events')")
            .expect("statement")
            .query_map([], |row| row.get::<_, String>(0))
            .expect("query")
            .collect::<std::result::Result<Vec<_>, _>>()
            .expect("columns");
        assert!(!columns.iter().any(|column| column == "payload"));
    }

    #[test]
    fn notification_settings_are_persistent_and_validated_by_the_schema() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("hunter.db");
        let database = Database::open(&path).expect("database");
        assert_eq!(
            database.notification_settings().expect("default settings"),
            NotificationSettings::default()
        );
        let settings = NotificationSettings {
            enabled: false,
            minimum_confidence: Confidence::VeryHigh,
        };
        database
            .save_notification_settings(settings)
            .expect("save settings");
        drop(database);
        assert_eq!(
            Database::open(&path)
                .expect("reopen")
                .notification_settings()
                .expect("stored settings"),
            settings
        );
    }

    #[test]
    fn analysis_without_findings_does_not_write_source_events() {
        let directory = tempdir().expect("tempdir");
        let mut database = Database::open(directory.path().join("hunter.db")).expect("database");
        let session = session();
        database.save_session(&session).expect("save session");
        let (event, report) = analyze(&session, "ordinary output", 1_800_000_001);
        assert!(
            database
                .persist_analysis(&event, &report)
                .expect("persist")
                .is_empty()
        );
        let count: i64 = database
            .connection
            .query_row("SELECT COUNT(*) FROM source_events", [], |row| row.get(0))
            .expect("count events");
        assert_eq!(count, 0);
    }

    #[test]
    fn lists_sessions_newest_first_with_patterns() {
        let directory = tempdir().expect("tempdir");
        let mut database = Database::open(directory.path().join("hunter.db")).expect("database");
        let mut older = Session::new(
            SessionId::generate(),
            "Older",
            Timestamp::from_unix_timestamp(1_800_000_000).expect("timestamp"),
        )
        .expect("session");
        older
            .set_flag_patterns(vec!["OLD{*}".to_owned()])
            .expect("patterns");
        let newer = Session::new(
            SessionId::generate(),
            "Newer",
            Timestamp::from_unix_timestamp(1_800_000_100).expect("timestamp"),
        )
        .expect("session");
        database.save_session(&older).expect("save older");
        database.save_session(&newer).expect("save newer");

        let sessions = database.list_sessions().expect("list sessions");

        assert_eq!(sessions, vec![newer, older]);
    }

    #[test]
    fn findings_and_provenance_survive_restart_and_deduplicate() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("hunter.db");
        let session = session();
        let first_id = {
            let mut database = Database::open(&path).expect("database");
            database.save_session(&session).expect("save session");
            let (event, report) = analyze(
                &session,
                r#"{"profile":{"payload":"RkxBR3twZXJzaXN0ZWR9"}}"#,
                1_800_000_001,
            );
            let ids = database
                .persist_analysis(&event, &report)
                .expect("persist analysis");
            assert_eq!(ids.len(), 1);
            ids[0]
        };

        let mut reopened = Database::open(&path).expect("reopen");
        assert_eq!(
            reopened.get_session(session.id()).expect("session query"),
            Some(session.clone())
        );
        let detail = reopened
            .get_finding(first_id)
            .expect("query")
            .expect("finding");
        assert_eq!(detail.summary.value, "FLAG{persisted}");
        assert_eq!(detail.summary.occurrences, 1);
        assert_eq!(detail.occurrences[0].path.to_string(), "profile.payload");
        assert_eq!(detail.occurrences[0].transformations.len(), 1);
        assert_eq!(detail.occurrences[0].transformations[0].name, "base64");
        assert!(!detail.occurrences_truncated);

        let (event, report) = analyze(&session, "FLAG{persisted}", 1_800_000_002);
        let ids = reopened
            .persist_analysis(&event, &report)
            .expect("persist duplicate");
        assert_eq!(ids, vec![first_id]);
        let detail = reopened
            .get_finding(first_id)
            .expect("query")
            .expect("finding");
        assert_eq!(detail.summary.occurrences, 2);
        assert_eq!(detail.occurrences.len(), 2);
        assert!(!detail.occurrences_truncated);

        for timestamp in 1_800_000_003..=1_800_000_017 {
            let (event, report) = analyze(&session, "FLAG{persisted}", timestamp);
            reopened
                .persist_analysis(&event, &report)
                .expect("persist occurrence");
        }
        let detail = reopened
            .get_finding(first_id)
            .expect("query")
            .expect("finding");
        assert_eq!(detail.summary.occurrences, 17);
        assert_eq!(detail.occurrences.len(), MAX_FINDING_DETAIL_OCCURRENCES);
        assert!(detail.occurrences_truncated);
    }

    #[test]
    fn rejects_unbounded_pages() {
        let directory = tempdir().expect("tempdir");
        let database = Database::open(directory.path().join("hunter.db")).expect("database");

        assert!(matches!(
            database.list_findings(SessionId::generate(), 0, MAX_FINDING_PAGE_SIZE + 1),
            Err(DatabaseError::PageTooLarge)
        ));
    }

    #[test]
    fn watch_directories_survive_restart_and_follow_session_state() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("hunter.db");
        let watched = directory.path().join("watched");
        std::fs::create_dir(&watched).expect("watch directory");
        let mut session = session();
        session.pause().expect("pause");

        {
            let mut database = Database::open(&path).expect("database");
            database.save_session(&session).expect("save session");
            assert!(
                database
                    .add_watch_directory(session.id(), &watched)
                    .expect("add watch")
            );
            assert!(
                !database
                    .add_watch_directory(session.id(), &watched)
                    .expect("deduplicate watch")
            );
        }

        let database = Database::open(&path).expect("reopen");
        assert_eq!(
            database
                .list_watch_directories(session.id())
                .expect("list watches"),
            vec![watched.clone()]
        );
        assert_eq!(
            database.all_watch_directories().expect("all watches"),
            vec![WatchDirectory {
                session_id: session.id(),
                directory: watched.clone(),
                active: false,
            }]
        );
        assert!(
            database
                .remove_watch_directory(session.id(), &watched)
                .expect("remove watch")
        );
        assert!(
            database
                .list_watch_directories(session.id())
                .expect("empty watches")
                .is_empty()
        );
    }

    #[test]
    fn terminal_sources_survive_restart_and_follow_session_state() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("hunter.db");
        let terminal = PathBuf::from("/dev/pts/7");
        let mut session = session();
        session.pause().expect("pause");

        {
            let mut database = Database::open(&path).expect("database");
            database.save_session(&session).expect("save session");
            assert!(
                database
                    .add_terminal(session.id(), &terminal)
                    .expect("add terminal")
            );
            assert!(
                !database
                    .add_terminal(session.id(), &terminal)
                    .expect("deduplicate terminal")
            );
        }

        let database = Database::open(&path).expect("reopen");
        assert_eq!(
            database
                .list_terminals(session.id())
                .expect("list terminals"),
            vec![terminal.clone()]
        );
        assert_eq!(
            database.all_terminals().expect("all terminals"),
            vec![TerminalRegistration {
                session_id: session.id(),
                terminal: terminal.clone(),
                active: false,
            }]
        );
        assert!(
            database
                .remove_terminal(session.id(), &terminal)
                .expect("remove terminal")
        );
        assert!(
            database
                .list_terminals(session.id())
                .expect("empty terminals")
                .is_empty()
        );
    }

    #[test]
    fn rejects_a_schema_newer_than_the_binary() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("hunter.db");
        let database = Database::open(&path).expect("database");
        database
            .connection
            .execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (5, 'now')",
                [],
            )
            .expect("future migration");
        drop(database);

        assert!(matches!(
            Database::open(&path),
            Err(DatabaseError::UnsupportedSchema {
                found: 5,
                supported: 4
            })
        ));
    }
}
