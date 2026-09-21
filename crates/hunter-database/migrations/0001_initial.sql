CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    status TEXT NOT NULL CHECK (status IN ('inactive', 'monitoring', 'paused', 'finished'))
) STRICT;

CREATE TABLE session_patterns (
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    pattern TEXT NOT NULL,
    PRIMARY KEY (session_id, ordinal),
    UNIQUE (session_id, pattern)
) STRICT;

CREATE TABLE source_events (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    captured_at TEXT NOT NULL,
    source_json TEXT NOT NULL
) STRICT;

CREATE TABLE candidates (
    id TEXT PRIMARY KEY,
    source_event_id TEXT NOT NULL REFERENCES source_events(id) ON DELETE CASCADE,
    parent_candidate_id TEXT,
    path_json TEXT NOT NULL,
    data BLOB NOT NULL,
    original_length INTEGER NOT NULL CHECK (original_length > 0),
    truncated INTEGER NOT NULL CHECK (truncated IN (0, 1)),
    depth INTEGER NOT NULL CHECK (depth >= 0)
) STRICT;

CREATE TABLE transformations (
    id TEXT PRIMARY KEY,
    input_candidate_id TEXT NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
    output_candidate_id TEXT NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    applied_at TEXT NOT NULL
) STRICT;

CREATE TABLE findings (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    value TEXT NOT NULL,
    confidence TEXT NOT NULL CHECK (confidence IN ('low', 'medium', 'high', 'very_high')),
    discovered_at TEXT NOT NULL,
    UNIQUE (session_id, value)
) STRICT;

CREATE TABLE finding_occurrences (
    id INTEGER PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    source_event_id TEXT NOT NULL REFERENCES source_events(id) ON DELETE CASCADE,
    candidate_id TEXT NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
    path_json TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    occurrence_count INTEGER NOT NULL CHECK (occurrence_count > 0)
) STRICT;

CREATE TABLE occurrence_transformations (
    occurrence_id INTEGER NOT NULL REFERENCES finding_occurrences(id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    transformation_id TEXT NOT NULL REFERENCES transformations(id) ON DELETE CASCADE,
    PRIMARY KEY (occurrence_id, ordinal)
) STRICT;

CREATE INDEX findings_session_discovered
    ON findings(session_id, discovered_at DESC);
CREATE INDEX occurrences_finding
    ON finding_occurrences(finding_id, id);
