CREATE TABLE session_terminal_sources (
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    terminal TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (session_id, terminal)
) STRICT;

CREATE INDEX terminal_sources_terminal
    ON session_terminal_sources(terminal);
