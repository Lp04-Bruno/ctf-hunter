CREATE TABLE session_watch_directories (
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    directory TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (session_id, directory)
) STRICT;

CREATE INDEX watch_directories_directory
    ON session_watch_directories(directory);
