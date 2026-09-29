CREATE TABLE notification_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    minimum_confidence TEXT NOT NULL CHECK (
        minimum_confidence IN ('low', 'medium', 'high', 'very_high')
    )
) STRICT;

INSERT INTO notification_settings(id, enabled, minimum_confidence)
VALUES (1, 1, 'high');
