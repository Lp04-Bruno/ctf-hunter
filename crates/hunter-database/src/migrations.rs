use rusqlite::{Connection, Transaction};

use crate::{DatabaseError, Result};

const MIGRATIONS: &[&str] = &[
    include_str!("../migrations/0001_initial.sql"),
    include_str!("../migrations/0002_file_watches.sql"),
    include_str!("../migrations/0003_terminal_sources.sql"),
];

pub fn apply(connection: &mut Connection) -> Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL
        ) STRICT;",
    )?;
    let current: i64 = connection.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
        [],
        |row| row.get(0),
    )?;
    let current = usize::try_from(current).map_err(|_| DatabaseError::Corrupt {
        field: "schema version",
        value: current.to_string(),
    })?;
    if current > MIGRATIONS.len() {
        return Err(DatabaseError::UnsupportedSchema {
            found: current,
            supported: MIGRATIONS.len(),
        });
    }
    for (index, migration) in MIGRATIONS.iter().enumerate().skip(current) {
        apply_one(connection.transaction()?, index + 1, migration)?;
    }
    Ok(())
}

fn apply_one(transaction: Transaction<'_>, version: usize, migration: &str) -> Result<()> {
    transaction.execute_batch(migration)?;
    transaction.execute(
        "INSERT INTO schema_migrations(version, applied_at)
         VALUES (?1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
        [i64::try_from(version).map_err(|_| DatabaseError::Invariant("migration overflow"))?],
    )?;
    transaction.commit()?;
    Ok(())
}
