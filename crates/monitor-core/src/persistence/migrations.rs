use anyhow::Result;
use rusqlite::Connection;

pub fn run_migrations(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "
        PRAGMA journal_mode=WAL;
        PRAGMA foreign_keys=ON;
    ",
    )?;

    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
    ",
    )?;

    let version: i64 = conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
        [],
        |row| row.get(0),
    )?;

    if version < 1 {
        conn.execute_batch(include_str!(
            "../../../../database/migrations/001_initial.sql"
        ))?;
        conn.execute("INSERT INTO schema_migrations (version) VALUES (?1)", [1])?;
    }

    if version < 2 {
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS credentials (
                id TEXT PRIMARY KEY,
                origin TEXT NOT NULL,
                match_key TEXT NOT NULL,
                site_label TEXT,
                encrypted_payload BLOB NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                source TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_credentials_match_key
                ON credentials(match_key);
            ",
        )?;
        conn.execute("INSERT INTO schema_migrations (version) VALUES (?1)", [2])?;
    }

    Ok(())
}
