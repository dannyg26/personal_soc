use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use rusqlite::{params, Connection};
use std::path::Path;
use std::sync::{Arc, Mutex};

use shared_types::models::{
    AiConversation, Alert, AlertStatus, PathCategory, ProcessMetric, ProcessRecord, ProcessStatus,
    Severity, SignerStatus, StartupEntry, StartupLocationType, TrustRule, UserAction,
};

/// A row in the unified activity/events timeline.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ActivityEvent {
    pub event_type: String,
    pub id: String,
    pub timestamp: String,
    pub title: String,
    pub description: String,
    pub severity: String,
    pub related_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CredentialRecord {
    pub id: String,
    pub origin: String,
    pub match_key: String,
    pub site_label: Option<String>,
    pub encrypted_payload: Vec<u8>,
    pub created_at: String,
    pub updated_at: String,
    pub source: String,
}

pub struct Database {
    conn: Arc<Mutex<Connection>>,
}

impl Database {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        super::migrations::run_migrations(&conn)?;
        // Settings table — added after initial migration, safe to create here
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );",
        )?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        super::migrations::run_migrations(&conn)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );",
        )?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    // ---- Settings ----

    pub fn get_setting(&self, key: &str) -> Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT value FROM settings WHERE key = ?1")?;
        let mut rows = stmt.query(params![key])?;
        Ok(rows.next()?.map(|r| r.get(0)).transpose()?)
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    // ---- Cleanup ----

    /// Delete terminated processes (and their metrics) last seen more than `older_than_hours` hours ago.
    /// Returns the number of process rows deleted.
    pub fn cleanup_old_processes(&self, older_than_hours: u32) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        let cutoff = Utc::now() - chrono::Duration::hours(older_than_hours as i64);
        let cutoff_str = cutoff.to_rfc3339();
        // Delete metrics for terminated processes older than cutoff
        conn.execute(
            "DELETE FROM process_metrics WHERE process_id IN (
                SELECT id FROM processes
                WHERE current_status = 'Terminated' AND last_seen_at < ?1
            )",
            params![cutoff_str],
        )?;
        // Delete the processes themselves
        let deleted = conn.execute(
            "DELETE FROM processes WHERE current_status = 'Terminated' AND last_seen_at < ?1",
            params![cutoff_str],
        )?;
        Ok(deleted)
    }

    // ---- Credential Vault ----

    pub fn insert_credential(&self, record: &CredentialRecord) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO credentials (
                id, origin, match_key, site_label, encrypted_payload, created_at, updated_at, source
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                record.id,
                record.origin,
                record.match_key,
                record.site_label,
                record.encrypted_payload,
                record.created_at,
                record.updated_at,
                record.source,
            ],
        )?;
        Ok(())
    }

    pub fn update_credential(&self, record: &CredentialRecord) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE credentials
             SET origin = ?1,
                 match_key = ?2,
                 site_label = ?3,
                 encrypted_payload = ?4,
                 updated_at = ?5,
                 source = ?6
             WHERE id = ?7",
            params![
                record.origin,
                record.match_key,
                record.site_label,
                record.encrypted_payload,
                record.updated_at,
                record.source,
                record.id,
            ],
        )?;
        Ok(())
    }

    pub fn list_credentials(&self) -> Result<Vec<CredentialRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, origin, match_key, site_label, encrypted_payload, created_at, updated_at, source
             FROM credentials
             ORDER BY updated_at DESC",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(CredentialRecord {
                id: row.get(0)?,
                origin: row.get(1)?,
                match_key: row.get(2)?,
                site_label: row.get(3)?,
                encrypted_payload: row.get(4)?,
                created_at: row.get(5)?,
                updated_at: row.get(6)?,
                source: row.get(7)?,
            })
        })?;

        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn list_credentials_by_match_key(&self, match_key: &str) -> Result<Vec<CredentialRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, origin, match_key, site_label, encrypted_payload, created_at, updated_at, source
             FROM credentials
             WHERE match_key = ?1
             ORDER BY updated_at DESC",
        )?;

        let rows = stmt.query_map([match_key], |row| {
            Ok(CredentialRecord {
                id: row.get(0)?,
                origin: row.get(1)?,
                match_key: row.get(2)?,
                site_label: row.get(3)?,
                encrypted_payload: row.get(4)?,
                created_at: row.get(5)?,
                updated_at: row.get(6)?,
                source: row.get(7)?,
            })
        })?;

        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn delete_credential(&self, id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM credentials WHERE id = ?1", params![id])?;
        Ok(())
    }

    // ---- Processes ----

    pub fn upsert_process(&self, p: &ProcessRecord) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO processes (id, pid, parent_pid, name, exe_path, command_line, signer_status,
             file_hash, first_seen_at, last_seen_at, user_name, integrity_level, current_status, risk_score, path_category)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)
             ON CONFLICT(id) DO UPDATE SET
               last_seen_at=excluded.last_seen_at,
               current_status=excluded.current_status,
               risk_score=excluded.risk_score,
               cpu_percent=excluded.cpu_percent,
               memory_bytes=excluded.memory_bytes",
            params![
                p.id,
                p.pid,
                p.parent_pid,
                p.name,
                p.exe_path,
                p.command_line,
                format!("{:?}", p.signer_status),
                p.file_hash,
                p.first_seen_at.to_rfc3339(),
                p.last_seen_at.to_rfc3339(),
                p.user_name,
                p.integrity_level,
                format!("{:?}", p.current_status),
                p.risk_score,
                format!("{:?}", p.path_category),
            ],
        )?;
        Ok(())
    }

    pub fn list_processes(&self) -> Result<Vec<ProcessRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, pid, parent_pid, name, exe_path, command_line, signer_status,
             file_hash, first_seen_at, last_seen_at, user_name, integrity_level, current_status,
             risk_score, path_category FROM processes WHERE current_status != 'Terminated'
             ORDER BY risk_score DESC, name ASC",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(ProcessRecord {
                id: row.get(0)?,
                pid: row.get(1)?,
                parent_pid: row.get(2)?,
                name: row.get(3)?,
                exe_path: row.get(4)?,
                command_line: row.get(5)?,
                signer_status: parse_signer_status(&row.get::<_, String>(6)?),
                file_hash: row.get(7)?,
                first_seen_at: parse_datetime(&row.get::<_, String>(8)?),
                last_seen_at: parse_datetime(&row.get::<_, String>(9)?),
                user_name: row.get(10)?,
                integrity_level: row.get(11)?,
                current_status: parse_process_status(&row.get::<_, String>(12)?),
                risk_score: row.get(13)?,
                path_category: parse_path_category(&row.get::<_, String>(14)?),
            })
        })?;

        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    /// Server-side paged query with optional search, status filter, sort, and pagination.
    /// Returns (rows, total_matching_count).
    pub fn list_processes_paged(
        &self,
        search: &str,
        status_filter: &str,
        sort_key: &str,
        sort_asc: bool,
        limit: u32,
        offset: u32,
    ) -> Result<(Vec<ProcessRecord>, u32)> {
        // Whitelist sort column to prevent SQL injection
        let sort_col = match sort_key {
            "pid" => "pid",
            "name" => "name",
            "current_status" => "current_status",
            "risk_score" => "risk_score",
            "signer_status" => "signer_status",
            "first_seen_at" => "first_seen_at",
            "last_seen_at" => "last_seen_at",
            _ => "first_seen_at",
        };
        let sort_dir = if sort_asc { "ASC" } else { "DESC" };
        // Empty string disables search; pass "%term%" to enable LIKE
        let search_pattern = if search.is_empty() {
            String::new()
        } else {
            format!("%{}%", search)
        };

        // "AtRisk" is a virtual filter: risk_score >= 25, non-Terminated only.
        // It uses its own WHERE clause with different param indices to avoid conflicts.
        let at_risk = status_filter == "AtRisk";

        let conn = self.conn.lock().unwrap();

        let cols = "id, pid, parent_pid, name, exe_path, command_line, signer_status,
             file_hash, first_seen_at, last_seen_at, user_name, integrity_level, current_status,
             risk_score, path_category";

        let map_row = |row: &rusqlite::Row<'_>| -> rusqlite::Result<ProcessRecord> {
            Ok(ProcessRecord {
                id: row.get(0)?,
                pid: row.get(1)?,
                parent_pid: row.get(2)?,
                name: row.get(3)?,
                exe_path: row.get(4)?,
                command_line: row.get(5)?,
                signer_status: parse_signer_status(&row.get::<_, String>(6)?),
                file_hash: row.get(7)?,
                first_seen_at: parse_datetime(&row.get::<_, String>(8)?),
                last_seen_at: parse_datetime(&row.get::<_, String>(9)?),
                user_name: row.get(10)?,
                integrity_level: row.get(11)?,
                current_status: parse_process_status(&row.get::<_, String>(12)?),
                risk_score: row.get(13)?,
                path_category: parse_path_category(&row.get::<_, String>(14)?),
            })
        };

        let total: u32;
        let records: Vec<ProcessRecord>;

        if at_risk {
            // ?1 = search_pattern, ?2 = limit, ?3 = offset
            let where_clause = "WHERE risk_score >= 25
              AND current_status != 'Terminated'
              AND (?1 = '' OR name LIKE ?1 OR CAST(pid AS TEXT) LIKE ?1 OR COALESCE(exe_path,'') LIKE ?1)";

            total = conn.query_row(
                &format!("SELECT COUNT(*) FROM processes {}", where_clause),
                params![search_pattern],
                |row| row.get(0),
            )?;

            let data_sql = format!(
                "SELECT {} FROM processes {} ORDER BY {} {} LIMIT ?2 OFFSET ?3",
                cols, where_clause, sort_col, sort_dir
            );
            let mut stmt = conn.prepare(&data_sql)?;
            records = stmt
                .query_map(params![search_pattern, limit, offset], map_row)?
                .filter_map(|r| r.ok())
                .collect();
        } else {
            // ?1 = status_filter, ?2 = search_pattern, ?3 = limit, ?4 = offset
            let where_clause = "WHERE (?1 = '' OR current_status = ?1)
              AND (?1 != '' OR current_status != 'Terminated')
              AND (?2 = '' OR name LIKE ?2 OR CAST(pid AS TEXT) LIKE ?2 OR COALESCE(exe_path,'') LIKE ?2)";

            total = conn.query_row(
                &format!("SELECT COUNT(*) FROM processes {}", where_clause),
                params![status_filter, search_pattern],
                |row| row.get(0),
            )?;

            let data_sql = format!(
                "SELECT {} FROM processes {} ORDER BY {} {} LIMIT ?3 OFFSET ?4",
                cols, where_clause, sort_col, sort_dir
            );
            let mut stmt = conn.prepare(&data_sql)?;
            records = stmt
                .query_map(
                    params![status_filter, search_pattern, limit, offset],
                    map_row,
                )?
                .filter_map(|r| r.ok())
                .collect();
        }

        Ok((records, total))
    }

    pub fn get_process_by_id(&self, id: &str) -> Result<Option<ProcessRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, pid, parent_pid, name, exe_path, command_line, signer_status,
             file_hash, first_seen_at, last_seen_at, user_name, integrity_level, current_status,
             risk_score, path_category FROM processes WHERE id = ?1",
        )?;

        let mut rows = stmt.query_map([id], |row| {
            Ok(ProcessRecord {
                id: row.get(0)?,
                pid: row.get(1)?,
                parent_pid: row.get(2)?,
                name: row.get(3)?,
                exe_path: row.get(4)?,
                command_line: row.get(5)?,
                signer_status: parse_signer_status(&row.get::<_, String>(6)?),
                file_hash: row.get(7)?,
                first_seen_at: parse_datetime(&row.get::<_, String>(8)?),
                last_seen_at: parse_datetime(&row.get::<_, String>(9)?),
                user_name: row.get(10)?,
                integrity_level: row.get(11)?,
                current_status: parse_process_status(&row.get::<_, String>(12)?),
                risk_score: row.get(13)?,
                path_category: parse_path_category(&row.get::<_, String>(14)?),
            })
        })?;

        Ok(rows.next().and_then(|r| r.ok()))
    }

    pub fn touch_process(&self, pid: u32) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE processes SET last_seen_at = ?1 WHERE pid = ?2 AND current_status != 'Terminated'",
            params![Utc::now().to_rfc3339(), pid],
        )?;
        Ok(())
    }

    pub fn mark_process_terminated(&self, pid: u32) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE processes SET current_status = 'Terminated', last_seen_at = ?1 WHERE pid = ?2 AND current_status != 'Terminated'",
            params![Utc::now().to_rfc3339(), pid],
        )?;
        Ok(())
    }

    // ---- Metrics ----

    pub fn insert_metric(&self, m: &ProcessMetric) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO process_metrics (id, process_id, timestamp, cpu_percent, memory_bytes, network_bytes_sent, network_bytes_received)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                m.id, m.process_id, m.timestamp.to_rfc3339(),
                m.cpu_percent, m.memory_bytes as i64,
                m.network_bytes_sent as i64, m.network_bytes_received as i64,
            ],
        )?;
        Ok(())
    }

    pub fn get_process_metrics(&self, process_id: &str, limit: u32) -> Result<Vec<ProcessMetric>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, process_id, timestamp, cpu_percent, memory_bytes, network_bytes_sent, network_bytes_received
             FROM process_metrics WHERE process_id = ?1 ORDER BY timestamp DESC LIMIT ?2",
        )?;

        let rows = stmt.query_map(params![process_id, limit], |row| {
            Ok(ProcessMetric {
                id: row.get(0)?,
                process_id: row.get(1)?,
                timestamp: parse_datetime(&row.get::<_, String>(2)?),
                cpu_percent: row.get(3)?,
                memory_bytes: row.get::<_, i64>(4)? as u64,
                network_bytes_sent: row.get::<_, i64>(5)? as u64,
                network_bytes_received: row.get::<_, i64>(6)? as u64,
            })
        })?;

        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    // ---- Alerts ----

    pub fn insert_alert(&self, alert: &Alert) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO alerts (id, process_id, timestamp, severity, title, summary, status, risk_score)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                alert.id, alert.process_id, alert.timestamp.to_rfc3339(),
                alert.severity.as_str(), alert.title, alert.summary,
                "open", alert.risk_score,
            ],
        )?;

        for rule in &alert.triggered_rules {
            conn.execute(
                "INSERT INTO alert_rules_triggered (id, alert_id, rule_key, explanation, evidence_json)
                 VALUES (?1,?2,?3,?4,?5)",
                params![
                    uuid::Uuid::new_v4().to_string(),
                    alert.id,
                    rule.rule_key,
                    rule.explanation,
                    rule.evidence.to_string(),
                ],
            )?;
        }

        Ok(())
    }

    pub fn list_alerts(&self, limit: u32) -> Result<Vec<Alert>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, process_id, timestamp, severity, title, summary, status, risk_score
             FROM alerts ORDER BY timestamp DESC LIMIT ?1",
        )?;

        let rows = stmt.query_map([limit], |row| {
            Ok(Alert {
                id: row.get(0)?,
                process_id: row.get(1)?,
                timestamp: parse_datetime(&row.get::<_, String>(2)?),
                severity: parse_severity(&row.get::<_, String>(3)?),
                title: row.get(4)?,
                summary: row.get(5)?,
                status: parse_alert_status(&row.get::<_, String>(6)?),
                risk_score: row.get(7)?,
                triggered_rules: vec![],
            })
        })?;

        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn update_alert_status(&self, id: &str, status: &AlertStatus) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let status_str = format!("{:?}", status).to_lowercase();
        conn.execute(
            "UPDATE alerts SET status = ?1 WHERE id = ?2",
            params![status_str, id],
        )?;
        Ok(())
    }

    // ---- Startup Entries ----

    pub fn upsert_startup_entry(&self, e: &StartupEntry) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO startup_entries (id, name, path, location_type, signer_status, first_seen_at, last_seen_at, enabled)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)
             ON CONFLICT(name, path) DO UPDATE SET
               last_seen_at=excluded.last_seen_at,
               enabled=excluded.enabled",
            params![
                e.id, e.name, e.path,
                format!("{:?}", e.location_type),
                format!("{:?}", e.signer_status),
                e.first_seen_at.to_rfc3339(),
                e.last_seen_at.to_rfc3339(),
                e.enabled,
            ],
        )?;
        Ok(())
    }

    pub fn count_new_startup_entries(&self) -> Result<u32> {
        let conn = self.conn.lock().unwrap();
        let cutoff = (Utc::now() - Duration::hours(24)).to_rfc3339();
        let count: u32 = conn.query_row(
            "SELECT COUNT(*) FROM startup_entries WHERE first_seen_at >= ?1",
            params![cutoff],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    pub fn delete_startup_entry(&self, id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM startup_entries WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn list_startup_entries(&self) -> Result<Vec<StartupEntry>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, name, path, location_type, signer_status, first_seen_at, last_seen_at, enabled
             FROM startup_entries ORDER BY first_seen_at DESC",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(StartupEntry {
                id: row.get(0)?,
                name: row.get(1)?,
                path: row.get(2)?,
                location_type: parse_startup_type(&row.get::<_, String>(3)?),
                signer_status: parse_signer_status(&row.get::<_, String>(4)?),
                first_seen_at: parse_datetime(&row.get::<_, String>(5)?),
                last_seen_at: parse_datetime(&row.get::<_, String>(6)?),
                enabled: row.get(7)?,
                is_new: false,
            })
        })?;

        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    // ---- User Actions ----

    pub fn log_user_action(&self, action: &UserAction) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO user_actions (id, timestamp, action_type, target_type, target_id, note)
             VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                action.id,
                action.timestamp.to_rfc3339(),
                format!("{:?}", action.action_type),
                action.target_type,
                action.target_id,
                action.note,
            ],
        )?;
        Ok(())
    }

    // ---- Trust Rules ----

    pub fn insert_trust_rule(&self, rule: &TrustRule) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO trust_rules (id, rule_type, value, scope, created_at, created_by)
             VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                rule.id,
                format!("{:?}", rule.rule_type),
                rule.value,
                rule.scope,
                rule.created_at.to_rfc3339(),
                rule.created_by,
            ],
        )?;
        Ok(())
    }

    pub fn is_trusted(&self, exe_path: Option<&str>, file_hash: Option<&str>, name: &str) -> bool {
        let conn = self.conn.lock().unwrap();

        let checks = [("ProcessName", name)];

        for (rule_type, value) in &checks {
            if let Ok(count) = conn.query_row(
                "SELECT COUNT(*) FROM trust_rules WHERE rule_type = ?1 AND value = ?2",
                params![rule_type, value],
                |row| row.get::<_, i64>(0),
            ) {
                if count > 0 {
                    return true;
                }
            }
        }

        if let Some(path) = exe_path {
            if let Ok(count) = conn.query_row(
                "SELECT COUNT(*) FROM trust_rules WHERE rule_type = 'ExePath' AND value = ?1",
                [path],
                |row| row.get::<_, i64>(0),
            ) {
                if count > 0 {
                    return true;
                }
            }
        }

        if let Some(hash) = file_hash {
            if let Ok(count) = conn.query_row(
                "SELECT COUNT(*) FROM trust_rules WHERE rule_type = 'FileHash' AND value = ?1",
                [hash],
                |row| row.get::<_, i64>(0),
            ) {
                if count > 0 {
                    return true;
                }
            }
        }

        false
    }

    // ---- Activity Events (unified timeline from all tables) ----

    /// Returns a merged, sorted timeline of security events from the last 30 days.
    pub fn list_events(&self, limit: u32) -> Result<Vec<ActivityEvent>> {
        let cutoff = (Utc::now() - Duration::days(30)).to_rfc3339();
        let conn = self.conn.lock().unwrap();

        let sql = "
            SELECT 'process_created' AS event_type,
                   id,
                   first_seen_at AS ts,
                   'Process Started: ' || name AS title,
                   COALESCE(exe_path, 'PID ' || CAST(pid AS TEXT)) AS description,
                   CASE WHEN risk_score >= 75 THEN 'high'
                        WHEN risk_score >= 50 THEN 'medium'
                        WHEN risk_score >= 25 THEN 'low'
                        ELSE 'info' END AS severity,
                   id AS related_id
            FROM processes WHERE first_seen_at >= ?1

            UNION ALL

            SELECT 'process_terminated',
                   id || '-t',
                   last_seen_at,
                   'Process Ended: ' || name,
                   COALESCE(exe_path, 'PID ' || CAST(pid AS TEXT)),
                   'info',
                   id
            FROM processes WHERE current_status = 'Terminated' AND last_seen_at >= ?1

            UNION ALL

            SELECT 'alert',
                   id,
                   timestamp,
                   title,
                   summary,
                   severity,
                   process_id
            FROM alerts WHERE timestamp >= ?1

            UNION ALL

            SELECT 'startup',
                   id,
                   first_seen_at,
                   'Startup Entry: ' || name,
                   path,
                   CASE signer_status
                       WHEN 'Unsigned' THEN 'low'
                       WHEN 'InvalidSignature' THEN 'high'
                       ELSE 'info' END,
                   id
            FROM startup_entries

            UNION ALL

            SELECT 'user_action',
                   id,
                   timestamp,
                   CASE action_type
                       WHEN 'KillProcess' THEN 'Process Killed'
                       WHEN 'TrustProcess' THEN 'Process Trusted'
                       WHEN 'AcknowledgeAlert' THEN 'Alert Acknowledged'
                       WHEN 'ResolveAlert' THEN 'Alert Resolved'
                       WHEN 'IgnoreAlert' THEN 'Alert Ignored'
                       WHEN 'DisableStartupEntry' THEN 'Startup Entry Disabled'
                       ELSE action_type END,
                   COALESCE(note, target_type || ': ' || target_id),
                   'info',
                   target_id
            FROM user_actions WHERE timestamp >= ?1

            ORDER BY ts DESC
            LIMIT ?2";

        let mut stmt = conn.prepare(sql)?;
        let rows = stmt.query_map(params![cutoff, limit], |row| {
            Ok(ActivityEvent {
                event_type: row.get(0)?,
                id: row.get(1)?,
                timestamp: row.get(2)?,
                title: row.get(3)?,
                description: row.get(4)?,
                severity: row.get(5)?,
                related_id: row.get(6)?,
            })
        })?;

        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    /// Returns a paginated page of the unified timeline plus the total count.
    pub fn list_events_paged(&self, limit: u32, offset: u32) -> Result<(Vec<ActivityEvent>, u32)> {
        let cutoff = (Utc::now() - Duration::days(30)).to_rfc3339();
        let conn = self.conn.lock().unwrap();

        let base_sql = "
            SELECT 'process_created' AS event_type,
                   id,
                   first_seen_at AS ts,
                   'Process Started: ' || name AS title,
                   COALESCE(exe_path, 'PID ' || CAST(pid AS TEXT)) AS description,
                   CASE WHEN risk_score >= 75 THEN 'high'
                        WHEN risk_score >= 50 THEN 'medium'
                        WHEN risk_score >= 25 THEN 'low'
                        ELSE 'info' END AS severity,
                   id AS related_id
            FROM processes WHERE first_seen_at >= ?1

            UNION ALL

            SELECT 'process_terminated',
                   id || '-t',
                   last_seen_at,
                   'Process Ended: ' || name,
                   COALESCE(exe_path, 'PID ' || CAST(pid AS TEXT)),
                   'info',
                   id
            FROM processes WHERE current_status = 'Terminated' AND last_seen_at >= ?1

            UNION ALL

            SELECT 'alert',
                   id,
                   timestamp,
                   title,
                   summary,
                   severity,
                   process_id
            FROM alerts WHERE timestamp >= ?1

            UNION ALL

            SELECT 'startup',
                   id,
                   first_seen_at,
                   'Startup Entry: ' || name,
                   path,
                   CASE signer_status
                       WHEN 'Unsigned' THEN 'low'
                       WHEN 'InvalidSignature' THEN 'high'
                       ELSE 'info' END,
                   id
            FROM startup_entries

            UNION ALL

            SELECT 'user_action',
                   id,
                   timestamp,
                   CASE action_type
                       WHEN 'KillProcess' THEN 'Process Killed'
                       WHEN 'TrustProcess' THEN 'Process Trusted'
                       WHEN 'AcknowledgeAlert' THEN 'Alert Acknowledged'
                       WHEN 'ResolveAlert' THEN 'Alert Resolved'
                       WHEN 'IgnoreAlert' THEN 'Alert Ignored'
                       WHEN 'DisableStartupEntry' THEN 'Startup Entry Disabled'
                       ELSE action_type END,
                   COALESCE(note, target_type || ': ' || target_id),
                   'info',
                   target_id
            FROM user_actions WHERE timestamp >= ?1";

        let count_sql = format!("SELECT COUNT(*) FROM ({base_sql}) sub");
        let mut count_stmt = conn.prepare(&count_sql)?;
        let total: u32 = count_stmt.query_row(params![cutoff], |r| r.get(0))?;

        let page_sql = format!("{base_sql} ORDER BY ts DESC LIMIT ?2 OFFSET ?3");
        let mut stmt = conn.prepare(&page_sql)?;
        let rows = stmt.query_map(params![cutoff, limit, offset], |row| {
            Ok(ActivityEvent {
                event_type: row.get(0)?,
                id: row.get(1)?,
                timestamp: row.get(2)?,
                title: row.get(3)?,
                description: row.get(4)?,
                severity: row.get(5)?,
                related_id: row.get(6)?,
            })
        })?;

        Ok((rows.filter_map(|r| r.ok()).collect(), total))
    }

    // ---- AI Conversations ----

    pub fn insert_ai_conversation(&self, conv: &AiConversation) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO ai_conversations (id, process_id, created_at, prompt, response, context_json)
             VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                conv.id, conv.process_id, conv.created_at.to_rfc3339(),
                conv.prompt, conv.response, conv.context_json.to_string(),
            ],
        )?;
        Ok(())
    }
}

// ---- Parsing helpers ----

fn parse_datetime(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}

fn parse_signer_status(s: &str) -> SignerStatus {
    match s {
        "Signed" => SignerStatus::Signed,
        "Unsigned" => SignerStatus::Unsigned,
        "InvalidSignature" => SignerStatus::InvalidSignature,
        _ => SignerStatus::Unknown,
    }
}

fn parse_process_status(s: &str) -> ProcessStatus {
    match s {
        "Terminated" => ProcessStatus::Terminated,
        "Suspicious" => ProcessStatus::Suspicious,
        "Trusted" => ProcessStatus::Trusted,
        _ => ProcessStatus::Running,
    }
}

fn parse_path_category(s: &str) -> PathCategory {
    match s {
        "System" => PathCategory::System,
        "ProgramFiles" => PathCategory::ProgramFiles,
        "Temp" => PathCategory::Temp,
        "Downloads" => PathCategory::Downloads,
        "AppData" => PathCategory::AppData,
        "UserWritable" => PathCategory::UserWritable,
        _ => PathCategory::Unknown,
    }
}

fn parse_severity(s: &str) -> Severity {
    match s {
        "low" => Severity::Low,
        "medium" => Severity::Medium,
        "high" => Severity::High,
        _ => Severity::Info,
    }
}

fn parse_alert_status(s: &str) -> AlertStatus {
    match s {
        "acknowledged" => AlertStatus::Acknowledged,
        "ignored" => AlertStatus::Ignored,
        "resolved" => AlertStatus::Resolved,
        _ => AlertStatus::Open,
    }
}

fn parse_startup_type(s: &str) -> StartupLocationType {
    match s {
        "RegistryRunKey" => StartupLocationType::RegistryRunKey,
        "RegistryRunOnceKey" => StartupLocationType::RegistryRunOnceKey,
        "StartupFolder" => StartupLocationType::StartupFolder,
        "ScheduledTask" => StartupLocationType::ScheduledTask,
        "Service" => StartupLocationType::Service,
        _ => StartupLocationType::Unknown,
    }
}
