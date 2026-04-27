use crate::models::{Alert, ProcessRecord, StartupEntry};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MonitorEvent {
    ProcessCreated {
        timestamp: DateTime<Utc>,
        process: ProcessRecord,
    },
    ProcessTerminated {
        timestamp: DateTime<Utc>,
        pid: u32,
        process_id: String,
    },
    AlertGenerated {
        timestamp: DateTime<Utc>,
        alert: Alert,
    },
    StartupEntryAdded {
        timestamp: DateTime<Utc>,
        entry: StartupEntry,
    },
    MetricsUpdated {
        timestamp: DateTime<Utc>,
        process_id: String,
        cpu_percent: f64,
        memory_bytes: u64,
    },
    MonitoringPaused {
        timestamp: DateTime<Utc>,
    },
    MonitoringResumed {
        timestamp: DateTime<Utc>,
    },
}
