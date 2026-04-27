use chrono::Utc;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use sysinfo::System;
use tokio::sync::{broadcast, RwLock};
use tokio::time::{interval, Duration};
use tracing::{debug, error, info};

use shared_types::events::MonitorEvent;
use shared_types::models::{Alert, AlertStatus, ProcessRecord, ProcessStatus, SystemOverview};

use crate::collectors::{MetricsCollector, ProcessCollector, StartupCollector};
use crate::persistence::Database;
use crate::rules::RulesEngine;
use crate::scoring::ScoringService;

pub struct MonitorService {
    db: Arc<Database>,
    process_collector: ProcessCollector,
    metrics_collector: MetricsCollector,
    startup_collector: StartupCollector,
    rules_engine: RulesEngine,
    scoring: ScoringService,
    event_tx: broadcast::Sender<MonitorEvent>,
    is_paused: Arc<RwLock<bool>>,
    known_pids: Arc<RwLock<HashMap<u32, String>>>, // pid -> process_id
    cached_cpu: Arc<RwLock<f64>>,
    cached_memory: Arc<RwLock<f64>>,
}

impl MonitorService {
    pub fn new(db_path: PathBuf) -> anyhow::Result<(Self, broadcast::Receiver<MonitorEvent>)> {
        let db = Database::open(&db_path)?;
        let (event_tx, event_rx) = broadcast::channel(256);

        Ok((
            Self {
                db: Arc::new(db),
                process_collector: ProcessCollector::new(),
                metrics_collector: MetricsCollector::new(),
                startup_collector: StartupCollector::new(),
                rules_engine: RulesEngine::new(),
                scoring: ScoringService::new(),
                event_tx,
                is_paused: Arc::new(RwLock::new(false)),
                known_pids: Arc::new(RwLock::new(HashMap::new())),
                cached_cpu: Arc::new(RwLock::new(0.0)),
                cached_memory: Arc::new(RwLock::new(0.0)),
            },
            event_rx,
        ))
    }

    pub fn subscribe(&self) -> broadcast::Receiver<MonitorEvent> {
        self.event_tx.subscribe()
    }

    pub async fn start_monitoring(&self) {
        info!("Starting monitoring loop");

        let mut process_interval = interval(Duration::from_secs(15));
        let mut metrics_interval = interval(Duration::from_secs(10));
        let mut startup_interval = interval(Duration::from_secs(60));
        let mut cleanup_interval = interval(Duration::from_secs(3600)); // hourly

        loop {
            tokio::select! {
                _ = process_interval.tick() => {
                    if !*self.is_paused.read().await {
                        self.tick_processes().await;
                    }
                }
                _ = metrics_interval.tick() => {
                    if !*self.is_paused.read().await {
                        self.tick_metrics().await;
                    }
                }
                _ = startup_interval.tick() => {
                    if !*self.is_paused.read().await {
                        self.tick_startup().await;
                    }
                }
                _ = cleanup_interval.tick() => {
                    self.tick_cleanup().await;
                }
            }
        }
    }

    async fn tick_processes(&self) {
        let current = match self.process_collector.enumerate_processes() {
            Ok(p) => p,
            Err(e) => {
                error!("Process enumeration failed: {}", e);
                return;
            }
        };

        let current_pids: HashMap<u32, &ProcessRecord> =
            current.iter().map(|p| (p.pid, p)).collect();
        let mut known = self.known_pids.write().await;

        // Detect new processes
        for (pid, process) in &current_pids {
            if !known.contains_key(pid) {
                let mut proc = (*process).clone();

                // Check trust
                let trusted = self.db.is_trusted(
                    proc.exe_path.as_deref(),
                    proc.file_hash.as_deref(),
                    &proc.name,
                );

                if trusted {
                    proc.current_status = ProcessStatus::Trusted;
                    proc.risk_score = 0;
                } else {
                    // Build parent map for rule evaluation
                    let parent = proc
                        .parent_pid
                        .and_then(|ppid| current_pids.get(&ppid).copied().cloned().map(|p| p));

                    let triggered = self.rules_engine.evaluate(&proc, parent.as_ref());
                    let score = self.scoring.compute_score(&proc, &triggered);

                    proc.risk_score = score;
                    if score >= 50 {
                        proc.current_status = ProcessStatus::Suspicious;

                        // Generate alert
                        let mut alert = Alert::new(
                            proc.id.clone(),
                            format!("Suspicious process: {}", proc.name),
                            triggered
                                .iter()
                                .map(|r| r.explanation.clone())
                                .collect::<Vec<_>>()
                                .join("; "),
                            score,
                        );
                        alert.triggered_rules = triggered
                            .iter()
                            .map(|r| shared_types::models::TriggeredRule {
                                rule_key: r.rule_key.clone(),
                                explanation: r.explanation.clone(),
                                evidence: r.evidence.clone(),
                                weight: r.weight,
                            })
                            .collect();

                        if let Err(e) = self.db.insert_alert(&alert) {
                            error!("Failed to insert alert: {}", e);
                        }

                        let _ = self.event_tx.send(MonitorEvent::AlertGenerated {
                            timestamp: Utc::now(),
                            alert,
                        });
                    }
                }

                if let Err(e) = self.db.upsert_process(&proc) {
                    error!("Failed to upsert process {}: {}", proc.name, e);
                }

                known.insert(*pid, proc.id.clone());

                let _ = self.event_tx.send(MonitorEvent::ProcessCreated {
                    timestamp: Utc::now(),
                    process: proc,
                });
            }
        }

        // Update last_seen_at for existing processes so UI reflects current state
        for (pid, _process) in &current_pids {
            if known.contains_key(pid) {
                let _ = self.db.touch_process(*pid);
            }
        }

        // Detect terminated processes
        let terminated_pids: Vec<u32> = known
            .keys()
            .filter(|pid| !current_pids.contains_key(pid))
            .copied()
            .collect();

        for pid in terminated_pids {
            if let Some(process_id) = known.remove(&pid) {
                if let Err(e) = self.db.mark_process_terminated(pid) {
                    error!("Failed to mark process {} terminated: {}", pid, e);
                }
                let _ = self.event_tx.send(MonitorEvent::ProcessTerminated {
                    timestamp: Utc::now(),
                    pid,
                    process_id,
                });
            }
        }
    }

    async fn tick_metrics(&self) {
        // Refresh system-wide CPU and memory in background so get_system_overview is cheap
        let cpu_cache = self.cached_cpu.clone();
        let mem_cache = self.cached_memory.clone();
        tokio::task::spawn_blocking(move || {
            let mut sys = System::new_all();
            sys.refresh_cpu_usage();
            std::thread::sleep(std::time::Duration::from_millis(250));
            sys.refresh_cpu_usage();
            sys.refresh_memory();
            let cpu = sys.global_cpu_info().cpu_usage() as f64;
            let total = sys.total_memory();
            let used = sys.used_memory();
            let mem = if total > 0 {
                (used as f64 / total as f64) * 100.0
            } else {
                0.0
            };
            // Store results — fire and forget, ignore lock errors
            if let Ok(mut c) = cpu_cache.try_write() {
                *c = cpu;
            }
            if let Ok(mut m) = mem_cache.try_write() {
                *m = mem;
            }
        });

        let known = self.known_pids.read().await;
        for (pid, process_id) in known.iter() {
            match self
                .metrics_collector
                .collect_process_metrics(*pid, process_id)
            {
                Ok(metric) => {
                    let _ = self.db.insert_metric(&metric);
                    let _ = self.event_tx.send(MonitorEvent::MetricsUpdated {
                        timestamp: Utc::now(),
                        process_id: process_id.clone(),
                        cpu_percent: metric.cpu_percent,
                        memory_bytes: metric.memory_bytes,
                    });
                }
                Err(e) => {
                    debug!("Metrics collection failed for PID {}: {}", pid, e);
                }
            }
        }
    }

    async fn tick_cleanup(&self) {
        let hours = self
            .db
            .get_setting("process_retention_hours")
            .ok()
            .flatten()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(0); // 0 = disabled
        if hours == 0 {
            return;
        }
        match self.db.cleanup_old_processes(hours) {
            Ok(n) if n > 0 => info!("Cleanup: removed {} old terminated process records", n),
            Ok(_) => {}
            Err(e) => error!("Cleanup failed: {}", e),
        }
    }

    async fn tick_startup(&self) {
        match self.startup_collector.collect_startup_entries() {
            Ok(entries) => {
                for entry in &entries {
                    if let Err(e) = self.db.upsert_startup_entry(entry) {
                        error!("Failed to upsert startup entry: {}", e);
                    }
                    if entry.is_new {
                        let _ = self.event_tx.send(MonitorEvent::StartupEntryAdded {
                            timestamp: Utc::now(),
                            entry: entry.clone(),
                        });
                    }
                }
            }
            Err(e) => error!("Startup collection failed: {}", e),
        }
    }

    pub async fn pause(&self) {
        *self.is_paused.write().await = true;
        let _ = self.event_tx.send(MonitorEvent::MonitoringPaused {
            timestamp: Utc::now(),
        });
        info!("Monitoring paused");
    }

    pub async fn resume(&self) {
        *self.is_paused.write().await = false;
        let _ = self.event_tx.send(MonitorEvent::MonitoringResumed {
            timestamp: Utc::now(),
        });
        info!("Monitoring resumed");
    }

    pub fn get_db(&self) -> Arc<Database> {
        self.db.clone()
    }

    pub fn kill_process(&self, pid: u32) -> anyhow::Result<()> {
        self.process_collector.kill_process(pid)
    }

    /// Enriches a single process record with expensive data (signature, hash).
    /// Call when the user opens a process detail view.
    pub fn enrich_process(&self, record: &mut shared_types::models::ProcessRecord) {
        self.process_collector.enrich_single_process(record);
    }

    pub async fn remove_startup_entry(
        &self,
        entry_id: &str,
        name: &str,
        location_type: &shared_types::models::StartupLocationType,
    ) -> anyhow::Result<()> {
        // Remove from registry/filesystem
        self.startup_collector
            .disable_startup_entry(name, location_type)?;
        // Remove from DB
        self.db.delete_startup_entry(entry_id)?;
        Ok(())
    }

    pub async fn get_system_overview(&self) -> SystemOverview {
        let db = &self.db;
        let active_alerts = db
            .list_alerts(1000)
            .map(|a| a.iter().filter(|x| x.status == AlertStatus::Open).count() as u32)
            .unwrap_or(0);
        let processes = db.list_processes().unwrap_or_default();
        let suspicious_count = processes.iter().filter(|p| p.risk_score >= 25).count() as u32;

        let cpu_usage = *self.cached_cpu.read().await;
        let memory_usage = *self.cached_memory.read().await;

        SystemOverview {
            health_score: {
                if active_alerts == 0 {
                    100
                } else {
                    // Logarithmic decay: fast drop for first few alerts, slower after that
                    // 1 alert→90, 3→78, 5→68, 10→50, 20→30, 50→10
                    let score = 100.0 / (1.0 + (active_alerts as f64 * 0.15).ln_1p());
                    (score as u32).max(5)
                }
            },
            active_alerts_count: active_alerts,
            suspicious_processes_count: suspicious_count,
            startup_changes_count: db.count_new_startup_entries().unwrap_or(0),
            monitored_processes_count: processes.len() as u32,
            cpu_usage,
            memory_usage,
            timestamp: Utc::now(),
        }
    }
}
