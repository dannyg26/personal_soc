use anyhow::Result;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;
use uuid::Uuid;

use shared_types::models::ProcessMetric;

/// Tracks previous CPU time samples per PID so we can compute a delta on the next tick.
struct CpuSample {
    process_time_100ns: u64, // kernel + user time in 100-ns units
    wall_instant: Instant,
}

pub struct MetricsCollector {
    prev_cpu: Mutex<HashMap<u32, CpuSample>>,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            prev_cpu: Mutex::new(HashMap::new()),
        }
    }

    pub fn collect_process_metrics(&self, pid: u32, process_id: &str) -> Result<ProcessMetric> {
        #[cfg(windows)]
        {
            self.collect_windows_metrics(pid, process_id)
        }
        #[cfg(not(windows))]
        {
            self.collect_stub_metrics(pid, process_id)
        }
    }

    #[cfg(windows)]
    fn collect_windows_metrics(&self, pid: u32, process_id: &str) -> Result<ProcessMetric> {
        use windows::Win32::Foundation::{CloseHandle, FILETIME};
        use windows::Win32::System::ProcessStatus::{
            GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
        };
        use windows::Win32::System::Threading::{
            GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };

        fn filetime_to_u64(ft: FILETIME) -> u64 {
            ((ft.dwHighDateTime as u64) << 32) | (ft.dwLowDateTime as u64)
        }

        let mut memory_bytes: u64 = 0;
        let mut cpu_percent: f64 = 0.0;
        let now = Instant::now();

        unsafe {
            if let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                // Memory
                let mut pmc = PROCESS_MEMORY_COUNTERS {
                    cb: std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
                    ..Default::default()
                };
                if GetProcessMemoryInfo(handle, &mut pmc, pmc.cb).is_ok() {
                    memory_bytes = pmc.WorkingSetSize as u64;
                }

                // CPU — requires two samples to compute delta
                let mut creation = FILETIME::default();
                let mut exit = FILETIME::default();
                let mut kernel = FILETIME::default();
                let mut user = FILETIME::default();
                if GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user).is_ok()
                {
                    let process_time = filetime_to_u64(kernel) + filetime_to_u64(user);
                    let mut prev_lock = self.prev_cpu.lock().unwrap();

                    if let Some(prev) = prev_lock.get(&pid) {
                        let process_delta =
                            process_time.saturating_sub(prev.process_time_100ns) as f64;
                        // wall time in 100-ns units (same unit as FILETIME)
                        let wall_delta_100ns =
                            prev.wall_instant.elapsed().as_nanos() as f64 / 100.0;
                        let num_cpus = std::thread::available_parallelism()
                            .map(|n| n.get())
                            .unwrap_or(1) as f64;
                        if wall_delta_100ns > 0.0 {
                            cpu_percent = (process_delta / (wall_delta_100ns * num_cpus) * 100.0)
                                .min(100.0)
                                .max(0.0);
                        }
                    }

                    prev_lock.insert(
                        pid,
                        CpuSample {
                            process_time_100ns: process_time,
                            wall_instant: now,
                        },
                    );
                }

                let _ = CloseHandle(handle);
            }
        }

        Ok(ProcessMetric {
            id: Uuid::new_v4().to_string(),
            process_id: process_id.to_string(),
            timestamp: Utc::now(),
            cpu_percent,
            memory_bytes,
            network_bytes_sent: 0,
            network_bytes_received: 0,
        })
    }

    #[cfg(not(windows))]
    fn collect_stub_metrics(&self, _pid: u32, process_id: &str) -> Result<ProcessMetric> {
        Ok(ProcessMetric {
            id: Uuid::new_v4().to_string(),
            process_id: process_id.to_string(),
            timestamp: Utc::now(),
            cpu_percent: 0.0,
            memory_bytes: 0,
            network_bytes_sent: 0,
            network_bytes_received: 0,
        })
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}
