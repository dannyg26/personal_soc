use shared_types::models::{AiContext, Alert, ProcessMetric, ProcessRecord};

pub struct ContextBuilder;

impl ContextBuilder {
    pub fn build(
        process: &ProcessRecord,
        parent_name: Option<String>,
        recent_metrics: &[ProcessMetric],
        alerts: &[Alert],
        startup_linked: bool,
        network_active: bool,
    ) -> AiContext {
        let (avg_cpu, avg_memory) = if recent_metrics.is_empty() {
            (0.0, 0.0)
        } else {
            let cpu = recent_metrics.iter().map(|m| m.cpu_percent).sum::<f64>()
                / recent_metrics.len() as f64;
            let mem = recent_metrics
                .iter()
                .map(|m| m.memory_bytes as f64)
                .sum::<f64>()
                / recent_metrics.len() as f64;
            (cpu, mem / 1_048_576.0) // bytes to MB
        };

        // Gather triggered rules from alerts
        let triggered_rules = alerts
            .iter()
            .flat_map(|a| a.triggered_rules.clone())
            .collect::<Vec<_>>();

        AiContext {
            process_name: process.name.clone(),
            exe_path: process.exe_path.clone(),
            signer_status: process.signer_status.clone(),
            file_hash: process.file_hash.clone(),
            parent_process_name: parent_name,
            command_line: process.command_line.clone(),
            triggered_rules,
            risk_score: process.risk_score,
            recent_cpu_avg: avg_cpu,
            recent_memory_mb: avg_memory,
            startup_linked,
            network_active,
            path_category: process.path_category.clone(),
        }
    }
}
