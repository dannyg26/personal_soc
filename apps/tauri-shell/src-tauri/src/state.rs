use crate::browser_bridge::BrowserBridgeRuntime;
use crate::credential_vault::VaultAccessController;
use monitor_core::services::monitor_service::MonitorService;
use std::sync::Arc;

pub struct AppState {
    pub monitor: Arc<MonitorService>,
    pub browser_bridge: BrowserBridgeRuntime,
    pub vault_access: VaultAccessController,
}

impl AppState {
    pub fn new(
        monitor: Arc<MonitorService>,
        browser_bridge: BrowserBridgeRuntime,
        vault_access: VaultAccessController,
    ) -> Self {
        Self {
            monitor,
            browser_bridge,
            vault_access,
        }
    }
}
