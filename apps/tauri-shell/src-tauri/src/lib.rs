mod browser_bridge;
mod commands;
mod credential_vault;
mod password;
mod state;
mod tray;
mod url_scanner;
mod virustotal;

use std::sync::Arc;
use tauri::Manager;
use tracing::info;
use tracing_subscriber::EnvFilter;

pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse().unwrap()))
        .init();

    info!("Starting Threat-Guard");

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_notification::init())
        .setup(|app| {
            let app_dir = app
                .path()
                .app_data_dir()
                .expect("Failed to get app data dir");
            std::fs::create_dir_all(&app_dir)?;

            let db_path = app_dir.join("psa.db");
            info!("Database path: {:?}", db_path);

            let (monitor, _event_rx) =
                monitor_core::services::monitor_service::MonitorService::new(db_path)
                    .expect("Failed to initialize monitor service");

            let monitor = Arc::new(monitor);
            let browser_bridge =
                browser_bridge::BrowserBridgeRuntime::new(credential_vault::BROWSER_BRIDGE_PORT);
            let vault_access = credential_vault::VaultAccessController::new();
            browser_bridge::spawn(
                browser_bridge.clone(),
                monitor.get_db(),
                vault_access.clone(),
            );

            let state = state::AppState::new(monitor.clone(), browser_bridge, vault_access);
            app.manage(state);

            let monitor_clone = monitor.clone();
            tauri::async_runtime::spawn(async move {
                monitor_clone.start_monitoring().await;
            });

            tray::setup_tray(app)?;

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_system_overview,
            commands::list_processes,
            commands::list_processes_paged,
            commands::get_process_details,
            commands::get_process_metrics,
            commands::list_alerts,
            commands::update_alert_status,
            commands::kill_process,
            commands::trust_process,
            commands::list_startup_entries,
            commands::remove_startup_entry,
            commands::check_url,
            commands::check_password,
            commands::list_password_credentials,
            commands::get_password_vault_status,
            commands::get_password_vault_risk_summary,
            commands::get_password_health_alert,
            commands::set_password_vault_passcode,
            commands::unlock_password_vault,
            commands::lock_password_vault,
            commands::get_password_credential_secret,
            commands::save_password_credential,
            commands::update_password_credential,
            commands::delete_password_credential,
            commands::get_browser_extension_status,
            commands::reset_browser_extension_pairing,
            commands::ask_ai_about_process,
            commands::list_activity_events,
            commands::list_activity_events_paged,
            commands::ask_ai,
            commands::pause_monitoring,
            commands::resume_monitoring,
            commands::get_setting,
            commands::save_setting,
            commands::run_cleanup_now,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
