use crate::state::AppState;
use crate::{credential_vault, password, url_scanner, virustotal};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use shared_types::models::{
    AiConversation, AlertStatus, PathCategory, ProcessStatus, SignerStatus, StartupLocationType,
    TrustRule, TrustRuleType, UserAction, UserActionType,
};
use tauri::State;
use uuid::Uuid;

type CmdResult<T> = Result<T, String>;

fn to_cmd_err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AiChatMessage {
    role: String,
    content: String,
}

fn format_chat_history(history: Option<&[AiChatMessage]>) -> Option<String> {
    let lines = history?
        .iter()
        .rev()
        .take(6)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .filter_map(|message| {
            let content = message.content.trim();
            if content.is_empty() {
                return None;
            }

            let role = match message.role.as_str() {
                "assistant" | "ai" => "Assistant",
                _ => "User",
            };

            Some(format!("{role}: {content}"))
        })
        .collect::<Vec<_>>();

    if lines.is_empty() {
        None
    } else {
        Some(lines.join("\n"))
    }
}

fn signer_status_label(status: &SignerStatus) -> &'static str {
    match status {
        SignerStatus::Signed => "signed",
        SignerStatus::Unsigned => "unsigned",
        SignerStatus::InvalidSignature => "invalid signature",
        SignerStatus::Unknown => "signature unknown",
    }
}

fn path_category_label(category: &PathCategory) -> &'static str {
    match category {
        PathCategory::System => "system path",
        PathCategory::ProgramFiles => "Program Files",
        PathCategory::UserWritable => "user-writable path",
        PathCategory::Temp => "Temp directory",
        PathCategory::Downloads => "Downloads folder",
        PathCategory::AppData => "AppData",
        PathCategory::Unknown => "unknown path",
    }
}

fn process_status_label(status: &ProcessStatus) -> &'static str {
    match status {
        ProcessStatus::Running => "running",
        ProcessStatus::Terminated => "terminated",
        ProcessStatus::Suspicious => "suspicious",
        ProcessStatus::Trusted => "trusted",
    }
}

#[derive(Serialize)]
pub struct UrlScanResult {
    scan_target: url_scanner::ScanTarget,
    normalized_url: String,
    domain: String,
    local_risk_score: u8,
    is_ip_address: bool,
    uses_https: bool,
    subdomain_depth: usize,
    url_length: usize,
    suspicious_keywords: Vec<String>,
    heuristics: Vec<String>,
    virustotal: Option<virustotal::VTResult>,
    virustotal_configured: bool,
    virustotal_error: Option<String>,
    verdict: String,
    verdict_source: String,
}

#[derive(Serialize)]
pub struct PasswordResult {
    entropy: f64,
    crack_time_display: String,
    strength_label: String,
    breach_count: u32,
}

#[derive(Serialize)]
pub struct PasswordHealthAlert {
    has_alert: bool,
    severity: String,
    title: String,
    summary: String,
    recommendation: String,
    risk_score: u32,
    compromised_count: u32,
    weak_compromised_count: u32,
    affected_sites: Vec<String>,
    last_checked_at: String,
}

#[tauri::command]
pub async fn get_system_overview(state: State<'_, AppState>) -> CmdResult<Value> {
    let overview = state.monitor.get_system_overview().await;
    serde_json::to_value(overview).map_err(to_cmd_err)
}

#[tauri::command]
pub async fn list_processes(state: State<'_, AppState>) -> CmdResult<Value> {
    let db = state.monitor.get_db();
    let processes = db.list_processes().map_err(to_cmd_err)?;
    serde_json::to_value(processes).map_err(to_cmd_err)
}

#[tauri::command]
pub async fn list_processes_paged(
    state: State<'_, AppState>,
    search: String,
    status_filter: String,
    sort_key: String,
    sort_asc: bool,
    limit: u32,
    offset: u32,
) -> CmdResult<Value> {
    let db = state.monitor.get_db();
    let (processes, total) = db
        .list_processes_paged(&search, &status_filter, &sort_key, sort_asc, limit, offset)
        .map_err(to_cmd_err)?;
    serde_json::to_value(serde_json::json!({ "processes": processes, "total": total }))
        .map_err(to_cmd_err)
}

#[tauri::command]
pub async fn get_process_details(
    state: State<'_, AppState>,
    process_id: String,
) -> CmdResult<Value> {
    let db = state.monitor.get_db();
    let mut process = db.get_process_by_id(&process_id).map_err(to_cmd_err)?;
    if let Some(ref mut p) = process {
        state.monitor.enrich_process(p);
    }
    serde_json::to_value(process).map_err(to_cmd_err)
}

#[tauri::command]
pub async fn get_process_metrics(
    state: State<'_, AppState>,
    process_id: String,
    limit: Option<u32>,
) -> CmdResult<Value> {
    let db = state.monitor.get_db();
    let metrics = db
        .get_process_metrics(&process_id, limit.unwrap_or(60))
        .map_err(to_cmd_err)?;
    serde_json::to_value(metrics).map_err(to_cmd_err)
}

#[tauri::command]
pub async fn list_alerts(state: State<'_, AppState>, limit: Option<u32>) -> CmdResult<Value> {
    let db = state.monitor.get_db();
    let alerts = db.list_alerts(limit.unwrap_or(100)).map_err(to_cmd_err)?;
    serde_json::to_value(alerts).map_err(to_cmd_err)
}

#[tauri::command]
pub async fn update_alert_status(
    state: State<'_, AppState>,
    alert_id: String,
    status: String,
) -> CmdResult<()> {
    let db = state.monitor.get_db();
    let alert_status = match status.as_str() {
        "acknowledged" => AlertStatus::Acknowledged,
        "ignored" => AlertStatus::Ignored,
        "resolved" => AlertStatus::Resolved,
        _ => AlertStatus::Open,
    };
    db.update_alert_status(&alert_id, &alert_status)
        .map_err(to_cmd_err)?;

    let action = UserAction {
        id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        action_type: UserActionType::AcknowledgeAlert,
        target_type: "alert".to_string(),
        target_id: alert_id,
        note: Some(format!("Status changed to {}", status)),
    };
    db.log_user_action(&action).map_err(to_cmd_err)?;
    Ok(())
}

#[tauri::command]
pub async fn kill_process(
    state: State<'_, AppState>,
    pid: u32,
    process_id: String,
) -> CmdResult<()> {
    state.monitor.kill_process(pid).map_err(to_cmd_err)?;

    let action = UserAction {
        id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        action_type: UserActionType::KillProcess,
        target_type: "process".to_string(),
        target_id: process_id,
        note: Some(format!("Killed PID {}", pid)),
    };
    state
        .monitor
        .get_db()
        .log_user_action(&action)
        .map_err(to_cmd_err)?;
    Ok(())
}

#[tauri::command]
pub async fn trust_process(
    state: State<'_, AppState>,
    process_id: String,
    rule_type: String,
    value: String,
) -> CmdResult<()> {
    let db = state.monitor.get_db();

    let trust_type = match rule_type.as_str() {
        "process_name" => TrustRuleType::ProcessName,
        "exe_path" => TrustRuleType::ExePath,
        "file_hash" => TrustRuleType::FileHash,
        "signer" => TrustRuleType::Signer,
        _ => return Err("Invalid trust rule type".to_string()),
    };

    let rule = TrustRule {
        id: Uuid::new_v4().to_string(),
        rule_type: trust_type,
        value: value.clone(),
        scope: "global".to_string(),
        created_at: Utc::now(),
        created_by: "user".to_string(),
    };
    db.insert_trust_rule(&rule).map_err(to_cmd_err)?;

    let action = UserAction {
        id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        action_type: UserActionType::TrustProcess,
        target_type: "process".to_string(),
        target_id: process_id,
        note: Some(format!("Trusted by {}: {}", rule_type, value)),
    };
    db.log_user_action(&action).map_err(to_cmd_err)?;
    Ok(())
}

#[tauri::command]
pub async fn list_startup_entries(state: State<'_, AppState>) -> CmdResult<Value> {
    let db = state.monitor.get_db();
    let entries = db.list_startup_entries().map_err(to_cmd_err)?;
    serde_json::to_value(entries).map_err(to_cmd_err)
}

#[tauri::command]
pub async fn check_password(password_input: String) -> CmdResult<PasswordResult> {
    let analysis = password::analyze(&password_input);
    let breach_count = get_breach_count(&analysis.sha1_prefix, &analysis.sha1_suffix).await?;

    Ok(PasswordResult {
        entropy: analysis.entropy,
        crack_time_display: analysis.crack_time_display,
        strength_label: analysis.strength_label,
        breach_count,
    })
}

#[tauri::command]
pub async fn list_password_credentials(
    state: State<'_, AppState>,
) -> CmdResult<Vec<credential_vault::CredentialSummary>> {
    let db = state.monitor.get_db();
    state
        .vault_access
        .require_active_unlock(db.as_ref(), credential_vault::VAULT_UNLOCK_REQUIRED_MESSAGE)?;
    credential_vault::list_credentials(db.as_ref())
}

#[tauri::command]
pub async fn get_password_vault_status(
    state: State<'_, AppState>,
) -> CmdResult<credential_vault::VaultAccessStatus> {
    let db = state.monitor.get_db();
    state.vault_access.status(db.as_ref())
}

#[tauri::command]
pub async fn get_password_vault_risk_summary(
    state: State<'_, AppState>,
) -> CmdResult<credential_vault::PasswordVaultRiskSummary> {
    let db = state.monitor.get_db();
    credential_vault::get_password_risk_summary(db.as_ref())
}

#[tauri::command]
pub async fn get_password_health_alert(
    state: State<'_, AppState>,
) -> CmdResult<PasswordHealthAlert> {
    let db = state.monitor.get_db();
    let credentials = credential_vault::list_credentials_for_security_review(db.as_ref())?;
    if credentials.is_empty() {
        return Ok(PasswordHealthAlert {
            has_alert: false,
            severity: "info".to_string(),
            title: "No compromised saved passwords detected".to_string(),
            summary: "Threat Guard did not find any saved credentials to review for breach exposure."
                .to_string(),
            recommendation: "Add credentials to Password Manager if you want Threat Guard to review them for password exposure."
                .to_string(),
            risk_score: 0,
            compromised_count: 0,
            weak_compromised_count: 0,
            affected_sites: Vec::new(),
            last_checked_at: Utc::now().to_rfc3339(),
        });
    }

    let mut breach_cache = HashMap::new();
    let mut compromised_count = 0_u32;
    let mut weak_compromised_count = 0_u32;
    let mut affected_sites = Vec::new();
    let mut seen_sites = HashSet::new();

    for credential in credentials {
        let analysis = password::analyze(&credential.password);
        let cache_key = format!("{}:{}", analysis.sha1_prefix, analysis.sha1_suffix);
        let breach_count = if let Some(count) = breach_cache.get(&cache_key) {
            *count
        } else {
            let count = get_breach_count(&analysis.sha1_prefix, &analysis.sha1_suffix).await?;
            breach_cache.insert(cache_key, count);
            count
        };

        if breach_count == 0 {
            continue;
        }

        compromised_count += 1;
        if is_weak_password_label(&analysis.strength_label) {
            weak_compromised_count += 1;
        }

        if seen_sites.insert(credential.site_label.clone()) && affected_sites.len() < 3 {
            affected_sites.push(credential.site_label);
        }
    }

    Ok(build_password_health_alert(
        compromised_count,
        weak_compromised_count,
        affected_sites,
    ))
}

#[tauri::command]
pub async fn set_password_vault_passcode(
    state: State<'_, AppState>,
    passcode: String,
    current_passcode: Option<String>,
) -> CmdResult<credential_vault::VaultAccessStatus> {
    let db = state.monitor.get_db();
    state
        .vault_access
        .set_passcode(db.as_ref(), &passcode, current_passcode.as_deref())
}

#[tauri::command]
pub async fn unlock_password_vault(
    state: State<'_, AppState>,
    passcode: String,
) -> CmdResult<credential_vault::VaultAccessStatus> {
    let db = state.monitor.get_db();
    state
        .vault_access
        .unlock_with_passcode(db.as_ref(), &passcode)
}

#[tauri::command]
pub async fn lock_password_vault(
    state: State<'_, AppState>,
) -> CmdResult<credential_vault::VaultAccessStatus> {
    let db = state.monitor.get_db();
    state.vault_access.lock(db.as_ref())
}

#[tauri::command]
pub async fn get_password_credential_secret(
    state: State<'_, AppState>,
    credential_id: String,
) -> CmdResult<credential_vault::CredentialSecretView> {
    let db = state.monitor.get_db();
    state
        .vault_access
        .require_active_unlock(
            db.as_ref(),
            credential_vault::VAULT_SECRET_UNLOCK_REQUIRED_MESSAGE,
        )?;
    credential_vault::get_credential_secret(db.as_ref(), &credential_id)
}

#[tauri::command]
pub async fn save_password_credential(
    state: State<'_, AppState>,
    site_input: String,
    username: String,
    password: String,
) -> CmdResult<credential_vault::CredentialSummary> {
    let db = state.monitor.get_db();
    credential_vault::save_credential(
        db.as_ref(),
        &site_input,
        None,
        &username,
        &password,
        "manual",
    )
}

#[tauri::command]
pub async fn update_password_credential(
    state: State<'_, AppState>,
    credential_id: String,
    site_input: String,
    username: String,
    password: Option<String>,
) -> CmdResult<credential_vault::CredentialSummary> {
    let db = state.monitor.get_db();
    state
        .vault_access
        .require_active_unlock(db.as_ref(), credential_vault::VAULT_MANAGE_REQUIRED_MESSAGE)?;
    credential_vault::update_credential(
        db.as_ref(),
        &credential_id,
        &site_input,
        None,
        &username,
        password.as_deref(),
    )
}

#[tauri::command]
pub async fn delete_password_credential(
    state: State<'_, AppState>,
    credential_id: String,
) -> CmdResult<()> {
    let db = state.monitor.get_db();
    state
        .vault_access
        .require_active_unlock(db.as_ref(), credential_vault::VAULT_MANAGE_REQUIRED_MESSAGE)?;
    credential_vault::delete_credential(db.as_ref(), &credential_id)
}

#[tauri::command]
pub async fn get_browser_extension_status(
    state: State<'_, AppState>,
) -> CmdResult<credential_vault::BrowserExtensionStatus> {
    let db = state.monitor.get_db();
    credential_vault::get_extension_status(db.as_ref(), state.browser_bridge.is_running())
}

#[tauri::command]
pub async fn reset_browser_extension_pairing(
    state: State<'_, AppState>,
) -> CmdResult<credential_vault::BrowserExtensionStatus> {
    let db = state.monitor.get_db();
    credential_vault::reset_extension_pairing(db.as_ref(), state.browser_bridge.is_running())
}

#[tauri::command]
pub async fn check_url(state: State<'_, AppState>, url: String) -> CmdResult<UrlScanResult> {
    const COMPILED_KEY: Option<&str> = option_env!("VIRUSTOTAL_API_KEY");

    let features = url_scanner::extract_features(&url)?;
    let normalized_url = features.normalized_url.clone();

    let api_key = state
        .monitor
        .get_db()
        .get_setting("virustotal_api_key")
        .map_err(to_cmd_err)?
        .filter(|key| !key.trim().is_empty())
        .or_else(|| COMPILED_KEY.map(String::from))
        .filter(|key| !key.trim().is_empty());

    let virustotal_configured = api_key.is_some();

    let (virustotal_result, virustotal_error) = if let Some(api_key) = api_key.as_deref() {
        let scan = match features.scan_target {
            url_scanner::ScanTarget::IpAddress => {
                virustotal::scan_ip(&features.domain, api_key).await
            }
            url_scanner::ScanTarget::Domain => {
                virustotal::scan_domain(&features.domain, api_key).await
            }
            url_scanner::ScanTarget::Url => virustotal::scan_url(&normalized_url, api_key).await,
        };

        match scan {
            Ok(result) => (Some(result), None),
            Err(err) => (None, Some(err)),
        }
    } else {
        (None, None)
    };

    let (verdict, verdict_source) = if let Some(result) = virustotal_result.as_ref() {
        (
            virustotal_verdict(result).to_string(),
            "virustotal".to_string(),
        )
    } else {
        (
            local_verdict(features.local_risk_score).to_string(),
            "local".to_string(),
        )
    };

    Ok(UrlScanResult {
        scan_target: features.scan_target,
        normalized_url,
        domain: features.domain,
        local_risk_score: features.local_risk_score,
        is_ip_address: features.is_ip_address,
        uses_https: features.uses_https,
        subdomain_depth: features.subdomain_depth,
        url_length: features.url_length,
        suspicious_keywords: features.suspicious_keywords,
        heuristics: features.heuristics,
        virustotal: virustotal_result,
        virustotal_configured,
        virustotal_error,
        verdict,
        verdict_source,
    })
}

fn virustotal_verdict(result: &virustotal::VTResult) -> &'static str {
    if result.malicious > 0 {
        "MALICIOUS"
    } else if result.suspicious > 0 {
        "SUSPICIOUS"
    } else {
        "CLEAN"
    }
}

fn local_verdict(score: u8) -> &'static str {
    if score >= 70 {
        "MALICIOUS"
    } else if score >= 35 {
        "SUSPICIOUS"
    } else {
        "CLEAN"
    }
}

fn build_password_health_alert(
    compromised_count: u32,
    weak_compromised_count: u32,
    affected_sites: Vec<String>,
) -> PasswordHealthAlert {
    let last_checked_at = Utc::now().to_rfc3339();
    if compromised_count == 0 {
        return PasswordHealthAlert {
            has_alert: false,
            severity: "info".to_string(),
            title: "No compromised saved passwords detected".to_string(),
            summary: "Threat Guard did not find any saved passwords in known breach data during the latest password exposure check."
                .to_string(),
            recommendation: "Keep reviewing password health regularly and change any reused or weak passwords."
                .to_string(),
            risk_score: 0,
            compromised_count: 0,
            weak_compromised_count: 0,
            affected_sites,
            last_checked_at,
        };
    }

    let severity = if weak_compromised_count > 0 || compromised_count > 1 {
        "high"
    } else {
        "medium"
    };
    let risk_score = if weak_compromised_count > 0 {
        92
    } else if compromised_count > 1 {
        82
    } else {
        68
    };
    let title = if weak_compromised_count > 0 {
        "Weak compromised password needs to be changed"
    } else if compromised_count == 1 {
        "Compromised saved password detected"
    } else {
        "Compromised saved passwords detected"
    };

    let site_summary = if affected_sites.is_empty() {
        String::new()
    } else {
        format!(" Affected accounts include {}.", affected_sites.join(", "))
    };

    let summary = if weak_compromised_count > 0 {
        format!(
            "Threat Guard found {compromised_count} saved password{} in known breach data. {weak_compromised_count} of them {} also weak and should be changed immediately.{site_summary}",
            if compromised_count == 1 { "" } else { "s" },
            if weak_compromised_count == 1 { "is" } else { "are" },
        )
    } else {
        format!(
            "Threat Guard found {compromised_count} saved password{} in known breach data. Those passwords should be changed soon.{site_summary}",
            if compromised_count == 1 { "" } else { "s" },
        )
    };

    PasswordHealthAlert {
        has_alert: true,
        severity: severity.to_string(),
        title: title.to_string(),
        summary,
        recommendation:
            "Open Password Manager, update the affected saved credentials, and replace those passwords on the matching websites."
                .to_string(),
        risk_score,
        compromised_count,
        weak_compromised_count,
        affected_sites,
        last_checked_at,
    }
}

fn is_weak_password_label(label: &str) -> bool {
    matches!(label, "Very Weak" | "Weak")
}

async fn get_breach_count(prefix: &str, suffix: &str) -> CmdResult<u32> {
    let client = reqwest::Client::new();
    let response = client
        .get(format!("https://api.pwnedpasswords.com/range/{prefix}"))
        .header("User-Agent", "threat-guard-password-checker")
        .header("Add-Padding", "true")
        .send()
        .await
        .map_err(to_cmd_err)?;

    if !response.status().is_success() {
        return Err(format!(
            "Password breach lookup failed with status {}",
            response.status()
        ));
    }

    let body = response.text().await.map_err(to_cmd_err)?;
    for line in body.lines() {
        let mut parts = line.splitn(2, ':');
        let returned_suffix = parts.next().unwrap_or("").trim();
        let count = parts
            .next()
            .unwrap_or("0")
            .trim()
            .parse::<u32>()
            .unwrap_or(0);

        if returned_suffix.eq_ignore_ascii_case(suffix) {
            return Ok(count);
        }
    }

    Ok(0)
}

#[tauri::command]
pub async fn ask_ai_about_process(
    state: State<'_, AppState>,
    process_id: String,
    question: String,
    history: Option<Vec<AiChatMessage>>,
) -> CmdResult<String> {
    use ai_explainer::client::{AiClientConfig, AiProvider};
    use ai_explainer::{AiClient, ContextBuilder};

    // Compiled-in key (from .env at build time) - users never need to configure anything.
    // Settings DB can override it (e.g. if someone wants to use their own key).
    const COMPILED_KEY: Option<&str> = option_env!("GROQ_API_KEY");

    let db = state.monitor.get_db();

    let api_key = db
        .get_setting("groq_api_key")
        .map_err(to_cmd_err)?
        .filter(|k| !k.trim().is_empty())
        .or_else(|| COMPILED_KEY.map(String::from))
        .filter(|k| !k.trim().is_empty());

    if api_key.is_none() {
        return Err("AI not configured. Add your Groq API key in Settings.".to_string());
    }

    let process = db
        .get_process_by_id(&process_id)
        .map_err(to_cmd_err)?
        .ok_or_else(|| "Process not found".to_string())?;

    let metrics = db
        .get_process_metrics(&process_id, 20)
        .map_err(to_cmd_err)?;
    let alerts = db.list_alerts(10).map_err(to_cmd_err)?;
    let process_alerts: Vec<_> = alerts
        .into_iter()
        .filter(|alert| alert.process_id == process_id)
        .collect();

    let parent_name = process.parent_pid.and_then(|ppid| {
        db.list_processes().ok().and_then(|processes| {
            processes
                .into_iter()
                .find(|process| process.pid == ppid)
                .map(|process| process.name)
        })
    });

    let ctx = ContextBuilder::build(
        &process,
        parent_name,
        &metrics,
        &process_alerts,
        false,
        false,
    );

    let config = AiClientConfig {
        provider: AiProvider::Groq,
        api_key,
        model: "llama-3.3-70b-versatile".to_string(),
        base_url: None,
    };

    let client = AiClient::new(config);
    let conversation_history = format_chat_history(history.as_deref());
    let response = client
        .ask_about_process(&ctx, conversation_history.as_deref(), &question)
        .await
        .map_err(to_cmd_err)?;

    let conv = AiConversation {
        id: Uuid::new_v4().to_string(),
        process_id: Some(process_id),
        created_at: Utc::now(),
        prompt: question,
        response: response.clone(),
        context_json: serde_json::to_value(&ctx).unwrap_or_default(),
    };
    let _ = db.insert_ai_conversation(&conv);

    Ok(response)
}

#[tauri::command]
pub async fn remove_startup_entry(
    state: State<'_, AppState>,
    entry_id: String,
    name: String,
    location_type: String,
) -> CmdResult<()> {
    let loc = match location_type.as_str() {
        "RegistryRunKey" => StartupLocationType::RegistryRunKey,
        "RegistryRunOnceKey" => StartupLocationType::RegistryRunOnceKey,
        "StartupFolder" => StartupLocationType::StartupFolder,
        "ScheduledTask" => StartupLocationType::ScheduledTask,
        "Service" => StartupLocationType::Service,
        _ => StartupLocationType::Unknown,
    };
    state
        .monitor
        .remove_startup_entry(&entry_id, &name, &loc)
        .await
        .map_err(to_cmd_err)
}

#[tauri::command]
pub async fn get_setting(state: State<'_, AppState>, key: String) -> CmdResult<Option<String>> {
    state.monitor.get_db().get_setting(&key).map_err(to_cmd_err)
}

#[tauri::command]
pub async fn save_setting(state: State<'_, AppState>, key: String, value: String) -> CmdResult<()> {
    state
        .monitor
        .get_db()
        .set_setting(&key, &value)
        .map_err(to_cmd_err)
}

#[tauri::command]
pub async fn run_cleanup_now(state: State<'_, AppState>, hours: u32) -> CmdResult<usize> {
    state
        .monitor
        .get_db()
        .cleanup_old_processes(hours)
        .map_err(to_cmd_err)
}

#[tauri::command]
pub async fn list_activity_events(
    state: State<'_, AppState>,
    limit: Option<u32>,
) -> CmdResult<Value> {
    let db = state.monitor.get_db();
    let events = db.list_events(limit.unwrap_or(300)).map_err(to_cmd_err)?;
    serde_json::to_value(events).map_err(to_cmd_err)
}

#[tauri::command]
pub async fn list_activity_events_paged(
    state: State<'_, AppState>,
    limit: u32,
    offset: u32,
) -> CmdResult<Value> {
    let db = state.monitor.get_db();
    let (events, total) = db.list_events_paged(limit, offset).map_err(to_cmd_err)?;
    serde_json::to_value(serde_json::json!({ "events": events, "total": total }))
        .map_err(to_cmd_err)
}

#[tauri::command]
pub async fn ask_ai(
    state: State<'_, AppState>,
    question: String,
    history: Option<Vec<AiChatMessage>>,
) -> CmdResult<String> {
    use ai_explainer::client::{AiClientConfig, AiProvider};
    use ai_explainer::prompts::{build_general_system_prompt, build_system_context_prompt};
    use ai_explainer::AiClient;

    const COMPILED_KEY: Option<&str> = option_env!("GROQ_API_KEY");

    let db = state.monitor.get_db();

    let api_key = db
        .get_setting("groq_api_key")
        .map_err(to_cmd_err)?
        .filter(|k| !k.trim().is_empty())
        .or_else(|| COMPILED_KEY.map(String::from))
        .filter(|k| !k.trim().is_empty());

    if api_key.is_none() {
        return Err("AI not configured. Add your Groq API key in Settings.".to_string());
    }

    let overview = state.monitor.get_system_overview().await;
    let (top_processes, _) = db
        .list_processes_paged("", "", "risk_score", false, 10, 0)
        .map_err(to_cmd_err)?;
    let alerts = db.list_alerts(20).map_err(to_cmd_err)?;
    let startup = db.list_startup_entries().map_err(to_cmd_err)?;
    let events = db.list_events(50).map_err(to_cmd_err)?;

    let mut context = format!(
        "System health score: {}/100\nCPU usage: {:.1}%\nMemory usage: {:.1}%\nMonitored processes: {}\nActive alerts: {}\nSuspicious processes: {}\nStartup changes detected: {}\n",
        overview.health_score,
        overview.cpu_usage,
        overview.memory_usage,
        overview.monitored_processes_count,
        overview.active_alerts_count,
        overview.suspicious_processes_count,
        overview.startup_changes_count,
    );

    let risky: Vec<_> = top_processes
        .iter()
        .filter(|process| process.risk_score > 0)
        .collect();
    if risky.is_empty() {
        context.push_str("\nNo risky processes are currently standing out.\n");
    } else {
        context.push_str("\nHighest-risk processes:\n");
        for process in risky.iter().take(8) {
            context.push_str(&format!(
                "- {} (PID {}): risk {}/100, {}, {}, status {}\n",
                process.name,
                process.pid,
                process.risk_score,
                signer_status_label(&process.signer_status),
                path_category_label(&process.path_category),
                process_status_label(&process.current_status),
            ));
        }
    }

    let open_alerts: Vec<_> = alerts
        .iter()
        .filter(|alert| matches!(alert.status, AlertStatus::Open))
        .collect();
    if open_alerts.is_empty() {
        context.push_str("\nNo open alerts.\n");
    } else {
        context.push_str("\nOpen alerts:\n");
        for alert in open_alerts.iter().take(8) {
            context.push_str(&format!(
                "- [{}] {} (risk {})\n",
                alert.severity.as_str(),
                alert.title,
                alert.risk_score
            ));
        }
    }

    let notable_startup: Vec<_> = startup
        .iter()
        .filter(|entry| !matches!(entry.signer_status, SignerStatus::Signed))
        .collect();
    if startup.is_empty() {
        context.push_str("\nNo startup entries are currently recorded.\n");
    } else if notable_startup.is_empty() {
        context.push_str(&format!(
            "\nStartup entries monitored: {}. None stand out based on signature status.\n",
            startup.len()
        ));
    } else {
        context.push_str(&format!(
            "\nNotable startup entries ({} total):\n",
            startup.len()
        ));
        for entry in notable_startup.iter().take(8) {
            let flag = if entry.is_new { " [new]" } else { "" };
            context.push_str(&format!(
                "- {}: {} ({}){}\n",
                entry.name,
                entry.path,
                signer_status_label(&entry.signer_status),
                flag
            ));
        }
    }

    let event_counts = events.iter().fold((0u32, 0u32, 0u32, 0u32), |acc, event| {
        match event.event_type.as_str() {
            "process_created" => (acc.0 + 1, acc.1, acc.2, acc.3),
            "alert" => (acc.0, acc.1 + 1, acc.2, acc.3),
            "startup" => (acc.0, acc.1, acc.2 + 1, acc.3),
            "user_action" => (acc.0, acc.1, acc.2, acc.3 + 1),
            _ => acc,
        }
    });
    context.push_str(&format!(
        "\nRecent activity summary (last 30 days): {} process starts, {} alerts, {} startup events, {} user actions\n",
        event_counts.0, event_counts.1, event_counts.2, event_counts.3
    ));
    if !events.is_empty() {
        context.push_str("\nLatest events:\n");
        for event in events.iter().take(6) {
            context.push_str(&format!(
                "- [{}] {}: {}\n",
                event.severity, event.title, event.description
            ));
        }
    }

    let config = AiClientConfig {
        provider: AiProvider::Groq,
        api_key,
        model: "llama-3.3-70b-versatile".to_string(),
        base_url: None,
    };

    let client = AiClient::new(config);
    let system = build_general_system_prompt();
    let conversation_history = format_chat_history(history.as_deref());
    let prompt = build_system_context_prompt(&context, conversation_history.as_deref(), &question);

    let response = client
        .call_raw(&system, &prompt)
        .await
        .map_err(to_cmd_err)?;

    let conv = AiConversation {
        id: Uuid::new_v4().to_string(),
        process_id: None,
        created_at: Utc::now(),
        prompt: question,
        response: response.clone(),
        context_json: serde_json::json!({
            "type": "general",
            "context": context,
            "history": conversation_history,
        }),
    };
    let _ = db.insert_ai_conversation(&conv);

    Ok(response)
}

#[tauri::command]
pub async fn pause_monitoring(state: State<'_, AppState>) -> CmdResult<()> {
    state.monitor.pause().await;
    Ok(())
}

#[tauri::command]
pub async fn resume_monitoring(state: State<'_, AppState>) -> CmdResult<()> {
    state.monitor.resume().await;
    Ok(())
}
