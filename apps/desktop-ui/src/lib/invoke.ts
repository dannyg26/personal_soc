import { invoke } from '@tauri-apps/api/core';
import type {
  ProcessRecord,
  ProcessMetric,
  Alert,
  StartupEntry,
  SystemOverview,
  ActivityEvent,
  UrlScanResult,
  PasswordCheckResult,
  StoredCredential,
  StoredCredentialSecret,
  PasswordVaultStatus,
  PasswordVaultRiskSummary,
  PasswordHealthAlert,
  BrowserExtensionStatus,
} from '@/types';

export interface AiChatMessage {
  role: 'user' | 'assistant';
  content: string;
}

export async function getSystemOverview(): Promise<SystemOverview> {
  return invoke('get_system_overview');
}

export async function listProcesses(): Promise<ProcessRecord[]> {
  return invoke('list_processes');
}

export async function listProcessesPaged(
  search: string,
  statusFilter: string,
  sortKey: string,
  sortAsc: boolean,
  limit: number,
  offset: number,
): Promise<{ processes: ProcessRecord[]; total: number }> {
  return invoke('list_processes_paged', { search, statusFilter, sortKey, sortAsc, limit, offset });
}

export async function getProcessDetails(processId: string): Promise<ProcessRecord | null> {
  return invoke('get_process_details', { processId });
}

export async function getProcessMetrics(processId: string, limit?: number): Promise<ProcessMetric[]> {
  return invoke('get_process_metrics', { processId, limit });
}

export async function listAlerts(limit?: number): Promise<Alert[]> {
  return invoke('list_alerts', { limit });
}

export async function updateAlertStatus(alertId: string, status: string): Promise<void> {
  return invoke('update_alert_status', { alertId, status });
}

export async function killProcess(pid: number, processId: string): Promise<void> {
  return invoke('kill_process', { pid, processId });
}

export async function trustProcess(processId: string, ruleType: string, value: string): Promise<void> {
  return invoke('trust_process', { processId, ruleType, value });
}

export async function listStartupEntries(): Promise<StartupEntry[]> {
  return invoke('list_startup_entries');
}

export async function removeStartupEntry(entryId: string, name: string, locationType: string): Promise<void> {
  return invoke('remove_startup_entry', { entryId, name, locationType });
}

export async function askAiAboutProcess(
  processId: string,
  question: string,
  history?: AiChatMessage[],
): Promise<string> {
  return invoke('ask_ai_about_process', { processId, question, history });
}

export async function pauseMonitoring(): Promise<void> {
  return invoke('pause_monitoring');
}

export async function resumeMonitoring(): Promise<void> {
  return invoke('resume_monitoring');
}

export async function getSetting(key: string): Promise<string | null> {
  return invoke('get_setting', { key });
}

export async function saveSetting(key: string, value: string): Promise<void> {
  return invoke('save_setting', { key, value });
}

export async function runCleanupNow(hours: number): Promise<number> {
  return invoke('run_cleanup_now', { hours });
}

export async function listActivityEvents(limit?: number): Promise<ActivityEvent[]> {
  return invoke('list_activity_events', { limit });
}

export async function listActivityEventsPaged(
  limit: number,
  offset: number,
): Promise<{ events: ActivityEvent[]; total: number }> {
  return invoke('list_activity_events_paged', { limit, offset });
}

export async function askAi(question: string, history?: AiChatMessage[]): Promise<string> {
  return invoke('ask_ai', { question, history });
}

export async function checkUrl(url: string): Promise<UrlScanResult> {
  return invoke('check_url', { url });
}

export async function checkPassword(passwordInput: string): Promise<PasswordCheckResult> {
  return invoke('check_password', { passwordInput });
}

export async function listPasswordCredentials(): Promise<StoredCredential[]> {
  return invoke('list_password_credentials');
}

export async function getPasswordVaultStatus(): Promise<PasswordVaultStatus> {
  return invoke('get_password_vault_status');
}

export async function getPasswordVaultRiskSummary(): Promise<PasswordVaultRiskSummary> {
  return invoke('get_password_vault_risk_summary');
}

export async function getPasswordHealthAlert(): Promise<PasswordHealthAlert> {
  return invoke('get_password_health_alert');
}

export async function setPasswordVaultPasscode(
  passcode: string,
  currentPasscode?: string,
): Promise<PasswordVaultStatus> {
  return invoke('set_password_vault_passcode', { passcode, currentPasscode });
}

export async function unlockPasswordVault(passcode: string): Promise<PasswordVaultStatus> {
  return invoke('unlock_password_vault', { passcode });
}

export async function lockPasswordVault(): Promise<PasswordVaultStatus> {
  return invoke('lock_password_vault');
}

export async function getPasswordCredentialSecret(
  credentialId: string,
): Promise<StoredCredentialSecret> {
  return invoke('get_password_credential_secret', { credentialId });
}

export async function savePasswordCredential(
  siteInput: string,
  username: string,
  password: string,
): Promise<StoredCredential> {
  return invoke('save_password_credential', { siteInput, username, password });
}

export async function updatePasswordCredential(
  credentialId: string,
  siteInput: string,
  username: string,
  password?: string | null,
): Promise<StoredCredential> {
  return invoke('update_password_credential', {
    credentialId,
    siteInput,
    username,
    password,
  });
}

export async function deletePasswordCredential(credentialId: string): Promise<void> {
  return invoke('delete_password_credential', { credentialId });
}

export async function getBrowserExtensionStatus(): Promise<BrowserExtensionStatus> {
  return invoke('get_browser_extension_status');
}

export async function resetBrowserExtensionPairing(): Promise<BrowserExtensionStatus> {
  return invoke('reset_browser_extension_pairing');
}
