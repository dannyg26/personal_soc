export type SignerStatus = 'Signed' | 'Unsigned' | 'InvalidSignature' | 'Unknown';
export type PathCategory = 'System' | 'ProgramFiles' | 'UserWritable' | 'Temp' | 'Downloads' | 'AppData' | 'Unknown';
export type ProcessStatus = 'Running' | 'Terminated' | 'Suspicious' | 'Trusted';
export type Severity = 'info' | 'low' | 'medium' | 'high';
export type AlertStatus = 'open' | 'acknowledged' | 'ignored' | 'resolved';

export interface TriggeredRule {
  rule_key: string;
  explanation: string;
  evidence: Record<string, unknown>;
  weight: number;
}

export interface ProcessRecord {
  id: string;
  pid: number;
  parent_pid: number | null;
  name: string;
  exe_path: string | null;
  command_line: string | null;
  signer_status: SignerStatus;
  file_hash: string | null;
  first_seen_at: string;
  last_seen_at: string;
  user_name: string | null;
  integrity_level: string | null;
  current_status: ProcessStatus;
  risk_score: number;
  path_category: PathCategory;
}

export interface ProcessMetric {
  id: string;
  process_id: string;
  timestamp: string;
  cpu_percent: number;
  memory_bytes: number;
  network_bytes_sent: number;
  network_bytes_received: number;
}

export interface Alert {
  id: string;
  process_id: string;
  timestamp: string;
  severity: Severity;
  title: string;
  summary: string;
  status: AlertStatus;
  risk_score: number;
  triggered_rules: TriggeredRule[];
}

export interface StartupEntry {
  id: string;
  name: string;
  path: string;
  location_type: string;
  signer_status: SignerStatus;
  first_seen_at: string;
  last_seen_at: string;
  enabled: boolean;
  is_new: boolean;
}

export interface ActivityEvent {
  event_type: 'process_created' | 'process_terminated' | 'alert' | 'startup' | 'user_action';
  id: string;
  timestamp: string;
  title: string;
  description: string;
  severity: 'info' | 'low' | 'medium' | 'high';
  related_id: string | null;
}

export interface SystemOverview {
  health_score: number;
  active_alerts_count: number;
  suspicious_processes_count: number;
  startup_changes_count: number;
  monitored_processes_count: number;
  cpu_usage: number;
  memory_usage: number;
  timestamp: string;
}

export interface VirusTotalResult {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  permalink: string;
}

export interface UrlScanResult {
  scan_target: 'url' | 'domain' | 'ip_address';
  normalized_url: string;
  domain: string;
  local_risk_score: number;
  is_ip_address: boolean;
  uses_https: boolean;
  subdomain_depth: number;
  url_length: number;
  suspicious_keywords: string[];
  heuristics: string[];
  virustotal: VirusTotalResult | null;
  virustotal_configured: boolean;
  virustotal_error: string | null;
  verdict: 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS';
  verdict_source: 'virustotal' | 'local';
}

export interface PasswordCheckResult {
  entropy: number;
  crack_time_display: string;
  strength_label: 'Very Weak' | 'Weak' | 'Moderate' | 'Strong' | 'Very Strong';
  breach_count: number;
}

export interface StoredCredential {
  id: string;
  origin: string;
  match_key: string;
  site_label: string;
  username: string;
  created_at: string;
  updated_at: string;
  source: string;
}

export interface StoredCredentialSecret {
  id: string;
  username: string;
  password: string;
}

export interface PasswordVaultStatus {
  configured: boolean;
  unlocked: boolean;
  unlock_window_seconds: number;
}

export interface PasswordVaultRiskSummary {
  has_alerts: boolean;
  at_risk_count: number;
  weak_count: number;
  reused_count: number;
}

export interface PasswordHealthAlert {
  has_alert: boolean;
  severity: Severity;
  title: string;
  summary: string;
  recommendation: string;
  risk_score: number;
  compromised_count: number;
  weak_compromised_count: number;
  affected_sites: string[];
  last_checked_at: string;
}

export interface BrowserExtensionStatus {
  port: number;
  running: boolean;
  pair_code: string;
  paired: boolean;
  last_paired_at: string | null;
}
