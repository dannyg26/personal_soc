use crate::password;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::Utc;
use monitor_core::persistence::{CredentialRecord, Database};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;
use uuid::Uuid;

pub const BROWSER_BRIDGE_PORT: u16 = 38913;
pub const VAULT_UNLOCK_WINDOW_SECONDS: u64 = 300;
pub const VAULT_UNLOCK_REQUIRED_MESSAGE: &str =
    "Enter your 6-digit Threat Guard passcode to unlock saved credentials.";
pub const VAULT_MANAGE_REQUIRED_MESSAGE: &str =
    "Unlock the password vault with your 6-digit Threat Guard passcode to manage saved credentials.";
pub const VAULT_SECRET_UNLOCK_REQUIRED_MESSAGE: &str =
    "Unlock the password vault with your 6-digit Threat Guard passcode before revealing a saved password.";
pub const VAULT_AUTOFILL_UNLOCK_REQUIRED_MESSAGE: &str =
    "Enter your Threat Guard vault passcode to autofill on this site.";
pub const VAULT_SETUP_REQUIRED_MESSAGE: &str =
    "Create a 6-digit Threat Guard vault passcode in Password Manager first.";

const PAIR_CODE_KEY: &str = "browser_bridge_pair_code";
const ACCESS_TOKEN_KEY: &str = "browser_bridge_access_token";
const LAST_PAIRED_AT_KEY: &str = "browser_bridge_last_paired_at";
const VAULT_PASSCODE_HASH_KEY: &str = "password_vault_passcode_hash";
const VAULT_PASSCODE_SALT_KEY: &str = "password_vault_passcode_salt";

#[derive(Clone, Serialize)]
pub struct CredentialSummary {
    pub id: String,
    pub origin: String,
    pub match_key: String,
    pub site_label: String,
    pub username: String,
    pub created_at: String,
    pub updated_at: String,
    pub source: String,
}

#[derive(Clone, Serialize)]
pub struct CredentialSecretView {
    pub id: String,
    pub username: String,
    pub password: String,
}

#[derive(Clone, Serialize)]
pub struct AutofillCredentialView {
    pub id: String,
    pub origin: String,
    pub site_label: String,
    pub username: String,
    pub password: String,
}

#[derive(Clone, Serialize)]
pub struct VaultAccessStatus {
    pub configured: bool,
    pub unlocked: bool,
    pub unlock_window_seconds: u64,
}

#[derive(Clone, Serialize)]
pub struct PasswordVaultRiskSummary {
    pub has_alerts: bool,
    pub at_risk_count: u32,
    pub weak_count: u32,
    pub reused_count: u32,
}

#[derive(Clone, Serialize)]
pub struct BrowserExtensionStatus {
    pub port: u16,
    pub running: bool,
    pub pair_code: String,
    pub paired: bool,
    pub last_paired_at: Option<String>,
}

#[derive(Clone)]
pub struct NormalizedSite {
    pub origin: String,
    pub match_key: String,
    pub site_label: String,
}

#[derive(Deserialize, Serialize)]
struct CredentialSecret {
    username: String,
    password: String,
}

#[derive(Clone)]
pub(crate) struct CredentialSecurityReview {
    pub site_label: String,
    pub password: String,
}

#[derive(Clone)]
pub struct VaultAccessController {
    unlocked_until: Arc<Mutex<Option<Instant>>>,
    session_ttl: Duration,
}

impl VaultAccessController {
    pub fn new() -> Self {
        Self {
            unlocked_until: Arc::new(Mutex::new(None)),
            session_ttl: Duration::from_secs(VAULT_UNLOCK_WINDOW_SECONDS),
        }
    }

    pub fn status(&self, db: &Database) -> Result<VaultAccessStatus, String> {
        Ok(VaultAccessStatus {
            configured: has_configured_passcode(db)?,
            unlocked: self.is_unlocked(),
            unlock_window_seconds: VAULT_UNLOCK_WINDOW_SECONDS,
        })
    }

    pub fn lock(&self, db: &Database) -> Result<VaultAccessStatus, String> {
        let mut guard = self.unlocked_until.lock().unwrap();
        *guard = None;
        drop(guard);
        self.status(db)
    }

    pub fn is_unlocked(&self) -> bool {
        let mut guard = self.unlocked_until.lock().unwrap();
        match *guard {
            Some(deadline) if Instant::now() < deadline => true,
            Some(_) => {
                *guard = None;
                false
            }
            None => false,
        }
    }

    pub fn require_active_unlock(&self, db: &Database, message: &str) -> Result<(), String> {
        if !has_configured_passcode(db)? {
            return Err(VAULT_SETUP_REQUIRED_MESSAGE.to_string());
        }

        if self.is_unlocked() {
            Ok(())
        } else {
            Err(message.to_string())
        }
    }

    pub fn unlock_with_passcode(
        &self,
        db: &Database,
        passcode: &str,
    ) -> Result<VaultAccessStatus, String> {
        if self.is_unlocked() {
            return self.status(db);
        }

        verify_passcode(db, passcode)?;
        self.mark_unlocked();
        self.status(db)
    }

    pub fn set_passcode(
        &self,
        db: &Database,
        passcode: &str,
        current_passcode: Option<&str>,
    ) -> Result<VaultAccessStatus, String> {
        let normalized = normalize_passcode(passcode)?;

        if has_configured_passcode(db)? && !self.is_unlocked() {
            let current = current_passcode.ok_or_else(|| {
                "Enter your current 6-digit Threat Guard passcode to change it.".to_string()
            })?;
            verify_passcode(db, current)?;
        }

        let salt = Uuid::new_v4().to_string();
        let hash = hash_passcode(&salt, normalized);
        db.set_setting(VAULT_PASSCODE_HASH_KEY, &hash)
            .map_err(to_err)?;
        db.set_setting(VAULT_PASSCODE_SALT_KEY, &salt)
            .map_err(to_err)?;

        self.mark_unlocked();
        self.status(db)
    }

    fn mark_unlocked(&self) {
        let mut guard = self.unlocked_until.lock().unwrap();
        *guard = Some(Instant::now() + self.session_ttl);
    }
}

pub fn list_credentials(db: &Database) -> Result<Vec<CredentialSummary>, String> {
    db.list_credentials()
        .map_err(to_err)?
        .into_iter()
        .map(record_to_summary)
        .collect()
}

pub fn list_autofill_credentials_for_origin(
    db: &Database,
    origin: &str,
) -> Result<Vec<AutofillCredentialView>, String> {
    let normalized = normalize_site_input(origin)?;
    db.list_credentials_by_match_key(&normalized.match_key)
        .map_err(to_err)?
        .into_iter()
        .map(record_to_autofill_view)
        .collect()
}

pub(crate) fn list_credentials_for_security_review(
    db: &Database,
) -> Result<Vec<CredentialSecurityReview>, String> {
    db.list_credentials()
        .map_err(to_err)?
        .into_iter()
        .map(|record| {
            let secret = decrypt_credential_secret(&record.encrypted_payload)?;
            Ok(CredentialSecurityReview {
                site_label: record.site_label.unwrap_or_else(|| "Website".to_string()),
                password: secret.password,
            })
        })
        .collect()
}

pub fn has_autofill_credentials_for_origin(db: &Database, origin: &str) -> Result<bool, String> {
    let normalized = normalize_site_input(origin)?;
    Ok(!db
        .list_credentials_by_match_key(&normalized.match_key)
        .map_err(to_err)?
        .is_empty())
}

pub fn get_credential_secret(
    db: &Database,
    credential_id: &str,
) -> Result<CredentialSecretView, String> {
    let record = find_credential_record(db, credential_id)?;

    let secret = decrypt_credential_secret(&record.encrypted_payload)?;
    Ok(CredentialSecretView {
        id: record.id,
        username: secret.username,
        password: secret.password,
    })
}

pub fn get_password_risk_summary(db: &Database) -> Result<PasswordVaultRiskSummary, String> {
    let records = db.list_credentials().map_err(to_err)?;
    let mut weak_ids = HashSet::new();
    let mut passwords_by_secret: HashMap<String, Vec<String>> = HashMap::new();

    for record in records {
        let record_id = record.id.clone();
        let secret = decrypt_credential_secret(&record.encrypted_payload)?;
        let analysis = password::analyze(&secret.password);

        if is_weak_strength(&analysis.strength_label) {
            weak_ids.insert(record_id.clone());
        }

        passwords_by_secret
            .entry(secret.password)
            .or_default()
            .push(record_id);
    }

    let mut reused_ids = HashSet::new();
    for credential_ids in passwords_by_secret.values() {
        if credential_ids.len() > 1 {
            reused_ids.extend(credential_ids.iter().cloned());
        }
    }

    let at_risk_count = weak_ids.union(&reused_ids).count() as u32;
    let weak_count = weak_ids.len() as u32;
    let reused_count = reused_ids.len() as u32;

    Ok(PasswordVaultRiskSummary {
        has_alerts: at_risk_count > 0,
        at_risk_count,
        weak_count,
        reused_count,
    })
}

pub fn save_credential(
    db: &Database,
    site_input: &str,
    site_label: Option<&str>,
    username: &str,
    password: &str,
    source: &str,
) -> Result<CredentialSummary, String> {
    let username = username.trim();
    if username.is_empty() {
        return Err("Username is required.".to_string());
    }

    if password.is_empty() {
        return Err("Password is required.".to_string());
    }

    let normalized = normalize_site_input(site_input)?;
    let chosen_label = site_label
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(&normalized.site_label)
        .to_string();

    let secret = CredentialSecret {
        username: username.to_string(),
        password: password.to_string(),
    };
    let encrypted_payload = encrypt_bytes(
        &serde_json::to_vec(&secret)
            .map_err(|err| format!("Failed to serialize credential: {err}"))?,
    )?;

    let now = Utc::now().to_rfc3339();
    let existing = db
        .list_credentials_by_match_key(&normalized.match_key)
        .map_err(to_err)?;

    for record in existing {
        let stored_secret = decrypt_credential_secret(&record.encrypted_payload)?;
        if normalize_username(&stored_secret.username) == normalize_username(username) {
            let updated = CredentialRecord {
                id: record.id,
                origin: normalized.origin.clone(),
                match_key: normalized.match_key.clone(),
                site_label: Some(chosen_label.clone()),
                encrypted_payload,
                created_at: record.created_at,
                updated_at: now,
                source: source.to_string(),
            };

            db.update_credential(&updated).map_err(to_err)?;
            return record_to_summary(updated);
        }
    }

    let created = CredentialRecord {
        id: Uuid::new_v4().to_string(),
        origin: normalized.origin,
        match_key: normalized.match_key,
        site_label: Some(chosen_label),
        encrypted_payload,
        created_at: now.clone(),
        updated_at: now,
        source: source.to_string(),
    };

    db.insert_credential(&created).map_err(to_err)?;
    record_to_summary(created)
}

pub fn update_credential(
    db: &Database,
    credential_id: &str,
    site_input: &str,
    site_label: Option<&str>,
    username: &str,
    password: Option<&str>,
) -> Result<CredentialSummary, String> {
    let existing = find_credential_record(db, credential_id)?;
    let username = username.trim();
    if username.is_empty() {
        return Err("Username is required.".to_string());
    }

    let normalized = normalize_site_input(site_input)?;
    let chosen_label = site_label
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .or(existing.site_label.clone())
        .unwrap_or_else(|| normalized.site_label.clone());
    let existing_secret = decrypt_credential_secret(&existing.encrypted_payload)?;

    let conflicting_record = db
        .list_credentials_by_match_key(&normalized.match_key)
        .map_err(to_err)?
        .into_iter()
        .find(|record| {
            if record.id == existing.id {
                return false;
            }

            decrypt_credential_secret(&record.encrypted_payload)
                .map(|secret| normalize_username(&secret.username) == normalize_username(username))
                .unwrap_or(false)
        });

    if conflicting_record.is_some() {
        return Err(
            "Another saved credential already uses that username on this site.".to_string(),
        );
    }

    let next_password = password
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .unwrap_or(existing_secret.password);

    let secret = CredentialSecret {
        username: username.to_string(),
        password: next_password,
    };
    let encrypted_payload = encrypt_bytes(
        &serde_json::to_vec(&secret)
            .map_err(|err| format!("Failed to serialize credential: {err}"))?,
    )?;

    let updated = CredentialRecord {
        id: existing.id,
        origin: normalized.origin,
        match_key: normalized.match_key,
        site_label: Some(chosen_label),
        encrypted_payload,
        created_at: existing.created_at,
        updated_at: Utc::now().to_rfc3339(),
        source: existing.source,
    };

    db.update_credential(&updated).map_err(to_err)?;
    record_to_summary(updated)
}

pub fn delete_credential(db: &Database, id: &str) -> Result<(), String> {
    db.delete_credential(id).map_err(to_err)
}

pub fn confirm_passcode(db: &Database, passcode: &str) -> Result<(), String> {
    verify_passcode(db, passcode)
}

pub fn ensure_pair_code(db: &Database) -> Result<String, String> {
    if let Some(code) = db.get_setting(PAIR_CODE_KEY).map_err(to_err)? {
        let trimmed = code.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }

    let code = generate_pair_code();
    db.set_setting(PAIR_CODE_KEY, &code).map_err(to_err)?;
    Ok(code)
}

pub fn get_extension_status(
    db: &Database,
    running: bool,
) -> Result<BrowserExtensionStatus, String> {
    let pair_code = ensure_pair_code(db)?;
    let paired = db
        .get_setting(ACCESS_TOKEN_KEY)
        .map_err(to_err)?
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false);
    let last_paired_at = db
        .get_setting(LAST_PAIRED_AT_KEY)
        .map_err(to_err)?
        .filter(|value| !value.trim().is_empty());

    Ok(BrowserExtensionStatus {
        port: BROWSER_BRIDGE_PORT,
        running,
        pair_code,
        paired,
        last_paired_at,
    })
}

pub fn reset_extension_pairing(
    db: &Database,
    running: bool,
) -> Result<BrowserExtensionStatus, String> {
    let new_code = generate_pair_code();
    db.set_setting(PAIR_CODE_KEY, &new_code).map_err(to_err)?;
    db.set_setting(ACCESS_TOKEN_KEY, "").map_err(to_err)?;
    db.set_setting(LAST_PAIRED_AT_KEY, "").map_err(to_err)?;
    get_extension_status(db, running)
}

pub fn pair_extension(db: &Database, pair_code: &str) -> Result<String, String> {
    let expected = ensure_pair_code(db)?;
    if !expected.eq_ignore_ascii_case(pair_code.trim()) {
        return Err("Pair code did not match Threat Guard.".to_string());
    }

    let token = Uuid::new_v4().to_string();
    db.set_setting(ACCESS_TOKEN_KEY, &token).map_err(to_err)?;
    db.set_setting(LAST_PAIRED_AT_KEY, &Utc::now().to_rfc3339())
        .map_err(to_err)?;
    Ok(token)
}

pub fn validate_extension_token(db: &Database, token: &str) -> Result<bool, String> {
    let saved = db.get_setting(ACCESS_TOKEN_KEY).map_err(to_err)?;
    Ok(saved
        .map(|value| !value.trim().is_empty() && value.trim() == token.trim())
        .unwrap_or(false))
}

pub fn normalize_site_input(site_input: &str) -> Result<NormalizedSite, String> {
    let trimmed = site_input.trim();
    if trimmed.is_empty() {
        return Err("A website origin is required.".to_string());
    }

    let candidate = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    };

    let parsed = Url::parse(&candidate)
        .map_err(|_| "Threat Guard could not understand that website. Try something like youtube.com or https://youtube.com.".to_string())?;

    let scheme = parsed.scheme().to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err("Only http and https websites are supported for browser autofill.".to_string());
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| "The website is missing a host.".to_string())?
        .trim_end_matches('.')
        .to_ascii_lowercase();

    let mut origin = format!("{scheme}://{host}");
    if let Some(port) = parsed.port() {
        origin.push(':');
        origin.push_str(&port.to_string());
    }

    Ok(NormalizedSite {
        origin,
        match_key: match_key_from_host(&host),
        site_label: host,
    })
}

fn record_to_summary(record: CredentialRecord) -> Result<CredentialSummary, String> {
    let secret = decrypt_credential_secret(&record.encrypted_payload)?;
    Ok(CredentialSummary {
        id: record.id,
        origin: record.origin,
        match_key: record.match_key,
        site_label: record.site_label.unwrap_or_else(|| "Website".to_string()),
        username: secret.username,
        created_at: record.created_at,
        updated_at: record.updated_at,
        source: record.source,
    })
}

fn record_to_autofill_view(record: CredentialRecord) -> Result<AutofillCredentialView, String> {
    let secret = decrypt_credential_secret(&record.encrypted_payload)?;
    Ok(AutofillCredentialView {
        id: record.id,
        origin: record.origin,
        site_label: record.site_label.unwrap_or_else(|| "Website".to_string()),
        username: secret.username,
        password: secret.password,
    })
}

fn decrypt_credential_secret(encrypted_payload: &[u8]) -> Result<CredentialSecret, String> {
    let decrypted = decrypt_bytes(encrypted_payload)?;
    serde_json::from_slice(&decrypted)
        .map_err(|err| format!("Failed to decode credential payload: {err}"))
}

fn find_credential_record(db: &Database, credential_id: &str) -> Result<CredentialRecord, String> {
    db.list_credentials()
        .map_err(to_err)?
        .into_iter()
        .find(|record| record.id == credential_id)
        .ok_or_else(|| "Threat Guard could not find that saved credential.".to_string())
}

fn normalize_username(username: &str) -> String {
    username.trim().to_ascii_lowercase()
}

fn is_weak_strength(strength_label: &str) -> bool {
    matches!(strength_label, "Very Weak" | "Weak")
}

fn match_key_from_host(host: &str) -> String {
    let host = host.trim().to_ascii_lowercase();
    if host.parse::<std::net::IpAddr>().is_ok() {
        return host;
    }

    let parts: Vec<&str> = host
        .split('.')
        .filter(|segment| !segment.is_empty())
        .collect();
    if parts.len() >= 2 {
        format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
    } else {
        host
    }
}

fn generate_pair_code() -> String {
    format!(
        "TG-{}",
        Uuid::new_v4()
            .simple()
            .to_string()
            .chars()
            .take(8)
            .collect::<String>()
            .to_ascii_uppercase()
    )
}

fn to_err(err: impl std::fmt::Display) -> String {
    err.to_string()
}

fn has_configured_passcode(db: &Database) -> Result<bool, String> {
    Ok(stored_passcode_record(db)?.is_some())
}

fn stored_passcode_record(db: &Database) -> Result<Option<(String, String)>, String> {
    let hash = db
        .get_setting(VAULT_PASSCODE_HASH_KEY)
        .map_err(to_err)?
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let salt = db
        .get_setting(VAULT_PASSCODE_SALT_KEY)
        .map_err(to_err)?
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    match (hash, salt) {
        (Some(hash), Some(salt)) => Ok(Some((hash, salt))),
        _ => Ok(None),
    }
}

fn verify_passcode(db: &Database, passcode: &str) -> Result<(), String> {
    let normalized = normalize_passcode(passcode)?;
    let (stored_hash, salt) = stored_passcode_record(db)?
        .ok_or_else(|| VAULT_SETUP_REQUIRED_MESSAGE.to_string())?;
    let candidate_hash = hash_passcode(&salt, normalized);

    if candidate_hash == stored_hash {
        Ok(())
    } else {
        Err("That Threat Guard vault passcode did not match.".to_string())
    }
}

fn normalize_passcode(passcode: &str) -> Result<&str, String> {
    let trimmed = passcode.trim();
    if trimmed.len() != 6 || !trimmed.chars().all(|character| character.is_ascii_digit()) {
        return Err("Use a 6-digit passcode for the Threat Guard vault.".to_string());
    }

    Ok(trimmed)
}

fn hash_passcode(salt: &str, passcode: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt.as_bytes());
    hasher.update(b":");
    hasher.update(passcode.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(windows)]
fn encrypt_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Cryptography::{CryptProtectData, CRYPT_INTEGER_BLOB};

    let mut input = CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB::default();

    unsafe {
        CryptProtectData(&mut input, PCWSTR::null(), None, None, None, 0, &mut output)
            .map_err(|err| format!("Windows DPAPI could not protect this credential: {err}"))?;

        let protected = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        let _ = LocalFree(HLOCAL(output.pbData.cast()));
        Ok(protected)
    }
}

#[cfg(windows)]
fn decrypt_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {
    use windows::core::PWSTR;
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB};

    let mut input = CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    let mut description = PWSTR::null();

    unsafe {
        CryptUnprotectData(
            &mut input,
            Some(&mut description),
            None,
            None,
            None,
            0,
            &mut output,
        )
        .map_err(|err| format!("Windows DPAPI could not unlock a saved credential: {err}"))?;

        let decrypted = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        let _ = LocalFree(HLOCAL(output.pbData.cast()));
        if !description.is_null() {
            let _ = LocalFree(HLOCAL(description.0.cast()));
        }
        Ok(decrypted)
    }
}

#[cfg(not(windows))]
fn encrypt_bytes(_bytes: &[u8]) -> Result<Vec<u8>, String> {
    Err("The encrypted credential vault is currently available on Windows builds.".to_string())
}

#[cfg(not(windows))]
fn decrypt_bytes(_bytes: &[u8]) -> Result<Vec<u8>, String> {
    Err("The encrypted credential vault is currently available on Windows builds.".to_string())
}
