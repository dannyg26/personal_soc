use anyhow::Result;
use chrono::Utc;
use uuid::Uuid;

use crate::collectors::process_collector::check_signature;
#[cfg(not(windows))]
use shared_types::models::SignerStatus;
use shared_types::models::{StartupEntry, StartupLocationType};

pub struct StartupCollector;

impl StartupCollector {
    pub fn new() -> Self {
        Self
    }

    pub fn collect_startup_entries(&self) -> Result<Vec<StartupEntry>> {
        #[cfg(windows)]
        {
            self.collect_windows_startup()
        }
        #[cfg(not(windows))]
        {
            self.collect_stub_startup()
        }
    }

    #[cfg(windows)]
    fn collect_windows_startup(&self) -> Result<Vec<StartupEntry>> {
        let mut entries = Vec::new();

        // HKLM Run key
        self.read_registry_run_key(
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            StartupLocationType::RegistryRunKey,
            &mut entries,
        );

        // HKCU Run key
        self.read_registry_run_key(
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            StartupLocationType::RegistryRunKey,
            &mut entries,
        );

        Ok(entries)
    }

    #[cfg(windows)]
    fn read_registry_run_key(
        &self,
        key_path: &str,
        location_type: StartupLocationType,
        entries: &mut Vec<StartupEntry>,
    ) {
        use windows::core::PCWSTR;
        use windows::Win32::System::Registry::{
            RegCloseKey, RegEnumValueW, RegOpenKeyExW, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE,
            KEY_READ, REG_SZ,
        };

        let (hive, subkey) = if key_path.starts_with("HKLM") {
            (HKEY_LOCAL_MACHINE, &key_path[5..])
        } else {
            (HKEY_CURRENT_USER, &key_path[5..])
        };

        let wide_key: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();

        unsafe {
            let mut hkey = Default::default();
            if RegOpenKeyExW(hive, PCWSTR(wide_key.as_ptr()), 0, KEY_READ, &mut hkey).is_ok() {
                let mut index = 0u32;
                loop {
                    let mut name_buf = vec![0u16; 16384];
                    let mut name_len = name_buf.len() as u32;
                    let mut data_buf = vec![0u8; 32768];
                    let mut data_len = data_buf.len() as u32;
                    let mut val_type = 0u32;

                    let result = RegEnumValueW(
                        hkey,
                        index,
                        windows::core::PWSTR(name_buf.as_mut_ptr()),
                        &mut name_len,
                        None,
                        Some(&mut val_type),
                        Some(data_buf.as_mut_ptr()),
                        Some(&mut data_len),
                    );

                    if result.is_err() {
                        break;
                    }

                    if val_type == REG_SZ.0 {
                        let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
                        let data_u16: Vec<u16> = data_buf[..data_len as usize]
                            .chunks_exact(2)
                            .map(|b| u16::from_le_bytes([b[0], b[1]]))
                            .collect();
                        let path = String::from_utf16_lossy(&data_u16)
                            .trim_end_matches('\0')
                            .to_string();

                        let signer = check_signature(&path);
                        let now = Utc::now();

                        entries.push(StartupEntry {
                            id: Uuid::new_v4().to_string(),
                            name,
                            path: path.clone(),
                            location_type: location_type.clone(),
                            signer_status: signer,
                            first_seen_at: now,
                            last_seen_at: now,
                            enabled: true,
                            is_new: false,
                        });
                    }

                    index += 1;
                }
                let _ = RegCloseKey(hkey);
            }
        }
    }

    #[cfg(not(windows))]
    fn collect_stub_startup(&self) -> Result<Vec<StartupEntry>> {
        let now = Utc::now();
        Ok(vec![
            StartupEntry {
                id: Uuid::new_v4().to_string(),
                name: "SecurityHealth".to_string(),
                path: "C:\\Windows\\System32\\SecurityHealthSystray.exe".to_string(),
                location_type: StartupLocationType::RegistryRunKey,
                signer_status: SignerStatus::Signed,
                first_seen_at: now,
                last_seen_at: now,
                enabled: true,
                is_new: false,
            },
            StartupEntry {
                id: Uuid::new_v4().to_string(),
                name: "SuspiciousUpdater".to_string(),
                path: "C:\\Users\\user\\AppData\\Local\\Temp\\updater.exe".to_string(),
                location_type: StartupLocationType::RegistryRunKey,
                signer_status: SignerStatus::Unsigned,
                first_seen_at: now,
                last_seen_at: now,
                enabled: true,
                is_new: true,
            },
        ])
    }

    pub fn disable_startup_entry(
        &self,
        name: &str,
        location_type: &StartupLocationType,
    ) -> Result<()> {
        #[cfg(windows)]
        {
            use windows::core::PCWSTR;
            use windows::Win32::System::Registry::{
                RegDeleteValueW, RegOpenKeyExW, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_WRITE,
            };

            let key_path = match location_type {
                StartupLocationType::RegistryRunKey | StartupLocationType::RegistryRunOnceKey =>
                    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                _ => anyhow::bail!("Removing this startup type is not supported (only registry Run keys can be removed)"),
            };

            let wide_key: Vec<u16> = key_path.encode_utf16().chain(std::iter::once(0)).collect();
            let wide_name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();

            unsafe {
                // Try HKCU first (no admin needed), fall back to HKLM
                let mut hkey = Default::default();
                let hkcu_result = RegOpenKeyExW(
                    HKEY_CURRENT_USER,
                    PCWSTR(wide_key.as_ptr()),
                    0,
                    KEY_WRITE,
                    &mut hkey,
                )
                .ok();

                if hkcu_result.is_err() {
                    RegOpenKeyExW(
                        HKEY_LOCAL_MACHINE,
                        PCWSTR(wide_key.as_ptr()),
                        0,
                        KEY_WRITE,
                        &mut hkey,
                    )
                    .ok()
                    .map_err(|e| anyhow::anyhow!("Failed to open registry key: {:?}", e))?;
                }

                RegDeleteValueW(hkey, PCWSTR(wide_name.as_ptr()))
                    .ok()
                    .map_err(|e| anyhow::anyhow!("Failed to delete registry value: {:?}", e))?;
            }
        }
        Ok(())
    }
}

impl Default for StartupCollector {
    fn default() -> Self {
        Self::new()
    }
}
