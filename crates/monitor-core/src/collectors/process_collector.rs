use anyhow::Result;
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::path::Path;

use shared_types::models::{PathCategory, ProcessRecord, SignerStatus};

pub struct ProcessCollector;

impl ProcessCollector {
    pub fn new() -> Self {
        Self
    }

    /// Enumerate all currently running processes.
    pub fn enumerate_processes(&self) -> Result<Vec<ProcessRecord>> {
        #[cfg(windows)]
        {
            self.enumerate_windows_processes()
        }
        #[cfg(not(windows))]
        {
            self.enumerate_stub_processes()
        }
    }

    #[cfg(windows)]
    fn enumerate_windows_processes(&self) -> Result<Vec<ProcessRecord>> {
        use windows::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };

        let mut processes = Vec::new();
        let now = Utc::now();

        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;
            if snapshot == INVALID_HANDLE_VALUE {
                anyhow::bail!("Failed to create process snapshot");
            }

            let mut entry = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };

            if Process32FirstW(snapshot, &mut entry).is_ok() {
                loop {
                    let name = String::from_utf16_lossy(
                        &entry.szExeFile[..entry
                            .szExeFile
                            .iter()
                            .position(|&c| c == 0)
                            .unwrap_or(entry.szExeFile.len())],
                    );

                    let pid = entry.th32ProcessID;
                    let parent_pid = entry.th32ParentProcessID;

                    let mut record = ProcessRecord::new(pid);
                    record.name = name;
                    record.parent_pid = if parent_pid == 0 {
                        None
                    } else {
                        Some(parent_pid)
                    };
                    record.first_seen_at = now;
                    record.last_seen_at = now;

                    // Get extended process info
                    self.enrich_process_record(&mut record);

                    processes.push(record);

                    if Process32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }

            let _ = windows::Win32::Foundation::CloseHandle(snapshot);
        }

        Ok(processes)
    }

    #[cfg(windows)]
    fn enrich_process_record(&self, record: &mut ProcessRecord) {
        use windows::core::PWSTR;
        use windows::Win32::System::Threading::{
            OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
            PROCESS_QUERY_LIMITED_INFORMATION,
        };

        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, record.pid);

            if let Ok(handle) = handle {
                let mut path_buf = vec![0u16; 32768];
                let mut size = path_buf.len() as u32;
                let path_pwstr = PWSTR(path_buf.as_mut_ptr());

                if QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, path_pwstr, &mut size)
                    .is_ok()
                {
                    let path = String::from_utf16_lossy(&path_buf[..size as usize]);
                    record.exe_path = Some(path.clone());
                    record.path_category = classify_path(&path);
                    // NOTE: signature check and file hash are intentionally skipped here
                    // during bulk enumeration — they are slow (WinVerifyTrust makes network
                    // calls; reading every EXE for hashing is also expensive).
                    // These are populated on-demand in enrich_single_process().
                }

                let _ = windows::Win32::Foundation::CloseHandle(handle);
            }
        }
    }

    /// Called on-demand for a single process (e.g. when user opens process detail).
    /// Populates the expensive fields: signer_status, file_hash.
    pub fn enrich_single_process(&self, record: &mut ProcessRecord) {
        if let Some(ref path) = record.exe_path.clone() {
            record.signer_status = check_signature(path);
            record.file_hash = compute_hash(path);
        }
    }

    /// Stub for non-Windows development
    #[cfg(not(windows))]
    fn enumerate_stub_processes(&self) -> Result<Vec<ProcessRecord>> {
        warn!("Running on non-Windows platform — returning stub process data");
        let now = Utc::now();

        let stubs = vec![
            (
                1234u32,
                Some(1u32),
                "chrome.exe",
                "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
            ),
            (
                5678,
                Some(1),
                "powershell.exe",
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            ),
            (
                9012,
                Some(1),
                "svchost.exe",
                "C:\\Windows\\System32\\svchost.exe",
            ),
            (
                3456,
                Some(1234),
                "suspicious.exe",
                "C:\\Users\\user\\AppData\\Local\\Temp\\suspicious.exe",
            ),
        ];

        Ok(stubs
            .into_iter()
            .map(|(pid, parent_pid, name, path)| {
                let mut r = ProcessRecord::new(pid);
                r.parent_pid = parent_pid;
                r.name = name.to_string();
                r.exe_path = Some(path.to_string());
                r.path_category = classify_path(path);
                r.signer_status = if path.contains("Temp") || path.contains("AppData") {
                    SignerStatus::Unsigned
                } else {
                    SignerStatus::Signed
                };
                r.first_seen_at = now;
                r.last_seen_at = now;
                r
            })
            .collect())
    }

    pub fn kill_process(&self, pid: u32) -> Result<()> {
        #[cfg(windows)]
        {
            use windows::Win32::System::Threading::{
                OpenProcess, TerminateProcess, PROCESS_TERMINATE,
            };
            unsafe {
                let handle = OpenProcess(PROCESS_TERMINATE, false, pid)
                    .map_err(|e| anyhow::anyhow!("Failed to open process {}: {:?}", pid, e))?;
                TerminateProcess(handle, 1)
                    .map_err(|e| anyhow::anyhow!("Failed to terminate process {}: {:?}", pid, e))?;
                let _ = windows::Win32::Foundation::CloseHandle(handle);
            }
        }
        #[cfg(not(windows))]
        {
            anyhow::bail!("kill_process not supported on this platform");
        }
        Ok(())
    }
}

impl Default for ProcessCollector {
    fn default() -> Self {
        Self::new()
    }
}

pub fn classify_path(path: &str) -> PathCategory {
    let lower = path.to_lowercase();
    if lower.contains("\\windows\\system32") || lower.contains("\\windows\\syswow64") {
        PathCategory::System
    } else if lower.contains("\\program files") || lower.contains("\\program files (x86)") {
        PathCategory::ProgramFiles
    } else if lower.contains("\\appdata\\local\\temp") || lower.contains("\\temp\\") {
        PathCategory::Temp
    } else if lower.contains("\\downloads\\") {
        PathCategory::Downloads
    } else if lower.contains("\\appdata\\") {
        PathCategory::AppData
    } else if lower.contains("\\users\\") {
        PathCategory::UserWritable
    } else {
        PathCategory::Unknown
    }
}

pub fn compute_hash(path: &str) -> Option<String> {
    let data = std::fs::read(path).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    Some(hex::encode(hasher.finalize()))
}

#[cfg(windows)]
pub fn check_signature(path: &str) -> SignerStatus {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::HWND;
    use windows::Win32::Security::WinTrust::{
        WinVerifyTrust, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_DATA_UICONTEXT,
        WINTRUST_FILE_INFO, WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_SAFER_FLAG,
        WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    };

    // Simple existence check first
    if !Path::new(path).exists() {
        return SignerStatus::Unknown;
    }

    let wide_path: Vec<u16> = OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let mut file_info = WINTRUST_FILE_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: PCWSTR(wide_path.as_ptr()),
            hFile: Default::default(),
            pgKnownSubject: std::ptr::null_mut(),
        };

        let mut trust_data = WINTRUST_DATA {
            cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
            pPolicyCallbackData: std::ptr::null_mut(),
            pSIPClientData: std::ptr::null_mut(),
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_NONE,
            dwUnionChoice: WTD_CHOICE_FILE,
            Anonymous: WINTRUST_DATA_0 {
                pFile: &mut file_info,
            },
            dwStateAction: WTD_STATEACTION_VERIFY,
            hWVTStateData: Default::default(),
            pwszURLReference: PWSTR::null(),
            dwProvFlags: WTD_SAFER_FLAG,
            dwUIContext: WINTRUST_DATA_UICONTEXT(0),
            pSignatureSettings: std::ptr::null_mut(),
        };

        // WINTRUST_ACTION_GENERIC_VERIFY_V2
        let mut action_id = windows::core::GUID {
            data1: 0x00AAC56B,
            data2: 0xCD44,
            data3: 0x11d0,
            data4: [0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE],
        };

        let result = WinVerifyTrust(
            HWND(std::ptr::null_mut()),
            &mut action_id,
            &mut trust_data as *mut _ as *mut _,
        );

        if result == 0 {
            SignerStatus::Signed
        } else {
            SignerStatus::Unsigned
        }
    }
}

#[cfg(not(windows))]
pub fn check_signature(_path: &str) -> SignerStatus {
    SignerStatus::Unknown
}
