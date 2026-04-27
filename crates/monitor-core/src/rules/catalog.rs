use super::engine::Rule;
use serde_json::json;
use shared_types::models::{PathCategory, ProcessRecord, SignerStatus};
use shared_types::rules::RuleMatchResult;

fn make_result(
    rule_key: &str,
    explanation: String,
    evidence: serde_json::Value,
    weight: u32,
) -> RuleMatchResult {
    RuleMatchResult {
        rule_key: rule_key.to_string(),
        matched: true,
        explanation,
        evidence,
        weight,
    }
}

/// Unsigned executable running from AppData, Temp, or Downloads
pub struct UnsignedInUserWritableDir;

impl Rule for UnsignedInUserWritableDir {
    fn key(&self) -> &str {
        "unsigned_in_user_writable_dir"
    }
    fn weight(&self) -> u32 {
        40
    }

    fn check(
        &self,
        process: &ProcessRecord,
        _parent: Option<&ProcessRecord>,
    ) -> Option<RuleMatchResult> {
        let is_unsigned = matches!(
            process.signer_status,
            SignerStatus::Unsigned | SignerStatus::InvalidSignature
        );
        let in_writable = matches!(
            process.path_category,
            PathCategory::UserWritable
                | PathCategory::Temp
                | PathCategory::Downloads
                | PathCategory::AppData
        );

        if is_unsigned && in_writable {
            Some(make_result(
                self.key(),
                format!(
                    "Unsigned executable running from {} — common malware staging location",
                    process.exe_path.as_deref().unwrap_or("unknown path")
                ),
                json!({
                    "signer_status": format!("{:?}", process.signer_status),
                    "path_category": format!("{:?}", process.path_category),
                    "exe_path": process.exe_path,
                }),
                self.weight(),
            ))
        } else {
            None
        }
    }
}

/// PowerShell spawned by Office application
pub struct PowerShellSpawnedByOffice;

impl Rule for PowerShellSpawnedByOffice {
    fn key(&self) -> &str {
        "powershell_spawned_by_office"
    }
    fn weight(&self) -> u32 {
        60
    }

    fn check(
        &self,
        process: &ProcessRecord,
        parent: Option<&ProcessRecord>,
    ) -> Option<RuleMatchResult> {
        let is_powershell = process.name.to_lowercase().contains("powershell");
        let parent_is_office = parent
            .map(|p| {
                let n = p.name.to_lowercase();
                n.contains("winword")
                    || n.contains("excel")
                    || n.contains("outlook")
                    || n.contains("powerpnt")
                    || n.contains("onenote")
                    || n.contains("mspub")
            })
            .unwrap_or(false);

        if is_powershell && parent_is_office {
            Some(make_result(
                self.key(),
                format!(
                    "PowerShell spawned by Office application ({}) — common macro attack pattern",
                    parent.map(|p| p.name.as_str()).unwrap_or("unknown")
                ),
                json!({
                    "process_name": process.name,
                    "parent_name": parent.map(|p| &p.name),
                    "parent_pid": parent.map(|p| p.pid),
                }),
                self.weight(),
            ))
        } else {
            None
        }
    }
}

/// cmd.exe spawned by script host (wscript, cscript, mshta)
pub struct CmdSpawnedByScriptHost;

impl Rule for CmdSpawnedByScriptHost {
    fn key(&self) -> &str {
        "cmd_spawned_by_script_host"
    }
    fn weight(&self) -> u32 {
        55
    }

    fn check(
        &self,
        process: &ProcessRecord,
        parent: Option<&ProcessRecord>,
    ) -> Option<RuleMatchResult> {
        let is_cmd = process.name.to_lowercase() == "cmd.exe";
        let parent_is_script_host = parent
            .map(|p| {
                let n = p.name.to_lowercase();
                n.contains("wscript")
                    || n.contains("cscript")
                    || n.contains("mshta")
                    || n.contains("wmic")
                    || n.contains("regsvr32")
            })
            .unwrap_or(false);

        if is_cmd && parent_is_script_host {
            Some(make_result(
                self.key(),
                format!(
                    "cmd.exe spawned by script host ({}) — suspicious execution chain",
                    parent.map(|p| p.name.as_str()).unwrap_or("unknown")
                ),
                json!({
                    "process_name": process.name,
                    "parent_name": parent.map(|p| &p.name),
                    "command_line": process.command_line,
                }),
                self.weight(),
            ))
        } else {
            None
        }
    }
}

/// Process name looks like a system binary but runs from non-system path
pub struct ProcessNameMasquerade;

impl Rule for ProcessNameMasquerade {
    fn key(&self) -> &str {
        "process_name_masquerade"
    }
    fn weight(&self) -> u32 {
        70
    }

    fn check(
        &self,
        process: &ProcessRecord,
        _parent: Option<&ProcessRecord>,
    ) -> Option<RuleMatchResult> {
        let system_names = [
            "svchost.exe",
            "lsass.exe",
            "csrss.exe",
            "winlogon.exe",
            "services.exe",
            "spoolsv.exe",
            "explorer.exe",
            "taskmgr.exe",
            "rundll32.exe",
            "regsvr32.exe",
            "msiexec.exe",
            "conhost.exe",
        ];

        let name_lower = process.name.to_lowercase();
        let is_system_name = system_names.contains(&name_lower.as_str());
        // Only flag if we actually know the path is in a user-controlled location.
        // Unknown path_category means we couldn't query the process (likely a privileged
        // system process) — do not flag those as masquerading.
        let known_user_path = matches!(
            process.path_category,
            PathCategory::UserWritable
                | PathCategory::Temp
                | PathCategory::Downloads
                | PathCategory::AppData
        );

        if is_system_name && known_user_path {
            Some(make_result(
                self.key(),
                format!(
                    "'{}' uses a system process name but runs from a non-system location — possible masquerading",
                    process.name
                ),
                json!({
                    "process_name": process.name,
                    "exe_path": process.exe_path,
                    "path_category": format!("{:?}", process.path_category),
                }),
                self.weight(),
            ))
        } else {
            None
        }
    }
}

/// Suspicious parent-child chain (browser spawning cmd, etc.)
pub struct SuspiciousParentChildChain;

impl Rule for SuspiciousParentChildChain {
    fn key(&self) -> &str {
        "suspicious_parent_child_chain"
    }
    fn weight(&self) -> u32 {
        45
    }

    fn check(
        &self,
        process: &ProcessRecord,
        parent: Option<&ProcessRecord>,
    ) -> Option<RuleMatchResult> {
        let child_is_shell = {
            let n = process.name.to_lowercase();
            n.contains("powershell")
                || n == "cmd.exe"
                || n.contains("wscript")
                || n.contains("cscript")
        };

        let parent_is_browser_or_doc = parent
            .map(|p| {
                let n = p.name.to_lowercase();
                n.contains("chrome")
                    || n.contains("firefox")
                    || n.contains("msedge")
                    || n.contains("iexplore")
                    || n.contains("acrobat")
                    || n.contains("acrord")
            })
            .unwrap_or(false);

        if child_is_shell && parent_is_browser_or_doc {
            Some(make_result(
                self.key(),
                format!(
                    "Shell process '{}' spawned by browser/document viewer — potential exploitation",
                    process.name
                ),
                json!({
                    "child": process.name,
                    "parent": parent.map(|p| &p.name),
                }),
                self.weight(),
            ))
        } else {
            None
        }
    }
}

/// Persistence-related process path shows up in startup entries
pub struct PersistenceAddedRecently;

impl Rule for PersistenceAddedRecently {
    fn key(&self) -> &str {
        "persistence_added_recently"
    }
    fn weight(&self) -> u32 {
        50
    }

    fn check(
        &self,
        _process: &ProcessRecord,
        _parent: Option<&ProcessRecord>,
    ) -> Option<RuleMatchResult> {
        // Triggered externally by service layer when startup linkage is detected
        None
    }
}

/// Executable in temp directory (regardless of signature)
pub struct ExeInTempDir;

impl Rule for ExeInTempDir {
    fn key(&self) -> &str {
        "exe_in_temp_dir"
    }
    fn weight(&self) -> u32 {
        25
    }

    fn check(
        &self,
        process: &ProcessRecord,
        _parent: Option<&ProcessRecord>,
    ) -> Option<RuleMatchResult> {
        let in_temp = matches!(process.path_category, PathCategory::Temp);
        // Skip known-safe Microsoft temp extractors
        let name_lower = process.name.to_lowercase();
        let is_known_temp_pattern = name_lower.contains("setup")
            || name_lower.contains("install")
            || name_lower.contains("update")
            || name_lower.contains("bing")
            || name_lower.contains("msedge")
            || name_lower.contains("windows");
        if in_temp && !is_known_temp_pattern {
            Some(make_result(
                self.key(),
                "Executable running from Temp directory — legitimate software rarely launches from here".to_string(),
                json!({ "exe_path": process.exe_path }),
                self.weight(),
            ))
        } else {
            None
        }
    }
}

/// High-risk path category (Downloads + unsigned)
pub struct HighRiskPathCategory;

impl Rule for HighRiskPathCategory {
    fn key(&self) -> &str {
        "high_risk_path_category"
    }
    fn weight(&self) -> u32 {
        20
    }

    fn check(
        &self,
        process: &ProcessRecord,
        _parent: Option<&ProcessRecord>,
    ) -> Option<RuleMatchResult> {
        let in_downloads = matches!(process.path_category, PathCategory::Downloads);
        if in_downloads {
            Some(make_result(
                self.key(),
                "Process running from Downloads folder — review if this was intentionally executed"
                    .to_string(),
                json!({ "exe_path": process.exe_path }),
                self.weight(),
            ))
        } else {
            None
        }
    }
}
