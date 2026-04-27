use shared_types::models::ProcessRecord;
use shared_types::rules::RuleMatchResult;

use super::catalog::*;

pub struct RulesEngine {
    rules: Vec<Box<dyn Rule + Send + Sync>>,
}

pub trait Rule {
    fn key(&self) -> &str;
    fn weight(&self) -> u32;
    fn check(
        &self,
        process: &ProcessRecord,
        parent: Option<&ProcessRecord>,
    ) -> Option<RuleMatchResult>;
}

impl RulesEngine {
    pub fn new() -> Self {
        Self {
            rules: vec![
                Box::new(UnsignedInUserWritableDir),
                Box::new(PowerShellSpawnedByOffice),
                Box::new(CmdSpawnedByScriptHost),
                Box::new(ProcessNameMasquerade),
                Box::new(SuspiciousParentChildChain),
                Box::new(PersistenceAddedRecently),
                Box::new(ExeInTempDir),
                Box::new(HighRiskPathCategory),
            ],
        }
    }

    pub fn evaluate(
        &self,
        process: &ProcessRecord,
        parent: Option<&ProcessRecord>,
    ) -> Vec<RuleMatchResult> {
        self.rules
            .iter()
            .filter_map(|rule| rule.check(process, parent))
            .filter(|r| r.matched)
            .collect()
    }
}

impl Default for RulesEngine {
    fn default() -> Self {
        Self::new()
    }
}
