use shared_types::models::{PathCategory, ProcessRecord, Severity, SignerStatus};
use shared_types::rules::RuleMatchResult;

pub struct ScoringService;

impl ScoringService {
    pub fn new() -> Self {
        Self
    }

    pub fn compute_score(
        &self,
        process: &ProcessRecord,
        triggered_rules: &[RuleMatchResult],
    ) -> u32 {
        let base: u32 = triggered_rules.iter().map(|r| r.weight).sum();

        // Positive adjustments
        let positive = self.compute_positive_adjustments(process);

        // Negative adjustments (trust signals)
        let negative = self.compute_negative_adjustments(process);

        let raw = base.saturating_add(positive).saturating_sub(negative);
        raw.min(100)
    }

    fn compute_positive_adjustments(&self, process: &ProcessRecord) -> u32 {
        let mut adj = 0u32;

        if matches!(process.signer_status, SignerStatus::Unsigned) {
            adj += 10;
        }

        if matches!(
            process.path_category,
            PathCategory::Temp | PathCategory::Downloads
        ) {
            adj += 5;
        }

        adj
    }

    fn compute_negative_adjustments(&self, process: &ProcessRecord) -> u32 {
        let mut adj = 0u32;

        if matches!(process.signer_status, SignerStatus::Signed) {
            adj += 15;
        }

        if matches!(process.path_category, PathCategory::System) {
            adj += 20;
        }

        if matches!(process.path_category, PathCategory::ProgramFiles) {
            adj += 10;
        }

        adj
    }

    pub fn severity_from_score(score: u32) -> Severity {
        Severity::from_score(score)
    }
}

impl Default for ScoringService {
    fn default() -> Self {
        Self::new()
    }
}
