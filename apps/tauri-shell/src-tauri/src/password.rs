use serde::Serialize;
use sha1::{Digest, Sha1};

#[derive(Serialize)]
pub struct PasswordAnalysis {
    pub entropy: f64,
    pub crack_time_display: String,
    pub strength_label: String,
    pub sha1_prefix: String,
    pub sha1_suffix: String,
}

pub fn analyze(password: &str) -> PasswordAnalysis {
    let entropy = calculate_entropy(password);
    let hash = sha1_upper_hex(password);
    let sha1_prefix = hash[..5].to_string();
    let sha1_suffix = hash[5..].to_string();

    PasswordAnalysis {
        entropy,
        crack_time_display: format_crack_time(calculate_crack_time(entropy)),
        strength_label: strength_label(entropy),
        sha1_prefix,
        sha1_suffix,
    }
}

fn calculate_entropy(password: &str) -> f64 {
    let charset = charset_size(password) as f64;
    let len = password.len() as f64;

    if charset == 0.0 {
        return 0.0;
    }

    len * charset.log2()
}

fn charset_size(password: &str) -> u32 {
    let mut size = 0;

    if password.chars().any(|c| c.is_lowercase()) {
        size += 26;
    }
    if password.chars().any(|c| c.is_uppercase()) {
        size += 26;
    }
    if password.chars().any(|c| c.is_numeric()) {
        size += 10;
    }
    if password.chars().any(|c| !c.is_alphanumeric()) {
        size += 32;
    }

    size
}

fn calculate_crack_time(entropy: f64) -> f64 {
    let guesses_per_sec = 1e10_f64;
    2_f64.powf(entropy) / guesses_per_sec
}

fn format_crack_time(seconds: f64) -> String {
    match seconds {
        s if s < 1.0 => "Less than a second".into(),
        s if s < 60.0 => format!("{s:.0} seconds"),
        s if s < 3_600.0 => format!("{:.0} minutes", s / 60.0),
        s if s < 86_400.0 => format!("{:.0} hours", s / 3_600.0),
        s if s < 31_536_000.0 => format!("{:.0} days", s / 86_400.0),
        s => format!("{:.2e} years", s / 31_536_000.0),
    }
}

fn strength_label(entropy: f64) -> String {
    match entropy as u32 {
        0..=35 => "Very Weak",
        36..=59 => "Weak",
        60..=79 => "Moderate",
        80..=99 => "Strong",
        _ => "Very Strong",
    }
    .into()
}

fn sha1_upper_hex(password: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(password.as_bytes());
    let digest = hasher.finalize();
    let mut output = String::with_capacity(digest.len() * 2);

    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02X}");
    }

    output
}

#[cfg(test)]
mod tests {
    use super::analyze;

    #[test]
    fn weak_password_has_low_entropy() {
        let analysis = analyze("password");

        assert!(analysis.entropy > 0.0);
        assert_eq!(analysis.strength_label, "Weak");
        assert_eq!(analysis.sha1_prefix.len(), 5);
    }

    #[test]
    fn strong_password_has_higher_entropy() {
        let analysis = analyze("Tr0ub4dor&3CorrectHorse");

        assert!(analysis.entropy > 100.0);
        assert_eq!(analysis.strength_label, "Very Strong");
        assert_eq!(analysis.sha1_suffix.len(), 35);
    }
}
