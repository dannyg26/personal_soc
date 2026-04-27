use serde::Serialize;
use std::net::IpAddr;
use url::Url;

const SUSPICIOUS_KEYWORDS: &[&str] = &[
    "login", "verify", "secure", "update", "confirm", "account", "banking", "paypal", "signin",
    "password", "wallet", "reset", "recovery", "invoice",
];

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanTarget {
    Url,
    Domain,
    IpAddress,
}

#[derive(Serialize, Clone)]
pub struct UrlFeatures {
    pub scan_target: ScanTarget,
    pub normalized_url: String,
    pub domain: String,
    pub is_ip_address: bool,
    pub subdomain_depth: usize,
    pub uses_https: bool,
    pub url_length: usize,
    pub suspicious_keywords: Vec<String>,
    pub heuristics: Vec<String>,
    pub local_risk_score: u8,
}

pub fn extract_features(raw_input: &str) -> Result<UrlFeatures, String> {
    let trimmed = raw_input.trim();
    if trimmed.is_empty() {
        return Err("Enter a URL, domain, or IP address to scan.".to_string());
    }

    let normalized_url = normalize_input(trimmed);
    let parsed = Url::parse(&normalized_url)
        .map_err(|_| "Enter a valid URL, domain, or IP address.".to_string())?;

    let domain = parsed
        .host_str()
        .ok_or_else(|| "Enter a valid URL, domain, or IP address.".to_string())?
        .to_string();

    let is_ip_address = domain.parse::<IpAddr>().is_ok();
    let scan_target = classify_scan_target(trimmed, &parsed, &domain, is_ip_address);
    let subdomain_depth = if is_ip_address {
        0
    } else {
        domain.split('.').count().saturating_sub(2)
    };
    let uses_https = trimmed.to_ascii_lowercase().starts_with("https://");
    let url_length = normalized_url.len();
    let lowered = normalized_url.to_ascii_lowercase();

    let suspicious_keywords = SUSPICIOUS_KEYWORDS
        .iter()
        .filter(|keyword| lowered.contains(**keyword))
        .map(|keyword| (*keyword).to_string())
        .collect::<Vec<_>>();

    let (local_risk_score, heuristics) = compute_local_risk(
        &parsed,
        &domain,
        is_ip_address,
        uses_https,
        url_length,
        subdomain_depth,
        &suspicious_keywords,
    );

    Ok(UrlFeatures {
        scan_target,
        normalized_url,
        domain,
        is_ip_address,
        subdomain_depth,
        uses_https,
        url_length,
        suspicious_keywords,
        heuristics,
        local_risk_score,
    })
}

fn normalize_input(input: &str) -> String {
    if input.starts_with("http://") || input.starts_with("https://") {
        input.to_string()
    } else {
        format!("http://{input}")
    }
}

fn classify_scan_target(
    trimmed: &str,
    parsed: &Url,
    domain: &str,
    is_ip_address: bool,
) -> ScanTarget {
    let has_explicit_scheme = trimmed.contains("://");
    let has_userinfo = !parsed.username().is_empty() || parsed.password().is_some();
    let has_non_root_path = parsed.path() != "/" && !parsed.path().is_empty();
    let has_query = parsed.query().is_some();
    let has_fragment = parsed.fragment().is_some();
    let has_port = parsed.port().is_some();
    let is_host_only = !has_explicit_scheme
        && !has_userinfo
        && !has_non_root_path
        && !has_query
        && !has_fragment
        && !has_port
        && trimmed.eq_ignore_ascii_case(domain);

    if is_host_only {
        if is_ip_address {
            ScanTarget::IpAddress
        } else {
            ScanTarget::Domain
        }
    } else {
        ScanTarget::Url
    }
}

fn compute_local_risk(
    parsed: &Url,
    domain: &str,
    is_ip_address: bool,
    uses_https: bool,
    url_length: usize,
    subdomain_depth: usize,
    suspicious_keywords: &[String],
) -> (u8, Vec<String>) {
    let mut score = 0i32;
    let mut heuristics = Vec::new();

    if is_ip_address {
        score += 35;
        heuristics.push("Direct IP host instead of a named domain.".to_string());
    }

    if !uses_https {
        score += 15;
        heuristics.push("Connection does not use HTTPS.".to_string());
    }

    if url_length > 90 {
        score += 10;
        heuristics.push("URL is unusually long and may be padded to hide intent.".to_string());
    }

    if subdomain_depth > 3 {
        score += 15;
        heuristics.push(format!(
            "{subdomain_depth} nested subdomains detected, which can be used for impersonation."
        ));
    }

    if domain.contains("xn--") {
        score += 20;
        heuristics.push("Punycode host detected, which can mask look-alike domains.".to_string());
    }

    let hyphen_count = domain.matches('-').count();
    if hyphen_count >= 3 {
        score += 10;
        heuristics.push("Domain uses several hyphens, a common phishing pattern.".to_string());
    }

    if !parsed.username().is_empty() || parsed.password().is_some() {
        score += 25;
        heuristics.push("URL includes embedded credentials before the host.".to_string());
    }

    if parsed
        .path_segments()
        .map(|segments| segments.count())
        .unwrap_or(0)
        > 5
    {
        score += 5;
        heuristics.push("Path depth is unusually high.".to_string());
    }

    if parsed
        .query()
        .map(|query| query.len() > 80)
        .unwrap_or(false)
    {
        score += 5;
        heuristics.push("Long query string increases obfuscation risk.".to_string());
    }

    if !suspicious_keywords.is_empty() {
        score += ((suspicious_keywords.len() as i32) * 8).min(24);
        heuristics.push(format!(
            "Suspicious keywords detected: {}.",
            suspicious_keywords.join(", ")
        ));
    }

    if heuristics.is_empty() {
        heuristics.push("No high-risk URL patterns detected locally.".to_string());
    }

    (score.clamp(0, 100) as u8, heuristics)
}

#[cfg(test)]
mod tests {
    use super::{extract_features, ScanTarget};

    #[test]
    fn suspicious_ip_scores_high() {
        let result = extract_features("http://192.168.1.10/login").expect("should parse");

        assert!(result.is_ip_address);
        assert_eq!(result.scan_target, ScanTarget::Url);
        assert!(result.local_risk_score >= 50);
    }

    #[test]
    fn clean_https_domain_scores_low() {
        let result = extract_features("https://openai.com").expect("should parse");

        assert!(!result.is_ip_address);
        assert_eq!(result.scan_target, ScanTarget::Url);
        assert!(result.uses_https);
        assert!(result.local_risk_score < 35);
    }

    #[test]
    fn bare_domain_uses_domain_lookup() {
        let result = extract_features("openai.com").expect("should parse");

        assert_eq!(result.scan_target, ScanTarget::Domain);
    }

    #[test]
    fn bare_ip_uses_ip_lookup() {
        let result = extract_features("1.1.1.1").expect("should parse");

        assert_eq!(result.scan_target, ScanTarget::IpAddress);
    }
}
