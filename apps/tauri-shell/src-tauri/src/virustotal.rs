use base64::prelude::{Engine as _, BASE64_URL_SAFE_NO_PAD};
use reqwest::Client;
use serde::Serialize;
use tokio::time::{sleep, Duration};

#[derive(Serialize)]
pub struct VTResult {
    pub malicious: u32,
    pub suspicious: u32,
    pub harmless: u32,
    pub undetected: u32,
    pub permalink: String,
}

pub async fn scan_url(url: &str, api_key: &str) -> Result<VTResult, String> {
    let client = Client::new();

    let submit = client
        .post("https://www.virustotal.com/api/v3/urls")
        .header("x-apikey", api_key)
        .form(&[("url", url)])
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if !submit.status().is_success() {
        let status = submit.status();
        let body = submit.text().await.unwrap_or_default();
        return Err(format!(
            "VirusTotal rejected the URL scan ({status}): {}",
            truncate_error(&body)
        ));
    }

    let submit_json: serde_json::Value = submit.json().await.map_err(|e| e.to_string())?;
    let analysis_id = submit_json["data"]["id"]
        .as_str()
        .ok_or_else(|| "VirusTotal did not return an analysis ID.".to_string())?
        .to_string();

    for _ in 0..5 {
        sleep(Duration::from_secs(2)).await;

        let report = client
            .get(format!(
                "https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            ))
            .header("x-apikey", api_key)
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if !report.status().is_success() {
            let status = report.status();
            let body = report.text().await.unwrap_or_default();
            return Err(format!(
                "VirusTotal analysis lookup failed ({status}): {}",
                truncate_error(&body)
            ));
        }

        let result: serde_json::Value = report.json().await.map_err(|e| e.to_string())?;
        let status = result["data"]["attributes"]["status"]
            .as_str()
            .unwrap_or_default();

        if status == "completed" {
            let stats = &result["data"]["attributes"]["stats"];
            return Ok(build_result(
                stats,
                format!(
                    "https://www.virustotal.com/gui/url/{}",
                    BASE64_URL_SAFE_NO_PAD.encode(url)
                ),
            ));
        }
    }

    Err("VirusTotal analysis timed out before a verdict was ready.".to_string())
}

pub async fn scan_domain(domain: &str, api_key: &str) -> Result<VTResult, String> {
    let client = Client::new();
    let report = client
        .get(format!(
            "https://www.virustotal.com/api/v3/domains/{domain}"
        ))
        .header("x-apikey", api_key)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if !report.status().is_success() {
        let status = report.status();
        let body = report.text().await.unwrap_or_default();
        return Err(format!(
            "VirusTotal domain lookup failed ({status}): {}",
            truncate_error(&body)
        ));
    }

    let result: serde_json::Value = report.json().await.map_err(|e| e.to_string())?;
    let stats = &result["data"]["attributes"]["last_analysis_stats"];

    Ok(build_result(
        stats,
        format!("https://www.virustotal.com/gui/domain/{domain}"),
    ))
}

pub async fn scan_ip(ip: &str, api_key: &str) -> Result<VTResult, String> {
    let client = Client::new();
    let report = client
        .get(format!(
            "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        ))
        .header("x-apikey", api_key)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if !report.status().is_success() {
        let status = report.status();
        let body = report.text().await.unwrap_or_default();
        return Err(format!(
            "VirusTotal IP lookup failed ({status}): {}",
            truncate_error(&body)
        ));
    }

    let result: serde_json::Value = report.json().await.map_err(|e| e.to_string())?;
    let stats = &result["data"]["attributes"]["last_analysis_stats"];

    Ok(build_result(
        stats,
        format!("https://www.virustotal.com/gui/ip-address/{ip}"),
    ))
}

fn build_result(stats: &serde_json::Value, permalink: String) -> VTResult {
    VTResult {
        malicious: stats["malicious"].as_u64().unwrap_or(0) as u32,
        suspicious: stats["suspicious"].as_u64().unwrap_or(0) as u32,
        harmless: stats["harmless"].as_u64().unwrap_or(0) as u32,
        undetected: stats["undetected"].as_u64().unwrap_or(0) as u32,
        permalink,
    }
}

fn truncate_error(body: &str) -> String {
    let compact = body.replace('\n', " ").replace('\r', " ");
    let trimmed = compact.trim();

    if trimmed.len() > 180 {
        format!("{}...", &trimmed[..180])
    } else {
        trimmed.to_string()
    }
}
