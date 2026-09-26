use anyhow::{anyhow, Result};
use crate::report::Severity;

pub enum VirusTotalResult {
    Known {
        malicious: u64,
        suspicious: u64,
        harmless: u64,
        undetected: u64,
        label: Option<String>,
    },
    Unknown,
}

pub fn lookup_hash(sha256: &str, api_key: &str) -> Result<VirusTotalResult> {
    let url = format!("https://www.virustotal.com/api/v3/files/{sha256}");

    let mut response = match ureq::get(&url).header("x-apikey", api_key).call() {
        Ok(r) => r,
        Err(ureq::Error::StatusCode(404)) => return Ok(VirusTotalResult::Unknown),
        Err(ureq::Error::StatusCode(401)) => return Err(anyhow!("invalid VirusTotal API key")),
        Err(ureq::Error::StatusCode(429)) => {
            return Err(anyhow!("VirusTotal quota exceeded (free tier: 4/min, 500/day)"))
        }
        Err(e) => return Err(e.into()),
    };

    let body = response.body_mut().read_to_string()?;
    let json: serde_json::Value = serde_json::from_str(&body)?;


    let stat = |field: &str| {
        json.pointer(&format!("/data/attributes/last_analysis_stats/{field}"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
    };

    let label = json
        .pointer("/data/attributes/popular_threat_classification/suggested_threat_label")
        .and_then(|v| v.as_str())
        .map(String::from);

    Ok(VirusTotalResult::Known {
        malicious: stat("malicious"),
        suspicious: stat("suspicious"),
        harmless: stat("harmless"),
        undetected: stat("undetected"),
        label,
    })
}


pub fn vt_severity(malicious: u64, suspicious: u64) -> Option<Severity> {
    match (malicious, suspicious) {
        (m, _) if m >= 5 => Some(Severity::Critical),
        (m, _) if m >= 1 => Some(Severity::High),
        (0, s) if s >= 1 => Some(Severity::Medium),
        _ => None, // no engine flagged it
    }
}