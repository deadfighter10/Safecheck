mod cli;
mod tools;
mod yara;
mod report;
mod entropy;
pub mod constants;
pub mod virustotal;

use anyhow::{anyhow, Result};
use cli::_parse_arguments;
use std::fs::{read, metadata};
use crate::entropy::get_entropy;
use crate::report::{Finding, Issue, Report, Severity, SubSystem};
use crate::tools::{archive_analysis, get_checksum, get_filetype, process_reported_filetype};
use crate::virustotal::{lookup_hash, VirusTotalResult, vt_severity};
use crate::yara::{get_yara_matches, load_rules, update_rules};

fn main() -> Result<()> {
    let args = _parse_arguments();
    match args.update_rules {
        true => {
            update_rules()?;
            return Ok(())
        }
        false => {}
    }

    let Some(path) = args.path else {
        return Err(anyhow!("no file given"));
    };

    let bytes = read(&path)?;
    let metadata = metadata(&path)?;
    let filetype = get_filetype(&bytes)?;
    let reported_filetype = process_reported_filetype(&path.extension())?;
    let checksum = get_checksum(&bytes);
    let mut final_report = Report::new(
        path.clone(),
        metadata,
        checksum,
        reported_filetype,
        filetype
    );

    match final_report.reported_filetype.trim().to_lowercase()
        == final_report.real_filetype.extension().trim().to_lowercase() {
        true => {}
        false => {
            final_report.add_finding(Finding::new(
                path,
                Issue::MagicByte,
                Severity::Critical,
                SubSystem::Base
            ))
        }
    }

    let rule_set = load_rules();
    eprintln!(
        "YARA: {} ({} files loaded, {} skipped)",
        rule_set.source,
        rule_set.loaded_files,
        rule_set.skipped_files.len()
    );

    get_yara_matches(&rule_set.rules, &bytes, &mut final_report)?;

    archive_analysis(&bytes, &rule_set.rules, &mut final_report)
        .unwrap_or_else(|_| eprintln!("The file is not a zip archive or unparsable."));

    get_entropy(&bytes, &mut final_report)?;

    if args.vt {
        final_report.vt_status = Some(match std::env::var("VT_API_KEY") {
            Err(_) => "not run: VT_API_KEY is not set".to_string(),
            Ok(key) => match lookup_hash(&final_report.checksum, &key) {
                Err(e) => format!("lookup failed: {e}"),
                Ok(VirusTotalResult::Unknown) => "not found (this file was never submitted)".to_string(),
                Ok(VirusTotalResult::Known { malicious, suspicious, harmless, undetected, label }) => {
                    let total = malicious + suspicious + harmless + undetected;

                    if let Some(severity) = vt_severity(malicious, suspicious) {
                        final_report.add_finding(Finding::new(
                            final_report.filepath.clone(),
                            Issue::VirusTotal { malicious, suspicious, total, label },
                            severity,
                            SubSystem::VirusTotal,
                        ));
                    }
                    format!("{malicious}/{total} engines flagged this file")
                }
            },
        });
    }

    final_report.generate_report();

    Ok(())
}
