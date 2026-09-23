mod cli;
mod tools;
mod yara;
mod report;
mod entropy;

use anyhow::Result;
use cli::_parse_arguments;
use std::fs::{read, metadata};
use crate::entropy::get_entropy;
use crate::report::{Finding, Issue, Report, Severity, SubSystem};
use crate::tools::{archive_analysis, get_checksum, get_filetype, process_reported_filetype};
use crate::yara::{build_rules, get_yara_matches};

fn main() -> Result<()> {
    let args = _parse_arguments();

    let bytes = read(&args.path)?;
    let metadata = metadata(&args.path)?;
    let filetype = get_filetype(&bytes)?;
    let reported_filetype = process_reported_filetype(&args.path.extension())?;
    let checksum = get_checksum(&bytes);
    let mut final_report = Report::new(
        args.path.clone(),
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
                args.path,
                Issue::MagicByte,
                Severity::Critical,
                SubSystem::Base
            ))
        }
    }

    let rule_set = build_rules();
    eprintln!(
        "YARA: {} rule files loaded, {} skipped (yara-x incompatible): {:?}",
        rule_set.loaded_files,
        rule_set.skipped_files.len(),
        rule_set.skipped_files
    );

    get_yara_matches(&rule_set.rules, &bytes, &mut final_report)?;

    archive_analysis(&bytes, &rule_set.rules, &mut final_report)
        .unwrap_or_else(|_| eprintln!("The file is not a zip archive or unparsable."));

    get_entropy(&bytes, &mut final_report)?;

    final_report.generate_report();

    Ok(())
}
