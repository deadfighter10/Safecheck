mod cli;
mod tools;
mod yara;
mod report;
mod entropy;

use anyhow::{anyhow, Result};
use cli::_parse_arguments;
use std::fs::{read, metadata};
use crate::entropy::get_entropy;
use crate::report::{Finding, Issue, Report, Severity, SubSystem};
use crate::tools::{archive_analysis, get_checksum, get_filetype, process_reported_filetype};
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

    final_report.generate_report();

    Ok(())
}
