use std::ffi::OsStr;
use std::io::{Cursor, Read};
use std::path::PathBuf;
use sha2::{Digest, Sha256};
use hex::encode;
use infer::{Type, get};
use anyhow::{Result, anyhow};
use yara_x::{Rules, Scanner};
use zip::ZipArchive;
use crate::report::{Finding, Issue, Report, Severity, SubSystem};
use crate::constants::{ACTIVE_CONTENT_MARKERS, HIGH_RISK_EXTENSIONS, MARKUP_TYPES, YARA_SCAN_EXTENSIONS};

fn find_active_content(contents: &[u8]) -> Vec<&'static str> {
    let text = String::from_utf8_lossy(contents).to_lowercase();
    ACTIVE_CONTENT_MARKERS
        .iter()
        .copied()
        .filter(|marker| text.contains(marker))
        .collect()
}

/// Gets the SHA256 checksum of a Vec<u8> vector and returns the checksum as a String.
pub fn get_checksum(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(&bytes);

    let checksum = hasher.finalize();
    encode(checksum)
}

pub fn get_filetype(bytes: &[u8]) -> Result<Type> {
    let info = get(bytes);
    match info {
        Some(data) => {
            Ok(data)
        }
        None => {
            Err(anyhow!("Cannot find filetype!"))
        }
    }
}


pub fn process_reported_filetype(extension: &Option<&OsStr>) -> Result<String> {
    match extension {
        Some(extension) => {
            match extension.to_os_string().into_string() {
                Ok(filetype) => { Ok(normalize_ext(filetype.as_str())) }
                Err(_err) => {
                    Err(anyhow!("Cannot turn the filetype into UTF-8"))
                }
            }
        }
        None => {
            Ok("No filetype".to_string())
        }
    }
}


pub fn archive_analysis(data: &[u8], rules: &Rules, report: &mut Report) -> Result<()> {
    let cursor = Cursor::new(data);

    let mut archive = ZipArchive::new(cursor)?;

    let mut scanner = Scanner::new(&rules);

    for i in 0..archive.len() {
        let mut zipped_file = archive.by_index(i)?;
        if zipped_file.is_dir() {
            continue;
        }
        let path = PathBuf::from(zipped_file.name());
        let reported_filetype = process_reported_filetype(&path.extension()).ok();

        let mut contents = Vec::new();

        if zipped_file.size() > 8000000 {
            report.add_finding(Finding::new(
                path.clone(),
                Issue::Size,
                Severity::Medium,
                SubSystem::Archive
            ));
            continue
        }

        if zipped_file.size() == 0 {
            report.add_finding(Finding::new(
                path.clone(),
                Issue::Size,
                Severity::Low,
                SubSystem::Archive
            ))
        }

        if zipped_file.read_to_end(&mut contents).is_err() {
            eprintln!("Failed to retrieve the content of {}.", zipped_file.name());
            continue;
        }

        let filetype = get_filetype(&contents).ok();

        let reported_ext = reported_filetype.as_deref().unwrap_or("");
        let detected_ext = filetype
            .as_ref()
            .map(|t| t.extension())
            .unwrap_or("");

        if HIGH_RISK_EXTENSIONS.contains(&reported_ext)
            || HIGH_RISK_EXTENSIONS.contains(&detected_ext)
        {
            report.add_finding(Finding::new(
                path.clone(),
                Issue::HighRiskFileType(format!(
                    "reported: {} | detected: {}",
                    if reported_ext.is_empty() { "none" } else { reported_ext },
                    if detected_ext.is_empty() { "unknown" } else { detected_ext }
                )),
                Severity::High,
                SubSystem::Archive
            ));
        }

        let is_markup = MARKUP_TYPES.contains(&reported_ext) || MARKUP_TYPES.contains(&detected_ext);

        if is_markup {
            let found = find_active_content(&contents);
            if !found.is_empty() {
                report.add_finding(Finding::new(
                    path.clone(),
                    Issue::ActiveContent(found.join(", ")),
                    Severity::Medium,
                    SubSystem::Archive,
                ));
            }
        }

        if YARA_SCAN_EXTENSIONS.contains(&reported_ext)
            || YARA_SCAN_EXTENSIONS.contains(&detected_ext)
        {
            let scanresults = scanner.scan(&contents)?;
            if scanresults.matching_rules().len() != 0 {
                for f in scanresults.matching_rules() {
                    report.add_finding(Finding::new(
                        path.clone(),
                        Issue::YaraIssue(f.identifier().to_string()),
                        Severity::Critical,
                        SubSystem::Archive
                    ))
                }
            }
        }

    }

    Ok(())
}

fn normalize_ext(ext: &str) -> String {
    match ext.trim().to_lowercase().as_str() {
        "jpeg" | "jpe" => "jpg".into(),
        "tif" => "tiff".into(),
        "htm" => "html".into(),
        "yml" => "yaml".into(),
        other => other.into(),
    }
}