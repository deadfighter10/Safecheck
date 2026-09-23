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

pub const HIGH_RISK_EXTENSIONS: &[&str] = &[
    // Native executables / libraries
    "exe",
    "dll",
    "com",
    "scr",
    "cpl",
    "ocx",
    "sys",
    "drv",
    "app",

    // Installers / packages
    "msi",
    "msp",
    "mst",
    "cab",
    "pkg",
    "dmg",
    "iso",

    // Scripts / command files
    "bat",
    "cmd",
    "js",
    "jse",
    "vbs",
    "vbe",
    "wsf",
    "wsh",
    "ps1",
    "psm1",
    "sh",
    "bash",
    "zsh",
    "fish",
    "command",
    "pl",
    "py",
    "rb",

    // Shortcuts / link-like files
    "lnk",
    "url",
    "scf",
    "shb",
    "shs",

    // Java / .NET related executable content
    "jar",
    "class",

    // Macro-enabled Office documents
    "docm",
    "dotm",
    "xlsm",
    "xltm",
    "xlam",
    "pptm",
    "potm",
    "ppsm",
    "ppam",

    // HTML / web content that can contain active content
    "hta",
    "html",
    "htm",
    "svg",

    // Apple executable / bundle-related
    "dylib",
    "bundle",
    "framework",
];

pub const YARA_SCAN_EXTENSIONS: &[&str] = &[
    // Executables / native code
    "exe",
    "dll",
    "com",
    "scr",
    "cpl",
    "ocx",
    "sys",
    "drv",
    "dylib",
    "app",
    "bundle",
    "framework",
    "elf",
    "so",

    // Scripts / interpreted code
    "js",
    "jse",
    "mjs",
    "vbs",
    "vbe",
    "wsf",
    "wsh",
    "ps1",
    "psm1",
    "bat",
    "cmd",
    "sh",
    "bash",
    "zsh",
    "fish",
    "command",
    "py",
    "pl",
    "pm",
    "rb",
    "php",

    // Web / markup / active content
    "html",
    "htm",
    "xhtml",
    "xht",
    "xml",
    "svg",
    "hta",

    // Documents that can contain active content / macros
    "pdf",
    "rtf",
    "doc",
    "dot",
    "docm",
    "dotm",
    "xls",
    "xlt",
    "xlsm",
    "xltm",
    "xlam",
    "ppt",
    "pot",
    "pps",
    "pptm",
    "potm",
    "ppsm",
    "ppam",

    // Java / managed executable content
    "jar",
    "class",
    "war",
    "ear",

    // Installers / packages
    "msi",
    "msp",
    "pkg",
    "dmg",

    // Archives / containers
    "zip",
    "7z",
    "rar",
    "tar",
    "gz",
    "bz2",
    "xz",
    "iso",
];


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
                Ok(filetype) => { Ok(filetype) }
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