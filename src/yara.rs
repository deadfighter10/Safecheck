use std::fs;
use std::fs::create_dir_all;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;
use anyhow::{anyhow, Result};
use yara_x::{Compiler, Rules, Scanner};
use zip::ZipArchive;
use crate::report::{Finding, Issue, Report, Severity, SubSystem};

include!(concat!(env!("OUT_DIR"), "/yara_rules.rs"));

pub struct RuleSet {
    pub rules: Rules,
    pub loaded_files: usize,
    pub skipped_files: Vec<&'static str>,
    pub source: &'static str,
}

pub fn build_rules() -> RuleSet {
    let mut compiler = Compiler::new();
    let mut loaded_files = 0;
    let mut skipped_files = Vec::new();

    for (name, source) in RULE_FILES {
        match compiler.add_source(*source) {
            Ok(_) => loaded_files += 1,
            Err(_) => skipped_files.push(*name),
        }
    }

    RuleSet {
        rules: compiler.build(),
        loaded_files,
        skipped_files,
        source: "Yara-Rules (embedded)",
    }
}

pub fn get_yara_matches(rules: &Rules, bytes: &[u8], report: &mut Report) -> Result<()> {
    let mut scanner = Scanner::new(rules);
    let scan_result = scanner.scan(bytes)?;

    for matching_rule in scan_result.matching_rules() {
        report.add_finding(Finding::new(
            report.filepath.clone(),
            Issue::YaraIssue(matching_rule.identifier().to_string()),
            Severity::Critical,
            SubSystem::Yara,
        ));
    }

    Ok(())
}


fn rules_cache_path() -> Result<PathBuf> {
    let dir = dirs::cache_dir()
        .ok_or_else(|| anyhow!("no cache directory on this system"))?
        .join("safecheck");
    create_dir_all(&dir)?;
    Ok(dir.join("yara-forge-core.yar"))
}

pub fn update_rules() -> Result<()> {
    const FORGE_URL: &str =
        "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip";

    let mut response = ureq::get(FORGE_URL).call()?;
    let bytes = response.body_mut().read_to_vec()?;

    let mut archive = ZipArchive::new(Cursor::new(bytes))?;

    let mut source = String::new();
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        if entry.name().ends_with(".yar") {
            entry.read_to_string(&mut source)?;
            break;
        }
    }
    if source.is_empty() {
        return Err(anyhow!("downloaded package contains no .yar file"));
    }

    let mut compiler = Compiler::new();
    compiler.add_source(source.as_str())?;
    let rules = compiler.build();
    println!("Updated YARA Forge rules: {} rules compiled", rules.iter().len());

    let path = rules_cache_path()?;
    let tmp = path.with_extension("yar.tmp");
    fs::write(&tmp, &source)?;
    fs::rename(&tmp, &path)?;

    Ok(())
}

pub fn load_rules() -> RuleSet {
    if let Ok(path) = rules_cache_path() {
        if let Ok(source) = fs::read_to_string(&path) {
            let mut compiler = Compiler::new();
            if compiler.add_source(source.as_str()).is_ok() {
                warn_if_stale(&path);
                return RuleSet {
                    rules: compiler.build(),
                    loaded_files: 1,
                    skipped_files: Vec::new(),
                    source: "YARA Forge (cached)",
                };
            }
        }
    }
    build_rules()
}


fn warn_if_stale(path: &Path) {
    const MAX_AGE: Duration = Duration::from_secs(14 * 24 * 60 * 60);

    let age = fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok());

    if let Some(age) = age {
        if age > MAX_AGE {
            eprintln!(
                "Warning: YARA rules are {} days old, run `safecheck update-rules`",
                age.as_secs() / 86_400
            );
        }
    }
}