use anyhow::Result;
use yara_x::{Compiler, Rules, Scanner};
use crate::report::{Finding, Issue, Report, Severity, SubSystem};

include!(concat!(env!("OUT_DIR"), "/yara_rules.rs"));

pub struct RuleSet {
    pub rules: Rules,
    pub loaded_files: usize,
    pub skipped_files: Vec<&'static str>,
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