use anyhow::Result;
use yara_x::{Compiler, Rules, Scanner};
use crate::report::{Finding, Issue, Report, Severity, SubSystem};

pub fn get_yara_matches(rules_source: &str, bytes: &[u8], report: &mut Report) -> Result<()> {
    let mut compiler = Compiler::new();

    match compiler.add_source(rules_source) {
        Ok(_) => {}
        Err(_error) => {}
    }
    let rules = compiler.build();

    let mut scanner = Scanner::new(&rules);

    let scan_result = scanner.scan(bytes)?;

    if scan_result.matching_rules().len() != 0 {
        for matching_rule in scan_result.matching_rules() {
            report.add_finding(Finding::new(
                report.filepath.clone(),
                Issue::YaraIssue(matching_rule.identifier().to_string()),
                Severity::Critical,
                SubSystem::Yara
            ));
        }
    }

    Ok(())

}

pub fn create_yara_rules(rules_source: &str) -> Result<Rules> {
    let mut compiler = Compiler::new();

    match compiler.add_source(rules_source) {
        Ok(_) => {}
        Err(_error) => {}
    }
    let rules = compiler.build();

    Ok(rules)
}