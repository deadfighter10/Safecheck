use std::fs::Metadata;
use std::path::{PathBuf};
use derive_more::Display;
use crate::entropy::WindowKind;
use infer::Type;

#[derive(Debug, PartialEq, Display, Clone)]
pub enum Issue {
    #[display("YaraIssue")]
    YaraIssue(String),
    MagicByte,
    #[display("HighRiskFileType")]
    HighRiskFileType(String),
    #[display("HighEntropy")]
    HighEntropy {
        kind: WindowKind,
        start: usize,
        end: usize,
        entropy: f64,
        chi2: f64,
    },
    #[display("ActiveContent")]
    ActiveContent(String),

    #[display("VirusTotal")]
    VirusTotal { malicious: u64, suspicious: u64, total: u64, label: Option<String> },

    Size
}

#[derive(Debug, PartialEq, Display, Copy, Clone)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low
}

#[derive(Debug, PartialEq, Display, Copy, Clone)]
pub enum SubSystem {
    Base,
    Yara,
    Archive,
    Entropy,
    VirusTotal
}

#[derive(Debug, PartialEq, Display)]
#[display("Path: {} | Issue: {} | Severity: {} | SubSystem: {}", path.display(), issue, severity, subsys)]
pub struct Finding {
    pub path: PathBuf,
    pub issue: Issue,
    pub severity: Severity,
    pub subsys: SubSystem
}

impl Finding {
    pub fn new(path: PathBuf, issue: Issue, severity: Severity, subsys: SubSystem) -> Finding {
        Finding {
            path,
            issue,
            severity,
            subsys
        }
    }
}

pub struct Report {
    pub findings: Vec<Finding>,
    pub critical_threats: u32,
    pub high_threats: u32,
    pub medium_threats: u32,
    pub low_threats: u32,
    pub filepath: PathBuf,
    pub metadata: Metadata,
    pub checksum: String,
    pub reported_filetype: String,
    pub real_filetype: Type,
    pub vt_status: Option<String>,
}

impl Report {
    pub fn new(filepath: PathBuf, metadata: Metadata, checksum: String, reported_filetype: String, real_filetype: Type) -> Report {
        Report {
            findings: Vec::new(),
            critical_threats:0,
            high_threats:0,
            medium_threats:0,
            low_threats:0,
            filepath,
            metadata,
            checksum,
            reported_filetype,
            real_filetype,
            vt_status: None
        }
    }

    pub fn add_finding(&mut self, new_finding: Finding) {
        match new_finding.severity {
            Severity::Critical => {
                self.critical_threats += 1
            }
            Severity::High => {
                self.high_threats += 1
            }
            Severity::Medium => {
                self.medium_threats += 1
            }
            Severity::Low => {
                self.low_threats += 1
            }
        }
        self.findings.push(new_finding);
    }

    pub fn generate_report(&self) {
        println!("=====================");
        println!("THREAT ANALYSIS");
        println!("=====================");
        println!("CRITICAL THREATS: {}", self.critical_threats);
        println!("HIGH THREATS: {}", self.high_threats);
        println!("MEDIUM THREATS: {}", self.medium_threats);
        println!("LOW THREATS: {}", self.low_threats);
        println!("\n\nBASE DATA");
        println!("Checksum: {}", self.checksum);
        println!("Length of file: {}", self.metadata.len());
        println!("Is file: {}", self.metadata.is_file());
        println!("Is folder: {}", self.metadata.is_dir());
        println!("Reported extension {}", self.reported_filetype);
        println!("Real extension: {}", self.real_filetype.extension());
        println!("MIME type: {}", self.real_filetype.mime_type());
        match self.reported_filetype.trim().to_lowercase()
            == self.real_filetype.extension().trim().to_lowercase() {
            true => {}
            false => {
                println!("MAGIC BYTE MISMATCH ERROR! | Severity: {}", Severity::Critical)
            }
        }
        println!("\nYARA SUBSYSTEM");
        let yara_errors: Vec<_> = self.findings
            .iter()
            .filter(|x| {x.subsys == SubSystem::Yara})
            .collect();
        if yara_errors.len() == 0 {
            println!("No Yara errors found.")
        } else {
            for i in yara_errors {
                if let Issue::YaraIssue(rule_name) = &i.issue {
                    println!("Path: {} | Rule: {} | Severity: {}", i.path.display(), rule_name, i.severity);
                } else {
                    println!("Path: {} | Issue: {} | Severity: {}", i.path.display(), i.issue, i.severity);
                }
            }
        }
        println!("\nARCHIVE SUBSYSTEM");
        let archive_errors: Vec<_> = self.findings
            .iter()
            .filter(|x| {x.subsys == SubSystem::Archive})
            .collect();
        if archive_errors.len() == 0 {
            println!("No Archive errors found.")
        } else {
            for i in archive_errors {
                if let Issue::YaraIssue(rule) = &i.issue {
                    println!("Path: {} | Issue: {} | Rule: {} | Severity: {}",
                             i.path.display(), i.issue, rule, i.severity);
                } else if let Issue::HighRiskFileType(types) = &i.issue  {
                    println!("Path: {} | Issue: {} | Problem: {} | Severity: {}",
                             i.path.display(), i.issue, types, i.severity);
                } else if let Issue::ActiveContent(markers) = &i.issue  {
                    println!("Path: {} | Issue: {} | Markers: {} | Severity: {}",
                             i.path.display(), i.issue, markers, i.severity);
                } else {
                    println!("Path: {} | Issue: {} | Severity: {}", i.path.display(), i.issue, i.severity);
                }
            }
        }
        println!("\nENTROPY SUBSYSTEM");
        let entropy_errors: Vec<_> = self.findings
            .iter()
            .filter(|x| {x.subsys == SubSystem::Entropy})
            .collect();
        if entropy_errors.len() == 0 {
            println!("No Entropy errors found.")
        } else {
            for i in entropy_errors {
                if let Issue::HighEntropy { kind, start, end, entropy, chi2 } = &i.issue {
                    println!(
                        "Path: {} | {} at {}..{} | entropy {:.2} | chi2 {:.0} | Severity: {}",
                        i.path.display(), kind, start, end, entropy, chi2, i.severity
                    );
                }
            }
        }
        println!("\nVIRUS TOTAL SUBSYSTEM");
        match &self.vt_status {
            None => println!("Not run (use --vt)."),
            Some(status) => println!("{status}"),
        }

        for i in self.findings.iter().filter(|x| x.subsys == SubSystem::VirusTotal) {
            if let Issue::VirusTotal { malicious, suspicious, total, label } = &i.issue {
                println!(
                    "Detections: {} malicious, {} suspicious of {} | Label: {} | Severity: {}",
                    malicious, suspicious, total,
                    label.as_deref().unwrap_or("none"),
                    i.severity
                );
            }
        }

        if self.vt_status.is_some() {
            println!("Details: https://www.virustotal.com/gui/file/{}", self.checksum);
        }
    }
}