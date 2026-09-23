use std::path::PathBuf;
use clap::{Parser};

#[derive(Parser, Debug)]
#[command(name = "safecheck")]
#[command(version)]
#[command(about = "Static file security analyzer")]
pub struct Args {
    /// File to scan
    #[arg(required_unless_present = "update_rules")]
    pub path: Option<PathBuf>,

    /// Download the latest YARA Forge rules
    #[arg(long)]
    pub update_rules: bool
}

pub fn _parse_arguments() -> Args {
    Args::parse()
}
