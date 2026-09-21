use std::path::PathBuf;
use derive_more::Display;
use clap::{Parser};

#[derive(Parser, Debug, Display)]
#[command(name = "safecheck")]
#[command(version)]
#[command(about = "Static file security analyzer")]
#[display("File path: {}", path.display())]
pub struct Args {
    pub path: PathBuf
}

pub fn _parse_arguments() -> Args {
    Args::parse()
}
