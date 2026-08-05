#![forbid(unsafe_code)]
//! `snow9660` CLI — SnowDrive ISO9660 filesystem tools (Phase 1 stub,
//! `snow9660_main.c`).
//!
//! Subcommands:
//! - `list`: list an ISO directory tree (stub, not yet implemented)

use std::process::ExitCode;

use clap::{Args, Parser};

#[derive(Debug, Parser)]
#[command(
    name = "snow9660",
    about = "SnowDrive ISO9660 filesystem tools",
    version = snow9660::VERSION,
    subcommand_required = true
)]
enum Cli {
    /// List ISO directory tree
    List(ListArgs),
}

#[derive(Args, Debug)]
struct ListArgs {
    /// ISO image file
    image: String,
}

fn main() -> ExitCode {
    match Cli::parse() {
        Cli::List(args) => {
            println!("snow9660: list {}: not yet implemented", args.image);
            ExitCode::SUCCESS
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_accepts_list_subcommand() {
        match Cli::try_parse_from(["snow9660", "list", "disc.iso"]).unwrap() {
            Cli::List(a) => assert_eq!(a.image, "disc.iso"),
        }
    }

    #[test]
    fn cli_list_requires_image() {
        assert!(Cli::try_parse_from(["snow9660", "list"]).is_err());
    }

    #[test]
    fn cli_help_is_displayed() {
        match Cli::try_parse_from(["snow9660", "--help"]) {
            Err(e) if e.kind() == clap::error::ErrorKind::DisplayHelp => {}
            other => panic!("expected DisplayHelp, got {other:?}"),
        }
    }

    #[test]
    fn cli_version_is_displayed() {
        match Cli::try_parse_from(["snow9660", "--version"]) {
            Err(e) if e.kind() == clap::error::ErrorKind::DisplayVersion => {}
            other => panic!("expected DisplayVersion, got {other:?}"),
        }
    }
}
