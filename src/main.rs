//! nikpak - command-line archiver for the .nik format.

mod archive;
mod bits;
mod cli;
mod crypto;
mod error;
mod format;
mod media;
mod nac;
mod util;

use cli::{Command, Parsed};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.is_empty() {
        println!("nikpak {} - fast archiver for the .nik format", cli::VERSION);
        println!();
        println!("Usage: nikpak <command> [options] <archive.nik> [files...]");
        println!("Commands: a (add)  x (extract)  e (extract flat)  l (list)  t (test)");
        println!();
        println!("Use 'nikpak -help' for all options and examples.");
        return ExitCode::from(7);
    }

    let parsed = match cli::parse(&args) {
        Ok(p) => p,
        Err(e) => return report(e),
    };

    let result = match parsed {
        Parsed::Help => {
            print!("{}", cli::HELP);
            return ExitCode::SUCCESS;
        }
        Parsed::Version => {
            println!("nikpak {}", cli::VERSION);
            return ExitCode::SUCCESS;
        }
        Parsed::Run(o) => match o.command {
            Command::Add => archive::create(&o),
            Command::ExtractFull | Command::ExtractFlat => archive::extract(&o),
            Command::List | Command::ListVerbose | Command::ListBare => archive::list(&o),
            Command::Test => archive::test(&o),
            Command::MediaTest => archive::media_test(&o),
        },
    };

    match result {
        Ok(code) => ExitCode::from(code),
        Err(e) => report(e),
    }
}

fn report(e: error::NikError) -> ExitCode {
    eprintln!("ERROR: {e}");
    ExitCode::from(e.exit_code())
}
