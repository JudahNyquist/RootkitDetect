mod findings;
mod forensics;
mod integrity;
mod misc;
mod modules;
mod net;
mod procs;
mod report;
mod util;

use clap::{Parser, Subcommand};
use findings::Finding;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(name = "krds", about = "kernel rootkit-ish checks for linux")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// run all the checks
    Scan {
        /// also dump raw artifacts into output/forensics
        #[arg(long)]
        collect: bool,
    },
    /// just grab forensic dumps, no scoring
    Collect,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let out_dir = PathBuf::from("output");
    let _ = std::fs::create_dir_all(&out_dir);

    match cli.cmd {
        Cmd::Scan { collect } => {
            let mut findings: Vec<Finding> = Vec::new();

            eprintln!("[*] modules");
            findings.extend(modules::run());

            eprintln!("[*] processes");
            findings.extend(procs::run());

            eprintln!("[*] network");
            findings.extend(net::run());

            eprintln!("[*] integrity");
            findings.extend(integrity::run(&out_dir));

            eprintln!("[*] misc");
            findings.extend(misc::run());

            let (score, level) = findings::score(&findings);
            let host = util::hostname();
            let kernel = util::uname_r();

            report::write(&out_dir, &host, &kernel, score, &level, &findings);

            println!();
            println!("host={host} kernel={kernel}");
            println!("risk={score:.1}/100 ({level})");
            println!("findings={}", findings.len());
            for f in findings.iter().take(12) {
                println!("  [{:>8}] {}: {}", f.severity, f.kind, f.title);
            }
            if findings.len() > 12 {
                println!("  ... {} more (see output/latest.txt)", findings.len() - 12);
            }
            println!("report: output/latest.txt");

            if collect {
                match forensics::collect(&out_dir.join("forensics")) {
                    Ok(p) => println!("forensics: {}", p.display()),
                    Err(e) => eprintln!("forensics failed: {e}"),
                }
            }

            if matches!(level.as_str(), "medium" | "high" | "critical") {
                ExitCode::from(2)
            } else {
                ExitCode::SUCCESS
            }
        }
        Cmd::Collect => match forensics::collect(&out_dir.join("forensics")) {
            Ok(p) => {
                println!("wrote {}", p.display());
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("{e}");
                ExitCode::FAILURE
            }
        },
    }
}
