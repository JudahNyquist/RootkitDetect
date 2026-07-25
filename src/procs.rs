use crate::findings::Finding;
use crate::util;
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::process::Command;

pub fn run() -> Vec<Finding> {
    let mut out = Vec::new();
    let via_readdir = pids_readdir();
    let via_stat = pids_stat_probe(&via_readdir);
    let via_ps = pids_ps();

    // visible via direct /proc/pid/stat but not listdir(/proc)
    for pid in via_stat.difference(&via_readdir) {
        let tgid = status_field(*pid, "Tgid");
        if let Ok(tgid) = tgid.parse::<i32>() {
            if tgid != *pid && via_readdir.contains(&tgid) {
                // just a thread of a visible process
                continue;
            }
        }
        if !Path::new(&format!("/proc/{pid}")).exists() {
            continue;
        }
        let comm = read_comm(*pid);
        out.push(
            Finding::new(
                "processes",
                "critical",
                format!("possible hidden process pid={pid} ({comm})"),
                "seen via /proc/pid/stat probe but missing from /proc readdir",
            )
            .ioc(format!("pid:{pid}"))
            .ioc(format!("comm:{comm}"))
            .with_score(35.0),
        );
    }

    // in /proc but ps missed it (skip kernel threads: empty cmdline + no exe)
    for pid in via_readdir.difference(&via_ps) {
        let cmd = read_cmdline(*pid);
        let exe = read_exe(*pid);
        if cmd.is_empty() && exe.is_empty() {
            continue;
        }
        let comm = read_comm(*pid);
        out.push(
            Finding::new(
                "processes",
                "high",
                format!("process invisible to ps: pid={pid} ({comm})"),
                "shows up in /proc but not in `ps -e`",
            )
            .ioc(format!("pid:{pid}"))
            .with_score(20.0),
        );
    }

    for pid in &via_readdir {
        let exe = read_exe(*pid);
        if exe.contains("(deleted)") && !read_cmdline(*pid).is_empty() {
            out.push(
                Finding::new(
                    "processes",
                    "medium",
                    format!("running from deleted binary: pid={pid}"),
                    format!("exe={exe}"),
                )
                .ioc(format!("pid:{pid}"))
                .ioc(format!("exe:{exe}"))
                .with_score(8.0),
            );
        }
        if exe.contains("memfd:") {
            out.push(
                Finding::new(
                    "processes",
                    "high",
                    format!("executed from memfd: pid={pid}"),
                    format!("exe={exe}"),
                )
                .ioc(format!("pid:{pid}"))
                .ioc("technique:memfd_create")
                .with_score(15.0),
            );
        }

        // LD_PRELOAD in environ
        if let Ok(env) = fs::read(format!("/proc/{pid}/environ")) {
            if env.windows(11).any(|w| w == b"LD_PRELOAD=") {
                let preload = env
                    .split(|b| *b == 0)
                    .filter_map(|p| std::str::from_utf8(p).ok())
                    .find(|s| s.starts_with("LD_PRELOAD="))
                    .unwrap_or("LD_PRELOAD=?")
                    .to_string();
                out.push(
                    Finding::new(
                        "processes",
                        "medium",
                        format!("LD_PRELOAD set for pid={pid}"),
                        preload.clone(),
                    )
                    .ioc(format!("pid:{pid}"))
                    .ioc(preload)
                    .with_score(8.0),
                );
            }
        }
    }

    let _ = util::read_to_string("/proc/loadavg");
    out
}

fn pids_readdir() -> HashSet<i32> {
    let mut s = HashSet::new();
    let Ok(rd) = fs::read_dir("/proc") else {
        return s;
    };
    for e in rd.flatten() {
        if let Ok(n) = e.file_name().to_string_lossy().parse::<i32>() {
            s.insert(n);
        }
    }
    s
}

fn pids_stat_probe(known: &HashSet<i32>) -> HashSet<i32> {
    let mut s = HashSet::new();
    let pid_max = util::read_to_string("/proc/sys/kernel/pid_max")
        .and_then(|t| t.trim().parse().ok())
        .unwrap_or(32768);

    let mut cands: HashSet<i32> = known.clone();
    for pid in known {
        for d in -2i32..=3 {
            cands.insert(pid + d);
        }
        // threads
        if let Ok(rd) = fs::read_dir(format!("/proc/{pid}/task")) {
            for e in rd.flatten() {
                if let Ok(t) = e.file_name().to_string_lossy().parse::<i32>() {
                    cands.insert(t);
                }
            }
        }
    }
    for i in 1..512.min(pid_max) {
        cands.insert(i);
    }

    for pid in cands {
        if pid <= 0 || pid > pid_max {
            continue;
        }
        if Path::new(&format!("/proc/{pid}/stat")).exists() {
            s.insert(pid);
        }
    }
    s
}

fn pids_ps() -> HashSet<i32> {
    let mut s = HashSet::new();
    let Ok(o) = Command::new("ps").args(["-e", "-o", "pid="]).output() else {
        return s;
    };
    for line in String::from_utf8_lossy(&o.stdout).lines() {
        if let Ok(p) = line.trim().parse::<i32>() {
            s.insert(p);
        }
    }
    s
}

fn read_comm(pid: i32) -> String {
    util::read_to_string(format!("/proc/{pid}/comm"))
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn read_cmdline(pid: i32) -> String {
    util::read_to_string(format!("/proc/{pid}/cmdline"))
        .unwrap_or_default()
        .replace('\0', " ")
        .trim()
        .to_string()
}

fn read_exe(pid: i32) -> String {
    fs::read_link(format!("/proc/{pid}/exe"))
        .map(|p| p.to_string_lossy().into())
        .unwrap_or_default()
}

fn status_field(pid: i32, field: &str) -> String {
    let Some(data) = util::read_to_string(format!("/proc/{pid}/status")) else {
        return String::new();
    };
    for line in data.lines() {
        if let Some(rest) = line.strip_prefix(field) {
            if let Some(rest) = rest.strip_prefix(':') {
                return rest.trim().to_string();
            }
        }
    }
    String::new()
}
