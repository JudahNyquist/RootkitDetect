use crate::findings::Finding;
use crate::util;
use std::fs;
use std::path::Path;
use std::process::Command;

/// leftovers: audit/sysctl, ld.so.preload, dmesg, kallsyms consistency bits
pub fn run() -> Vec<Finding> {
    let mut out = Vec::new();
    out.extend(sysctl_bits());
    out.extend(audit_bits());
    out.extend(preload_and_paths());
    out.extend(dmesg_bits());
    out.extend(memory_ish());
    out
}

fn sysctl_bits() -> Vec<Finding> {
    let mut out = Vec::new();
    if let Some(v) = util::read_to_string("/proc/sys/kernel/yama/ptrace_scope") {
        if v.trim() == "0" {
            out.push(
                Finding::new(
                    "syscalls",
                    "low",
                    "ptrace_scope is 0",
                    "unrestricted ptrace makes process injection easier",
                )
                .with_score(2.0),
            );
        }
    }
    if let Some(v) = util::read_to_string("/proc/sys/kernel/kptr_restrict") {
        if v.trim() == "0" {
            out.push(
                Finding::new(
                    "syscalls",
                    "info",
                    "kptr_restrict is 0",
                    "kernel pointers visible — good for analysis, also helps attackers",
                )
                .with_score(0.5),
            );
        }
    }
    out
}

fn audit_bits() -> Vec<Finding> {
    let mut out = Vec::new();
    let path = Path::new("/var/log/audit/audit.log");
    if !path.exists() {
        out.push(
            Finding::new(
                "syscalls",
                "info",
                "no audit.log",
                "enable auditd rules for init_module/ptrace/bpf if you want syscall trails",
            )
            .with_score(0.0),
        );
        return out;
    }

    let Ok(data) = fs::read_to_string(path) else {
        return out;
    };
    // only look at the tail
    let lines: Vec<&str> = data.lines().rev().take(5000).collect();
    let interesting = [
        ("init_module", "medium", 6.0),
        ("finit_module", "medium", 6.0),
        ("delete_module", "medium", 6.0),
        ("kexec_load", "high", 20.0),
        ("process_vm_writev", "medium", 7.0),
        ("process_vm_readv", "medium", 7.0),
    ];

    // map names -> nrs on x86_64, also match name in key= if present
    // audit logs usually have syscall=<nr>; we match both nr and exe lines loosely
    let nr = [
        ("175", "init_module"),
        ("313", "finit_module"),
        ("176", "delete_module"),
        ("246", "kexec_load"),
        ("311", "process_vm_writev"),
        ("310", "process_vm_readv"),
    ];

    let mut hits = 0usize;
    for line in lines.iter().filter(|l| l.contains("type=SYSCALL")) {
        for (num, name) in nr {
            if line.contains(&format!("syscall={num}")) {
                let (sev, sc) = interesting
                    .iter()
                    .find(|(n, _, _)| *n == name)
                    .map(|(_, s, c)| (*s, *c))
                    .unwrap_or(("low", 3.0));
                // don't flood — first few only
                if hits < 12 {
                    let exe = grab_field(line, "exe=")
                        .or_else(|| grab_field(line, "comm="))
                        .unwrap_or("?");
                    out.push(
                        Finding::new(
                            "syscalls",
                            sev,
                            format!("audit: {name} by {exe}"),
                            "module load / memory poke / kexec in audit trail — verify it",
                        )
                        .ioc(format!("syscall:{name}"))
                        .with_score(sc),
                    );
                }
                hits += 1;
            }
        }
    }
    out
}

fn grab_field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let i = line.find(key)?;
    let rest = &line[i + key.len()..];
    if let Some(r) = rest.strip_prefix('"') {
        return r.split('"').next();
    }
    rest.split_whitespace().next()
}

fn preload_and_paths() -> Vec<Finding> {
    let mut out = Vec::new();
    let preload = Path::new("/etc/ld.so.preload");
    if preload.exists() {
        if let Ok(meta) = preload.metadata() {
            if meta.len() > 0 {
                let content = util::read_to_string(preload).unwrap_or_default();
                out.push(
                    Finding::new(
                        "behavior",
                        "high",
                        "/etc/ld.so.preload is non-empty",
                        content.chars().take(300).collect::<String>(),
                    )
                    .ioc("file:/etc/ld.so.preload")
                    .with_score(25.0),
                );
            }
        }
    }
    for p in ["/lib/libprocesshider.so", "/dev/shm/.rk"] {
        if Path::new(p).exists() {
            out.push(
                Finding::new(
                    "behavior",
                    "medium",
                    format!("suspicious path exists: {p}"),
                    "common artifact location",
                )
                .ioc(format!("file:{p}"))
                .with_score(10.0),
            );
        }
    }
    out
}

fn dmesg_bits() -> Vec<Finding> {
    let mut out = Vec::new();
    let Ok(o) = Command::new("dmesg").arg("-T").output() else {
        return out;
    };
    let text = String::from_utf8_lossy(&o.stdout);
    let needles = [
        "rootkit",
        "module verification failed",
        "disagrees about version of symbol",
        "loading out-of-tree module taints",
    ];
    let mut n = 0;
    for line in text.lines() {
        let low = line.to_lowercase();
        if needles.iter().any(|k| low.contains(k)) {
            let sev = if low.contains("rootkit") {
                "high"
            } else {
                "low"
            };
            out.push(
                Finding::new("behavior", sev, "interesting dmesg line", line.chars().take(300).collect::<String>())
                    .with_score(if sev == "high" { 5.0 } else { 1.0 }),
            );
            n += 1;
            if n >= 15 {
                break;
            }
        }
    }
    out
}

fn memory_ish() -> Vec<Finding> {
    let mut out = Vec::new();
    // quick check: kallsyms all-zero addrs
    if let Some(ks) = util::read_to_string("/proc/kallsyms") {
        let sample: Vec<_> = ks.lines().take(20).collect();
        if !sample.is_empty()
            && sample
                .iter()
                .filter(|l| !l.is_empty())
                .all(|l| l.starts_with("0000000000000000"))
        {
            out.push(
                Finding::new(
                    "memory",
                    "info",
                    "kernel pointers hidden in kallsyms",
                    "run as root / relax kptr_restrict for deeper analysis",
                )
                .with_score(0.0),
            );
        }
    }
    out
}
