use crate::findings::Finding;
use crate::util;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;

const KNOWN_MODS: &[(&str, &str)] = &[
    ("diamorphine", "Diamorphine"),
    ("reptile", "Reptile"),
    ("suterusu", "Suterusu"),
    ("adore", "Adore-ng"),
    ("adore-ng", "Adore-ng"),
];

const BAD_SYMS: &[&str] = &[
    "hacked_getdents",
    "hacked_kill",
    "give_root",
    "hide_module",
    "hidden_tcp4_seq_show",
];

pub fn run() -> Vec<Finding> {
    let mut out = Vec::new();
    let proc_mods = parse_proc_modules();
    let sysfs = list_sysfs_modules();

    let sus_re =
        Regex::new(r"(?i)rootkit|hide|stealth|backdoor|^rk|diamorphine|reptile|suterusu|adore")
            .expect("regex");

    for (name, info) in &proc_mods {
        let lower = name.to_lowercase();
        for (sig, label) in KNOWN_MODS {
            if &lower == sig || lower.contains(sig) {
                out.push(
                    Finding::new(
                        "modules",
                        "critical",
                        format!("known rootkit module: {label} ({name})"),
                        "module name matches a known LKM rootkit signature",
                    )
                    .ioc(format!("module:{name}"))
                    .ioc(format!("rootkit:{label}"))
                    .with_score(40.0),
                );
            }
        }
        if sus_re.is_match(name) {
            out.push(
                Finding::new(
                    "modules",
                    "high",
                    format!("suspicious module name: {name}"),
                    format!("addr={} size={}", info.addr, info.size),
                )
                .ioc(format!("module:{name}"))
                .with_score(20.0),
            );
        }
    }

    for name in &sysfs {
        if proc_mods.contains_key(name) {
            continue;
        }
        let base = Path::new("/sys/module").join(name);
        if !base.join("coresize").exists() || !base.join("sections").is_dir() {
            continue;
        }
        if kallsyms_mentions_module(name) {
            out.push(
                Finding::new(
                    "modules",
                    "high",
                    format!("possible hidden module: {name}"),
                    "in /sys/module + kallsyms but missing from /proc/modules",
                )
                .ioc(format!("module:{name}"))
                .with_score(25.0),
            );
        }
    }

    for name in proc_mods.keys() {
        if !sysfs.contains(name) {
            out.push(
                Finding::new(
                    "modules",
                    "medium",
                    format!("in /proc/modules but not sysfs: {name}"),
                    "module list views disagree",
                )
                .ioc(format!("module:{name}"))
                .with_score(10.0),
            );
        }
    }

    if let Some(ks) = util::read_to_string("/proc/kallsyms") {
        for sym in BAD_SYMS {
            // crude substring check is fine for these unique names
            if ks.lines().any(|l| l.split_whitespace().any(|t| t == *sym)) {
                out.push(
                    Finding::new(
                        "modules",
                        "critical",
                        format!("rootkit symbol in kallsyms: {sym}"),
                        "symbol commonly left by public teaching rootkits",
                    )
                    .ioc(format!("symbol:{sym}"))
                    .with_score(40.0),
                );
            }
        }
    }

    if let Some(t) = util::read_to_string("/proc/sys/kernel/tainted") {
        let t = t.trim();
        if t != "0" && !t.is_empty() {
            out.push(
                Finding::new(
                    "modules",
                    "info",
                    format!("kernel tainted ({t})"),
                    "often proprietary/out-of-tree modules; also set by some rootkits",
                )
                .with_score(1.0),
            );
        }
    }

    let release = util::uname_r();
    let mut missing = 0usize;
    let mut sample = Vec::new();
    for name in proc_mods.keys() {
        if !module_on_disk(name, &release) {
            missing += 1;
            if sample.len() < 15 {
                sample.push(name.clone());
            }
        }
    }
    if missing > 0 {
        let sev = if missing >= 30 { "medium" } else { "low" };
        out.push(
            Finding::new(
                "modules",
                sev,
                format!("{missing} modules have no matching .ko under /lib/modules"),
                format!("sample: {}", sample.join(", ")),
            )
            .with_score((2.0 + missing as f64 * 0.2).min(15.0)),
        );
    }

    out
}

struct ModInfo {
    size: u64,
    addr: String,
}

fn parse_proc_modules() -> HashMap<String, ModInfo> {
    let mut map = HashMap::new();
    let Some(data) = util::read_to_string("/proc/modules") else {
        return map;
    };
    for line in data.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }
        let addr = parts
            .iter()
            .copied()
            .find(|p| p.starts_with("0x"))
            .unwrap_or("")
            .to_string();
        map.insert(
            parts[0].to_string(),
            ModInfo {
                size: parts[1].parse().unwrap_or(0),
                addr,
            },
        );
    }
    map
}

fn list_sysfs_modules() -> HashSet<String> {
    let mut s = HashSet::new();
    let Ok(rd) = fs::read_dir("/sys/module") else {
        return s;
    };
    for e in rd.flatten() {
        if e.path().is_dir() {
            s.insert(e.file_name().to_string_lossy().into());
        }
    }
    s
}

fn kallsyms_mentions_module(name: &str) -> bool {
    let needle = format!("[{name}]");
    let Ok(f) = fs::File::open("/proc/kallsyms") else {
        return false;
    };
    for line in BufReader::new(f).lines().flatten() {
        if line.contains(&needle) {
            return true;
        }
    }
    false
}

fn module_on_disk(name: &str, release: &str) -> bool {
    let base = Path::new("/lib/modules").join(release);
    if !base.is_dir() {
        return false;
    }
    let candidates = [
        name.to_string(),
        name.replace('-', "_"),
        name.replace('_', "-"),
    ];
    for entry in walkdir::WalkDir::new(&base).into_iter().flatten() {
        let fname = entry.file_name().to_string_lossy();
        if !(fname.ends_with(".ko") || fname.ends_with(".ko.zst") || fname.ends_with(".ko.xz")) {
            continue;
        }
        let stem = fname.split('.').next().unwrap_or("");
        let stem_n = stem.replace('-', "_");
        for c in &candidates {
            if stem == c.as_str() || stem_n == c.replace('-', "_") {
                return true;
            }
        }
    }
    false
}
