use crate::findings::Finding;
use crate::util;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize, Default)]
struct Baseline {
    kernel: String,
    files: HashMap<String, String>,
    kallsyms_sample: String,
    kallsyms_lines: usize,
    modules_hash: String,
}

pub fn run(out_dir: &Path) -> Vec<Finding> {
    let mut out = Vec::new();
    let baseline_path = out_dir.join("integrity_baseline.json");
    let snap = snapshot();

    if !baseline_path.exists() {
        if let Ok(j) = serde_json::to_string_pretty(&snap) {
            let _ = fs::write(&baseline_path, j);
        }
        out.push(
            Finding::new(
                "integrity",
                "info",
                "integrity baseline created",
                format!("wrote {}", baseline_path.display()),
            )
            .with_score(0.0),
        );
    } else if let Ok(data) = fs::read_to_string(&baseline_path) {
        if let Ok(base) = serde_json::from_str::<Baseline>(&data) {
            for (path, hash) in &snap.files {
                match base.files.get(path) {
                    None => out.push(
                        Finding::new(
                            "integrity",
                            "medium",
                            format!("new critical file: {path}"),
                            "showed up after baseline",
                        )
                        .ioc(format!("file:{path}"))
                        .with_score(8.0),
                    ),
                    Some(old) if old != hash => out.push(
                        Finding::new(
                            "integrity",
                            "high",
                            format!("hash mismatch: {path}"),
                            format!("was {old}, now {hash}"),
                        )
                        .ioc(format!("file:{path}"))
                        .ioc(format!("sha256:{hash}"))
                        .with_score(20.0),
                    ),
                    _ => {}
                }
            }
            for path in base.files.keys() {
                if !snap.files.contains_key(path) {
                    out.push(
                        Finding::new(
                            "integrity",
                            "high",
                            format!("monitored file missing: {path}"),
                            "present in baseline, gone now",
                        )
                        .ioc(format!("file:{path}"))
                        .with_score(15.0),
                    );
                }
            }
            if !base.kallsyms_sample.is_empty() && base.kallsyms_sample != snap.kallsyms_sample
            {
                out.push(
                    Finding::new(
                        "integrity",
                        "medium",
                        "kallsyms sample hash changed",
                        "symbol table sample drifted — check module list",
                    )
                    .with_score(8.0),
                );
            }
            let delta = snap.kallsyms_lines.abs_diff(base.kallsyms_lines);
            if delta > 500 {
                out.push(
                    Finding::new(
                        "integrity",
                        "low",
                        format!("large kallsyms line-count delta ({delta})"),
                        "normal after big module loads, still worth a glance",
                    )
                    .with_score(3.0),
                );
            }
            if base.modules_hash != snap.modules_hash {
                out.push(
                    Finding::new(
                        "integrity",
                        "low",
                        "/proc/modules changed since baseline",
                        "expected after loading drivers; review if unexpected",
                    )
                    .with_score(2.0),
                );
            }
        }
    }

    const BAD: &[&str] = &[
        "hacked_getdents",
        "hacked_kill",
        "give_root",
        "hide_module",
        "hidden_tcp4_seq_show",
    ];
    if let Some(ks) = util::read_to_string("/proc/kallsyms") {
        for sym in BAD {
            if ks.lines().any(|l| l.split_whitespace().any(|t| t == *sym)) {
                out.push(
                    Finding::new(
                        "integrity",
                        "critical",
                        format!("suspicious kernel symbol: {sym}"),
                        "matches known teaching-rootkit symbols",
                    )
                    .ioc(format!("symbol:{sym}"))
                    .with_score(40.0),
                );
            }
        }
    }

    out
}

fn snapshot() -> Baseline {
    let mut files = HashMap::new();
    let boot = PathBuf::from("/boot");
    if let Ok(rd) = fs::read_dir(&boot) {
        for e in rd.flatten() {
            let p = e.path();
            let name = e.file_name().to_string_lossy().to_string();
            if !(name.starts_with("vmlinuz")
                || name.starts_with("System.map")
                || name.starts_with("initrd")
                || name.starts_with("initramfs")
                || name.ends_with(".efi"))
            {
                continue;
            }
            if let Some(h) = sha256_file(&p) {
                files.insert(p.to_string_lossy().into(), h);
            }
        }
    }

    let mut kallsyms_lines = 0usize;
    let mut sample = String::new();
    if let Some(ks) = util::read_to_string("/proc/kallsyms") {
        for (i, line) in ks.lines().enumerate() {
            kallsyms_lines += 1;
            if i < 2000 {
                sample.push_str(line);
                sample.push('\n');
            }
        }
    }

    let modules = util::read_to_string("/proc/modules").unwrap_or_default();

    Baseline {
        kernel: util::uname_r(),
        files,
        kallsyms_sample: hex_sha256(sample.as_bytes()),
        kallsyms_lines,
        modules_hash: hex_sha256(modules.as_bytes()),
    }
}

fn sha256_file(path: &Path) -> Option<String> {
    let mut f = fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    let mut total = 0usize;
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n;
        if total >= 64 * 1024 * 1024 {
            break;
        }
    }
    Some(hex::encode(hasher.finalize()))
}

fn hex_sha256(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}
