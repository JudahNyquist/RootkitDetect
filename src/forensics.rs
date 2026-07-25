use crate::util;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

pub fn collect(base: &Path) -> io::Result<PathBuf> {
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let dir = base.join(&stamp);
    fs::create_dir_all(&dir)?;

    // modules
    if let Some(m) = util::read_to_string("/proc/modules") {
        fs::write(dir.join("proc_modules.txt"), m)?;
    }

    // rough process list
    let mut procs = String::from("pid\tcomm\texe\tcmdline\n");
    if let Ok(rd) = fs::read_dir("/proc") {
        for e in rd.flatten() {
            let name = e.file_name();
            let Ok(pid) = name.to_string_lossy().parse::<i32>() else {
                continue;
            };
            let comm = util::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
            let cmd = util::read_to_string(format!("/proc/{pid}/cmdline"))
                .unwrap_or_default()
                .replace('\0', " ");
            let exe = fs::read_link(format!("/proc/{pid}/exe"))
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            procs.push_str(&format!(
                "{pid}\t{}\t{exe}\t{}\n",
                comm.trim(),
                cmd.trim()
            ));
        }
    }
    fs::write(dir.join("processes.tsv"), procs)?;

    for t in ["tcp", "tcp6", "udp", "udp6"] {
        if let Some(d) = util::read_to_string(format!("/proc/net/{t}")) {
            fs::write(dir.join(format!("proc_net_{t}.txt")), d)?;
        }
    }

    if let Ok(o) = Command::new("ss").args(["-antup"]).output() {
        fs::write(dir.join("ss.txt"), o.stdout)?;
    }
    if let Ok(o) = Command::new("dmesg").arg("-T").output() {
        fs::write(dir.join("dmesg.txt"), o.stdout)?;
    }

    let sys = format!(
        "tainted={}\nmodules_disabled={}\nkptr_restrict={}\nptrace_scope={}\n",
        util::read_to_string("/proc/sys/kernel/tainted").unwrap_or_default().trim(),
        util::read_to_string("/proc/sys/kernel/modules_disabled")
            .unwrap_or_default()
            .trim(),
        util::read_to_string("/proc/sys/kernel/kptr_restrict")
            .unwrap_or_default()
            .trim(),
        util::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
            .unwrap_or_default()
            .trim(),
    );
    fs::write(dir.join("sys_state.txt"), sys)?;

    Ok(dir)
}
