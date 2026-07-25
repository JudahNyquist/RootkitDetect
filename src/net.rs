use crate::findings::Finding;
use crate::util;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::process::Command;

const SUS_PORTS: &[u16] = &[4444, 31337, 12345, 6666, 6667, 1337];

pub fn run() -> Vec<Finding> {
    let mut out = Vec::new();
    let mut socks = Vec::new();
    socks.extend(parse_table("tcp"));
    socks.extend(parse_table("tcp6"));
    socks.extend(parse_table("udp"));
    socks.extend(parse_table("udp6"));

    let inode_map = inode_to_pids();
    let listeners: Vec<_> = socks
        .iter()
        .filter(|s| s.table.starts_with("tcp") && s.state == "LISTEN")
        .cloned()
        .collect();

    for s in &listeners {
        let pids = inode_map.get(&s.inode).cloned().unwrap_or_default();
        if pids.is_empty() {
            out.push(
                Finding::new(
                    "network",
                    "high",
                    format!("orphan listening socket on port {}", s.local_port),
                    format!(
                        "{}:{} inode={} — no process fd points at it",
                        s.local_ip, s.local_port, s.inode
                    ),
                )
                .ioc(format!("port:{}", s.local_port))
                .ioc(format!("inode:{}", s.inode))
                .with_score(18.0),
            );
        }
        if SUS_PORTS.contains(&s.local_port) {
            out.push(
                Finding::new(
                    "network",
                    "medium",
                    format!("listener on sketchy port {}", s.local_port),
                    "port shows up a lot in malware / teaching backdoors",
                )
                .ioc(format!("port:{}", s.local_port))
                .with_score(8.0),
            );
        }
    }

    let ss_ports = ss_listen_ports();
    let proc_ports: HashSet<u16> = listeners.iter().map(|s| s.local_port).collect();
    for p in proc_ports.difference(&ss_ports) {
        out.push(
            Finding::new(
                "network",
                "medium",
                format!("port {p} in /proc/net but not in ss"),
                "kernel table and ss disagree",
            )
            .ioc(format!("port:{p}"))
            .with_score(10.0),
        );
    }
    for p in ss_ports.difference(&proc_ports) {
        out.push(
            Finding::new(
                "network",
                "low",
                format!("port {p} in ss but not in /proc/net tcp(6)"),
                "might just be ipv6/raw parsing differences — check manually",
            )
            .ioc(format!("port:{p}"))
            .with_score(3.0),
        );
    }

    for s in &socks {
        if s.state == "ESTABLISHED" && SUS_PORTS.contains(&s.remote_port) {
            out.push(
                Finding::new(
                    "network",
                    "medium",
                    format!("established conn to suspicious remote port {}", s.remote_port),
                    format!("{}:{} -> {}:{}", s.local_ip, s.local_port, s.remote_ip, s.remote_port),
                )
                .ioc(format!("remote:{}:{}", s.remote_ip, s.remote_port))
                .with_score(8.0),
            );
        }
    }

    let _ = util::read_to_string("/proc/net/dev");
    out
}

#[derive(Clone)]
struct Sock {
    table: String,
    local_ip: String,
    local_port: u16,
    remote_ip: String,
    remote_port: u16,
    state: String,
    inode: String,
}

fn parse_table(table: &str) -> Vec<Sock> {
    let mut rows = Vec::new();
    let Some(data) = util::read_to_string(format!("/proc/net/{table}")) else {
        return rows;
    };
    for line in data.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }
        let (lip, lport) = parse_addr(parts[1]);
        let (rip, rport) = parse_addr(parts[2]);
        let state = if table.starts_with("tcp") {
            tcp_state(parts[3])
        } else {
            parts[3].to_string()
        };
        rows.push(Sock {
            table: table.into(),
            local_ip: lip,
            local_port: lport,
            remote_ip: rip,
            remote_port: rport,
            state,
            inode: parts[9].into(),
        });
    }
    rows
}

fn parse_addr(s: &str) -> (String, u16) {
    let Some((ip_hex, port_hex)) = s.split_once(':') else {
        return (s.into(), 0);
    };
    let port = u16::from_str_radix(port_hex, 16).unwrap_or(0);
    if ip_hex.len() == 8 {
        if let Ok(raw) = u32::from_str_radix(ip_hex, 16) {
            let b = raw.to_le_bytes();
            return (format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]), port);
        }
    }
    (ip_hex.into(), port)
}

fn tcp_state(code: &str) -> String {
    match code {
        "01" => "ESTABLISHED",
        "0A" => "LISTEN",
        "02" => "SYN_SENT",
        "03" => "SYN_RECV",
        "06" => "TIME_WAIT",
        "07" => "CLOSE",
        "08" => "CLOSE_WAIT",
        _ => code,
    }
    .into()
}

fn inode_to_pids() -> HashMap<String, Vec<i32>> {
    let mut map: HashMap<String, Vec<i32>> = HashMap::new();
    let Ok(rd) = fs::read_dir("/proc") else {
        return map;
    };
    for e in rd.flatten() {
        let name = e.file_name();
        let Ok(pid) = name.to_string_lossy().parse::<i32>() else {
            continue;
        };
        let fd_dir = e.path().join("fd");
        let Ok(fds) = fs::read_dir(fd_dir) else {
            continue;
        };
        for fd in fds.flatten() {
            let Ok(target) = fs::read_link(fd.path()) else {
                continue;
            };
            let t = target.to_string_lossy();
            if let Some(rest) = t.strip_prefix("socket:[") {
                if let Some(inode) = rest.strip_suffix(']') {
                    map.entry(inode.to_string()).or_default().push(pid);
                }
            }
        }
    }
    map
}

fn ss_listen_ports() -> HashSet<u16> {
    let mut s = HashSet::new();
    let Ok(o) = Command::new("ss").args(["-lntuH"]).output() else {
        return s;
    };
    for line in String::from_utf8_lossy(&o.stdout).lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }
        if let Some(port) = parts[4].rsplit(':').next() {
            if let Ok(p) = port.parse::<u16>() {
                s.insert(p);
            }
        }
    }
    s
}

// silence unused import warning if metadata unused — keep for later
#[allow(dead_code)]
fn _inode_of(path: &str) -> Option<u64> {
    fs::metadata(path).ok().map(|m| m.ino())
}
