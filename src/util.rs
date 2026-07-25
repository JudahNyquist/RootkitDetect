use std::fs;
use std::path::Path;
use std::process::Command;

pub fn read_to_string(path: impl AsRef<Path>) -> Option<String> {
    fs::read_to_string(path).ok()
}

pub fn uname_r() -> String {
    Command::new("uname")
        .arg("-r")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "?".into())
}

pub fn hostname() -> String {
    read_to_string("/etc/hostname")
        .unwrap_or_else(|| "unknown".into())
        .trim()
        .to_string()
}
