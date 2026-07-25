use crate::findings::Finding;
use chrono::Utc;
use serde::Serialize;
use std::fs;
use std::path::Path;

#[derive(Serialize)]
struct Report<'a> {
    host: &'a str,
    kernel: &'a str,
    when: String,
    risk_score: f64,
    risk_level: &'a str,
    findings: &'a [Finding],
}

pub fn write(
    out_dir: &Path,
    host: &str,
    kernel: &str,
    score: f64,
    level: &str,
    findings: &[Finding],
) {
    let _ = fs::create_dir_all(out_dir);
    let when = Utc::now().to_rfc3339();
    let rep = Report {
        host,
        kernel,
        when: when.clone(),
        risk_score: score,
        risk_level: level,
        findings,
    };

    if let Ok(j) = serde_json::to_string_pretty(&rep) {
        let _ = fs::write(out_dir.join("latest.json"), &j);
        let stamp = when.replace(':', "").replace('+', "_");
        let _ = fs::write(out_dir.join(format!("scan_{stamp}.json")), j);
    }

    let mut txt = String::new();
    txt.push_str("krds scan report\n");
    txt.push_str(&format!("host:   {host}\n"));
    txt.push_str(&format!("kernel: {kernel}\n"));
    txt.push_str(&format!("when:   {when}\n"));
    txt.push_str(&format!("risk:   {score:.1}/100 ({level})\n"));
    txt.push_str(&format!("count:  {}\n\n", findings.len()));

    let mut sorted = findings.to_vec();
    sorted.sort_by(|a, b| sev_rank(&b.severity).cmp(&sev_rank(&a.severity)));
    for (i, f) in sorted.iter().enumerate() {
        txt.push_str(&format!(
            "[{}] [{}] ({}) {}\n    {}\n",
            i + 1,
            f.severity,
            f.kind,
            f.title,
            f.detail
        ));
        if !f.iocs.is_empty() {
            txt.push_str(&format!("    iocs: {}\n", f.iocs.join(", ")));
        }
        txt.push('\n');
    }
    txt.push_str("note: if the kernel is already owned, this tool can be lied to.\n");

    let _ = fs::write(out_dir.join("latest.txt"), &txt);
}

fn sev_rank(s: &str) -> u8 {
    match s {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}
