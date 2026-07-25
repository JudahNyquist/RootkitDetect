use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub kind: String,
    pub severity: String,
    pub title: String,
    pub detail: String,
    pub iocs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
}

impl Finding {
    pub fn new(
        kind: &str,
        severity: &str,
        title: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            kind: kind.into(),
            severity: severity.into(),
            title: title.into(),
            detail: detail.into(),
            iocs: Vec::new(),
            score: None,
        }
    }

    pub fn ioc(mut self, s: impl Into<String>) -> Self {
        self.iocs.push(s.into());
        self
    }

    pub fn with_score(mut self, s: f64) -> Self {
        self.score = Some(s);
        self
    }
}

fn sev_points(sev: &str) -> f64 {
    match sev {
        "critical" => 35.0,
        "high" => 18.0,
        "medium" => 8.0,
        "low" => 3.0,
        _ => 0.5,
    }
}

pub fn score(findings: &[Finding]) -> (f64, String) {
    let mut raw = 0.0;
    let mut has_crit = false;
    for f in findings {
        if f.severity == "critical" {
            has_crit = true;
        }
        raw += f.score.unwrap_or_else(|| sev_points(&f.severity));
    }
    // soft cap so one noisy host doesn't always hit 100
    let mut risk = (raw * 0.6).min(100.0);
    if has_crit {
        risk = risk.max(60.0);
    }
    let level = if risk >= 80.0 {
        "critical"
    } else if risk >= 60.0 {
        "high"
    } else if risk >= 35.0 {
        "medium"
    } else if risk >= 15.0 {
        "low"
    } else {
        "info"
    };
    (risk, level.into())
}
