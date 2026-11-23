//! How long each step of setting up the AI worker took, so a slow startup can be measured instead
//! of guessed. The latest run is kept in `startup-timing.json` in the worker's private data. It
//! holds step names and durations only: no paths, accounts, servers or model files. It is written
//! each time a serving process is launched, so `runtime_start` covers the launch, not model loading.
use serde::Serialize;
use std::{
    fs,
    path::Path,
    time::{Duration, Instant},
};

const FILE: &str = "startup-timing.json";
/// A setup that keeps retrying must not grow the record without end.
const PHASE_LIMIT: usize = 128;

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct Phase {
    name: String,
    milliseconds: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TimingReport {
    schema_version: u32,
    app_version: String,
    total_milliseconds: u64,
    phases: Vec<Phase>,
}

fn milliseconds(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

pub(crate) struct StartupTiming {
    started: Instant,
    phases: Vec<Phase>,
}
impl StartupTiming {
    pub(crate) fn new() -> Self {
        Self {
            started: Instant::now(),
            phases: Vec::new(),
        }
    }
    /// Records a step that began at `began` and ends now.
    pub(crate) fn phase(&mut self, name: impl Into<String>, began: Instant) {
        if self.phases.len() < PHASE_LIMIT {
            self.phases.push(Phase {
                name: name.into(),
                milliseconds: milliseconds(began.elapsed()),
            });
        }
    }
    pub(crate) fn report(&self, app_version: &str) -> TimingReport {
        TimingReport {
            schema_version: 1,
            app_version: app_version.to_owned(),
            total_milliseconds: milliseconds(self.started.elapsed()),
            phases: self.phases.clone(),
        }
    }
}

/// Best effort: a record that can't be written never affects AI processing.
pub(crate) fn save(data: &Path, report: &TimingReport) {
    let Ok(raw) = serde_json::to_vec_pretty(report) else {
        return;
    };
    let temporary = data.join(format!(".startup-timing-{}.tmp", uuid::Uuid::new_v4()));
    if crate::runtime_store::write_new(&temporary, &raw).is_err()
        || fs::rename(&temporary, data.join(FILE)).is_err()
    {
        let _ = fs::remove_file(&temporary);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_latest_run_replaces_the_last_and_holds_only_steps_and_times() {
        let data = std::env::temp_dir().join(format!("frameleaf-timing-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&data).unwrap();
        for version in ["1.0.0", "1.0.1"] {
            let mut timing = StartupTiming::new();
            timing.phase("runtime_verification", Instant::now());
            save(&data, &timing.report(version));
        }
        let saved: serde_json::Value =
            serde_json::from_slice(&fs::read(data.join(FILE)).unwrap()).unwrap();
        assert_eq!(saved["appVersion"], "1.0.1");
        assert_eq!(saved["phases"][0]["name"], "runtime_verification");
        let mut fields: Vec<_> = saved.as_object().unwrap().keys().cloned().collect();
        fields.sort();
        assert_eq!(
            fields,
            ["appVersion", "phases", "schemaVersion", "totalMilliseconds"]
        );
        assert_eq!(fs::read_dir(&data).unwrap().count(), 1);
        let _ = fs::remove_dir_all(&data);
    }

    #[test]
    fn a_setup_that_keeps_retrying_does_not_grow_the_record_without_end() {
        let mut timing = StartupTiming::new();
        for _ in 0..PHASE_LIMIT + 10 {
            timing.phase("model_test", Instant::now());
        }
        assert_eq!(timing.report("1.0.0").phases.len(), PHASE_LIMIT);
    }
}
