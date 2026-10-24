//! Process RSS admission for a serial, preloaded native worker.
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, PartialEq)]
pub(crate) struct Envelope {
    pub startup: u64,
    pub running: u64,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Observation {
    scope: String,
    before_resident_bytes: u64,
    after_resident_bytes: u64,
    peak_resident_bytes: u64,
}
pub(crate) fn envelope(floor: u64, reports: &[&Value]) -> Result<Envelope, String> {
    let invalid = || String::from("runtime_memory_measurement_invalid");
    let safe = |bytes: u64| bytes > 0 && bytes <= 9_007_199_254_740_991;
    if !safe(floor) || !(1..=64).contains(&reports.len()) {
        return Err(invalid());
    }
    let mut baseline = 0u64;
    let mut resident_growth = 0u64;
    let mut transient = 0u64;
    for report in reports {
        let memory = report
            .get("memory")
            .ok_or("runtime_memory_measurement_required")?;
        let observation: Observation =
            serde_json::from_value(memory.clone()).map_err(|_| invalid())?;
        let Observation {
            scope,
            before_resident_bytes: before,
            after_resident_bytes: after,
            peak_resident_bytes: peak,
        } = observation;
        if scope != "process-lifetime-rss"
            || ![before, after, peak].into_iter().all(safe)
            || peak < before.max(after)
        {
            return Err(invalid());
        }
        baseline = baseline.max(before);
        // Shared allocations may be counted twice; cache paths alone cannot prove shared live sessions.
        resident_growth = resident_growth
            .checked_add(after.saturating_sub(before))
            .ok_or_else(invalid)?;
        transient = transient.max(peak - after);
    }
    let resident = baseline.checked_add(resident_growth).ok_or_else(invalid)?;
    // Keep the compiled free-memory floor even when the observed peak remains resident.
    let running = floor.max(transient);
    let startup = resident.checked_add(running).ok_or_else(invalid)?;
    Ok(Envelope { startup, running })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn report(before: u64, after: u64, peak: u64) -> Value {
        json!({"memory": {"scope":"process-lifetime-rss", "beforeResidentBytes":before,
            "afterResidentBytes":after, "peakResidentBytes":peak}})
    }
    #[test]
    fn resident_models_are_not_reserved_again_as_free_memory() {
        let observed = report(100, 300, 400);
        assert_eq!(
            envelope(50, &[&observed]).unwrap(),
            Envelope {
                startup: 400,
                running: 100
            }
        );
    }
    #[test]
    fn grouped_models_keep_all_residency_but_only_serial_transient_headroom() {
        let a = report(100, 300, 500);
        let b = report(100, 400, 650);
        assert_eq!(
            envelope(100, &[&a, &b]).unwrap(),
            Envelope {
                startup: 850,
                running: 250
            }
        );
    }
    #[test]
    fn fully_resident_peak_still_keeps_the_compiled_free_memory_floor() {
        let observed = report(100, 300, 300);
        assert_eq!(
            envelope(500, &[&observed]).unwrap(),
            Envelope {
                startup: 800,
                running: 500
            }
        );
        assert!(envelope(0, &[&observed]).is_err());
        assert!(envelope(1, &[]).is_err());
        assert!(envelope(1, &vec![&observed; 65]).is_err());
    }
    #[test]
    fn missing_or_malformed_measurements_never_become_a_measured_envelope() {
        assert_eq!(
            envelope(500, &[&json!({})]).unwrap_err(),
            "runtime_memory_measurement_required"
        );
        for bad in [
            report(100, 400, 300),
            json!({"memory":null}),
            json!({"memory":{"scope":"gpu-memory", "beforeResidentBytes":100,
                "afterResidentBytes":200, "peakResidentBytes":300}}),
        ] {
            assert_eq!(
                envelope(500, &[&bad]).unwrap_err(),
                "runtime_memory_measurement_invalid"
            );
        }
    }
}
