//! Host metric threshold alerts — the state machine behind the alert the
//! module docs deferred ("Threshold alerts are deferred", mod.rs).
//!
//! Pure logic, no I/O: `scrape_once` feeds each sample in and sends one
//! alert per returned [`Breach`]. A metric must hold at or above its
//! threshold for [`CONSECUTIVE`] scrapes before it fires — a single load
//! spike stays out of your sinks — and must fall [`HYSTERESIS`] points
//! below the threshold before it can fire again, so a value hovering at
//! the line cannot flap.
//!
//! State is in-memory, owned by the collector loop: a restart re-arms
//! everything, so the worst case is one duplicate alert after a restart
//! while a metric is already over its threshold.

use crate::config::AlertsConfig;

/// Scrapes a metric must stay at/above threshold before an alert fires
/// (~90 s at the 30 s scrape interval).
const CONSECUTIVE: u32 = 3;

/// Points below threshold a metric must fall before it can alert again.
const HYSTERESIS: f64 = 5.0;

/// One metric crossing its configured line, ready to be formatted.
pub struct Breach {
    pub label: &'static str,
    pub value: f64,
    pub threshold: f64,
}

#[derive(Default)]
pub struct ThresholdState {
    cpu: MetricState,
    mem: MetricState,
    disk: MetricState,
}

#[derive(Default)]
struct MetricState {
    /// Consecutive scrapes at/above threshold.
    over: u32,
    /// An alert for the current excursion has already fired.
    alerted: bool,
}

impl MetricState {
    /// Returns true exactly once per excursion above `threshold`.
    fn observe(&mut self, value: f64, threshold: f64) -> bool {
        if threshold <= 0.0 {
            return false; // disabled in config
        }
        if value >= threshold {
            self.over += 1;
            if !self.alerted && self.over >= CONSECUTIVE {
                self.alerted = true;
                return true;
            }
        } else {
            self.over = 0;
            if value < threshold - HYSTERESIS {
                self.alerted = false;
            }
        }
        false
    }
}

impl ThresholdState {
    /// Feed one scrape's readings; returns the breaches that should alert now.
    pub fn observe(&mut self, cpu: f64, mem: f64, disk: f64, cfg: &AlertsConfig) -> Vec<Breach> {
        let checks = [
            ("CPU", cpu, cfg.cpu_alert_pct, &mut self.cpu),
            ("Memory", mem, cfg.mem_alert_pct, &mut self.mem),
            ("Disk", disk, cfg.disk_alert_pct, &mut self.disk),
        ];
        let mut breaches = Vec::new();
        for (label, value, threshold, metric) in checks {
            if metric.observe(value, threshold) {
                breaches.push(Breach {
                    label,
                    value,
                    threshold,
                });
            }
        }
        breaches
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> AlertsConfig {
        AlertsConfig::default() // 90/90/90 per Task 1
    }

    #[test]
    fn fires_only_after_three_consecutive_scrapes_over() {
        let mut s = ThresholdState::default();
        assert!(s.observe(95.0, 10.0, 10.0, &cfg()).is_empty());
        assert!(s.observe(95.0, 10.0, 10.0, &cfg()).is_empty());
        let breaches = s.observe(95.0, 10.0, 10.0, &cfg());
        assert_eq!(breaches.len(), 1);
        assert_eq!(breaches[0].label, "CPU");
        assert_eq!(breaches[0].threshold, 90.0);
    }

    #[test]
    fn a_dip_below_threshold_resets_the_consecutive_count() {
        let mut s = ThresholdState::default();
        s.observe(95.0, 10.0, 10.0, &cfg());
        s.observe(95.0, 10.0, 10.0, &cfg());
        s.observe(50.0, 10.0, 10.0, &cfg()); // spike over, then back — no alert
        assert!(s.observe(95.0, 10.0, 10.0, &cfg()).is_empty());
        assert!(s.observe(95.0, 10.0, 10.0, &cfg()).is_empty());
        assert_eq!(s.observe(95.0, 10.0, 10.0, &cfg()).len(), 1);
    }

    #[test]
    fn one_alert_per_excursion_with_hysteresis_rearm() {
        let mut s = ThresholdState::default();
        for _ in 0..3 {
            s.observe(95.0, 10.0, 10.0, &cfg());
        }
        // Still over: no repeat.
        assert!(s.observe(99.0, 10.0, 10.0, &cfg()).is_empty());
        // Dips to 87 — below 90 but not below 85 (90 - HYSTERESIS): still armed-off.
        s.observe(87.0, 10.0, 10.0, &cfg());
        for _ in 0..2 {
            s.observe(95.0, 10.0, 10.0, &cfg());
        }
        assert!(
            s.observe(95.0, 10.0, 10.0, &cfg()).is_empty(),
            "hovering at the line must not re-alert"
        );
        // Falls to 80 — below 85: re-armed. Next sustained breach alerts again.
        s.observe(80.0, 10.0, 10.0, &cfg());
        for _ in 0..2 {
            s.observe(95.0, 10.0, 10.0, &cfg());
        }
        assert_eq!(s.observe(95.0, 10.0, 10.0, &cfg()).len(), 1);
    }

    #[test]
    fn zero_threshold_disables_that_metric() {
        let mut base = cfg();
        base.cpu_alert_pct = 0.0;
        let mut s = ThresholdState::default();
        for _ in 0..10 {
            assert!(s.observe(100.0, 10.0, 10.0, &base).is_empty());
        }
    }

    #[test]
    fn independent_metrics_fire_independently() {
        let mut s = ThresholdState::default();
        s.observe(95.0, 95.0, 10.0, &cfg());
        s.observe(95.0, 95.0, 10.0, &cfg());
        let breaches = s.observe(95.0, 95.0, 10.0, &cfg());
        let labels: Vec<_> = breaches.iter().map(|b| b.label).collect();
        assert_eq!(labels, vec!["CPU", "Memory"]);
    }
}
