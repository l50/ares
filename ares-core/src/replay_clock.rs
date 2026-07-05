//! Virtual replay clock for deterministic benchmark replay.
//!
//! During a benchmark replay the captured logs/alerts are historical, but the
//! blue-team agent must reason in *attack time*. [`replay_now`] returns the
//! replay anchor (the first fired alert's timestamp, supplied via the
//! `ARES_REPLAY_CLOCK_START` env var) instead of wall-clock now, so that
//! "recent"/relative-window queries land on the attack rather than the present.
//!
//! When `ARES_REPLAY_CLOCK_START` is unset (a live investigation, not a
//! replay), [`replay_now`] is exactly [`Utc::now`] and [`is_replay`] is false.
//!
//! Lives in `ares-core` so `ares-tools` (the query tools) and `ares-llm` (the
//! prompt builder) share one clock source instead of re-implementing the parse.

use std::sync::atomic::{AtomicI64, Ordering};

use chrono::{DateTime, Utc};

/// Env var carrying the replay-clock anchor as an RFC3339 timestamp. The
/// benchmark replay runner sets it to the first fired alert's `fired_at`.
pub const REPLAY_CLOCK_ENV: &str = "ARES_REPLAY_CLOCK_START";

/// Sentinel for "no programmatic override set".
const UNSET: i64 = i64::MIN;

/// Optional programmatic override (tests / replay drivers). While `UNSET` the
/// anchor is resolved from [`REPLAY_CLOCK_ENV`] instead.
static OVERRIDE_NANOS: AtomicI64 = AtomicI64::new(UNSET);

fn nanos_to_dt(ns: i64) -> DateTime<Utc> {
    let secs = ns.div_euclid(1_000_000_000);
    let sub = ns.rem_euclid(1_000_000_000) as u32;
    DateTime::from_timestamp(secs, sub).unwrap_or_else(Utc::now)
}

/// Resolve the replay anchor. A programmatic override (via [`set_replay_clock`])
/// wins; otherwise the env var is read *fresh on every call* so a process reused
/// across replay investigations always reflects the current anchor — there is
/// deliberately no env-value cache to go stale. Returns `None` for a live
/// investigation (no override and the env var unset/unparsable).
fn anchor() -> Option<DateTime<Utc>> {
    let ov = OVERRIDE_NANOS.load(Ordering::Relaxed);
    if ov != UNSET {
        return Some(nanos_to_dt(ov));
    }
    let raw = std::env::var(REPLAY_CLOCK_ENV).ok()?;
    DateTime::parse_from_rfc3339(raw.trim())
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

/// The current instant on the replay clock: the replay anchor when a replay is
/// active, otherwise wall-clock [`Utc::now`].
pub fn replay_now() -> DateTime<Utc> {
    anchor().unwrap_or_else(Utc::now)
}

/// Whether a replay clock anchor is configured (i.e. this is a replay run).
pub fn is_replay() -> bool {
    anchor().is_some()
}

/// Explicitly set the replay anchor, overriding the env var (mainly for tests
/// and programmatic replay drivers). Pair with [`reset_replay_clock`] so the
/// override does not leak into unrelated code paths (e.g. other tests sharing
/// the same process).
pub fn set_replay_clock(anchor: DateTime<Utc>) {
    if let Some(ns) = anchor.timestamp_nanos_opt() {
        OVERRIDE_NANOS.store(ns, Ordering::Relaxed);
    }
}

/// Clear a programmatic override set by [`set_replay_clock`], restoring
/// env-var-driven behavior. Idempotent.
pub fn reset_replay_clock() {
    OVERRIDE_NANOS.store(UNSET, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_and_read_roundtrips() {
        let anchor = DateTime::parse_from_rfc3339("2026-06-30T22:20:23Z")
            .unwrap()
            .with_timezone(&Utc);
        set_replay_clock(anchor);
        assert!(is_replay());
        assert_eq!(replay_now(), anchor);
        // Do not leak the override into other tests sharing this process.
        reset_replay_clock();
    }
}
