//! Blue-team operational mode.
//!
//! `BlueMode` is read from the `ARES_BLUE_MODE` env var at orchestrator
//! startup and threaded through the completion loop. It replaces the old
//! `ARES_BLUE_ENABLED` boolean, which conflated two independent choices
//! ("run blue at all" and "have red wait on blue at completion").

use std::fmt;
use std::str::FromStr;

/// How blue interacts with the red operation lifecycle.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum BlueMode {
    /// No blue at all. Red completes solo, no snapshot is captured.
    Off,
    /// Red completes solo. A snapshot is captured after red drains
    /// (typically fired by the launcher as a background job that waits
    /// for Loki flush); blue runs later against the snapshot via
    /// `benchmark:replay:{run,loop}`. This is the default.
    Replay,
    /// Legacy joint-run: blue orchestrator spawns in-process alongside
    /// red, and the red completion loop waits up to 45 minutes for blue
    /// investigations to drain before releasing. Sets
    /// `red_blocked_on_blue` in the op meta if the wait triggered.
    Live,
}

impl BlueMode {
    /// True only for `Live`. Convenience for feature-gated call sites that
    /// need "should red wait for blue?" as a boolean.
    pub fn is_live(self) -> bool {
        matches!(self, BlueMode::Live)
    }

    /// Read from the process environment, defaulting to `Replay` when the
    /// var is unset. Unrecognized values also fall back to `Replay` — this
    /// matches the "red should keep running" bias; an operator who wanted
    /// live mode would notice the missing behavior immediately.
    pub fn from_env() -> Self {
        std::env::var("ARES_BLUE_MODE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(BlueMode::Replay)
    }
}

impl fmt::Display for BlueMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            BlueMode::Off => "off",
            BlueMode::Replay => "replay",
            BlueMode::Live => "live",
        };
        f.write_str(s)
    }
}

impl FromStr for BlueMode {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" | "0" | "false" | "no" | "" => Ok(BlueMode::Off),
            "replay" => Ok(BlueMode::Replay),
            "live" | "1" | "true" | "yes" => Ok(BlueMode::Live),
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_canonical() {
        assert_eq!("off".parse::<BlueMode>().unwrap(), BlueMode::Off);
        assert_eq!("replay".parse::<BlueMode>().unwrap(), BlueMode::Replay);
        assert_eq!("live".parse::<BlueMode>().unwrap(), BlueMode::Live);
    }

    #[test]
    fn parse_legacy_bool() {
        assert_eq!("0".parse::<BlueMode>().unwrap(), BlueMode::Off);
        assert_eq!("1".parse::<BlueMode>().unwrap(), BlueMode::Live);
        assert_eq!("true".parse::<BlueMode>().unwrap(), BlueMode::Live);
        assert_eq!("false".parse::<BlueMode>().unwrap(), BlueMode::Off);
    }

    #[test]
    fn parse_unknown_errors() {
        assert!("nope".parse::<BlueMode>().is_err());
    }

    #[test]
    fn display_round_trip() {
        for m in [BlueMode::Off, BlueMode::Replay, BlueMode::Live] {
            assert_eq!(m.to_string().parse::<BlueMode>().unwrap(), m);
        }
    }

    #[test]
    fn is_live_only_for_live() {
        assert!(!BlueMode::Off.is_live());
        assert!(!BlueMode::Replay.is_live());
        assert!(BlueMode::Live.is_live());
    }
}
