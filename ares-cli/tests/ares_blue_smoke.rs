//! Smoke tests for the `ares-blue` binary.
//!
//! `ares-blue` intentionally exposes only the blue-team subcommand
//! surface — every red-team subcommand must be rejected at dispatch
//! time. These tests spawn the compiled binary directly so a broken
//! module mount or an accidental subcommand allow-through fails the
//! test suite instead of silently allowing a mis-invocation.
//!
//! The binary path is provided by Cargo as `CARGO_BIN_EXE_ares-blue`
//! at test build time — no manual path fixup, no PATH pollution.

use std::process::Command;

fn ares_blue() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ares-blue"))
}

#[test]
fn top_level_help_succeeds() {
    // `--help` writes to stdout and exits 0; confirms clap parsed the
    // subcommand tree without a schema conflict from the `#[path]`
    // module mounts.
    let out = ares_blue().arg("--help").output().expect("spawn");
    assert!(
        out.status.success(),
        "--help exited with {:?} stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("blue") && stdout.contains("benchmark") && stdout.contains("worker"),
        "help must list the blue-team subcommand surface"
    );
}

#[test]
fn orchestrator_subcommand_is_refused() {
    // Red-only subcommand — dispatcher must reject with a non-zero exit
    // and a message that names the correct binary to use.
    let out = ares_blue().arg("orchestrator").output().expect("spawn");
    assert!(
        !out.status.success(),
        "orchestrator must not succeed on ares-blue"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("blue-team subcommand surface"),
        "reject message must name the blue-team surface (got: {combined:?})"
    );
}

#[test]
fn worker_without_blue_mode_env_is_refused() {
    // `worker` is only allowed under `ARES_WORKER_MODE=blue_task` — an
    // unset or wrong-mode invocation must exit non-zero with the
    // env-var name in the error so the operator sees exactly what to
    // set.
    let out = ares_blue()
        .arg("worker")
        // Force the env unset regardless of the test-runner env.
        .env_remove("ARES_WORKER_MODE")
        .output()
        .expect("spawn");
    assert!(
        !out.status.success(),
        "worker without blue mode must exit non-zero"
    );
    // The error path writes to stderr via eprintln because telemetry
    // isn't initialised for `worker` subcommands.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("ARES_WORKER_MODE=blue_task"),
        "stderr must name the required env var (got: {stderr:?})"
    );
}

#[test]
fn worker_with_wrong_mode_env_is_refused() {
    // Same-shape check for a red-team mode value — must fail even when
    // the env var IS set but to the wrong value.
    let out = ares_blue()
        .arg("worker")
        .env("ARES_WORKER_MODE", "task")
        .output()
        .expect("spawn");
    assert!(
        !out.status.success(),
        "worker with wrong mode must exit non-zero"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("blue_task"),
        "stderr must name the required mode value (got: {stderr:?})"
    );
}

#[test]
fn ops_subcommand_is_refused() {
    // `ops` is red-side scoreboard/loot access — refuse on ares-blue
    // regardless of args.
    let out = ares_blue().arg("ops").arg("list").output().expect("spawn");
    assert!(!out.status.success(), "ops must not succeed on ares-blue");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("main `ares` binary"),
        "reject message must point at the red binary (got: {combined:?})"
    );
}
