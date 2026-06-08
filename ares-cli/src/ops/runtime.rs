use anyhow::{Context, Result};
use chrono::Utc;
use tracing::warn;

use ares_core::models::Hash;
use ares_core::state::RedisStateReader;

use crate::redis_conn::{connect_redis, resolve_operation_id};
use crate::util::{format_duration, format_number};

/// Per-bucket totals derived from `state.all_hashes`.
///
/// The raw count alone is misleading: a single DCSync against a medium AD
/// forest dumps thousands of rows (every user, every machine account, every
/// trust account, plus a kerberoast/AS-REP pass) — but only a small subset
/// is directly auth-usable. Showing a single `Hashes: N` number lets a
/// kerberoast-heavy op look as "loaded" as one with a real DA dump. Bucket
/// the count so the operator sees what they actually have.
#[derive(Default)]
struct HashBuckets {
    ntlm_user: usize,
    machine_account: usize,
    trust_key: usize,
    kerberoast_tgs: usize,
    asrep_tgt: usize,
    other: usize,
}

impl HashBuckets {
    fn total(&self) -> usize {
        self.ntlm_user
            + self.machine_account
            + self.trust_key
            + self.kerberoast_tgs
            + self.asrep_tgt
            + self.other
    }
}

fn classify_hashes(hashes: &[Hash]) -> HashBuckets {
    let mut b = HashBuckets::default();
    for h in hashes {
        let hash_type = h.hash_type.trim().to_ascii_lowercase();
        let value = h.hash_value.as_str();

        let is_asrep = matches!(
            hash_type.as_str(),
            "asrep" | "as-rep" | "krb5asrep" | "asreproast"
        ) || value.starts_with("$krb5asrep$");
        if is_asrep {
            b.asrep_tgt += 1;
            continue;
        }

        let is_kerberoast = matches!(
            hash_type.as_str(),
            "kerberoast" | "krb5tgs" | "tgs-rep" | "tgs"
        ) || value.starts_with("$krb5tgs$");
        if is_kerberoast {
            b.kerberoast_tgs += 1;
            continue;
        }

        // Trust keys are `$`-suffixed too — check before machine_account so
        // a trust hash isn't miscounted as a plain machine account.
        if h.is_trust_key {
            b.trust_key += 1;
            continue;
        }

        if h.username.trim_end().ends_with('$') {
            b.machine_account += 1;
            continue;
        }

        // Everything left is directly auth-usable NTLM (or AES, treated the
        // same here — the resolver picks AES over RC4 when injecting).
        // Empty hash_type defaults to NTLM at ingest time, so untyped rows
        // land here too.
        if hash_type.is_empty()
            || matches!(
                hash_type.as_str(),
                "ntlm" | "nt" | "lm" | "aes" | "aes128" | "aes256"
            )
        {
            b.ntlm_user += 1;
        } else {
            b.other += 1;
        }
    }
    b
}

pub(crate) async fn ops_runtime(
    redis_url: Option<String>,
    operation_id: Option<String>,
    latest: bool,
    watch: u64,
) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;
    let op_id = resolve_operation_id(&mut conn, operation_id, latest).await?;

    if watch > 0 {
        runtime_watch(&mut conn, &op_id, watch).await
    } else {
        print_runtime_snapshot(&mut conn, &op_id).await
    }
}

async fn runtime_watch(
    conn: &mut redis::aio::MultiplexedConnection,
    op_id: &str,
    interval: u64,
) -> Result<()> {
    let mut first = true;
    loop {
        if !first {
            println!("\n{}", "=".repeat(60));
        }
        let ts = Utc::now().format("%Y-%m-%d %H:%M:%S UTC");
        println!("[watch] Refreshing every {interval}s  |  {ts}");
        println!("{}", "=".repeat(60));
        first = false;

        if let Err(e) = print_runtime_snapshot(conn, op_id).await {
            warn!("Runtime snapshot failed: {e}");
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(interval)).await;
    }
}

async fn print_runtime_snapshot(
    conn: &mut redis::aio::MultiplexedConnection,
    op_id: &str,
) -> Result<()> {
    let reader = RedisStateReader::new(op_id.to_string());
    let state = reader
        .load_state(conn)
        .await?
        .with_context(|| format!("No state found for operation: {op_id}"))?;

    let is_running = reader.is_running(conn).await?;
    let now = Utc::now();

    let (runtime_seconds, status) = if let Some(completed) = state.completed_at {
        (
            (completed - state.started_at).num_seconds().max(0) as u64,
            "completed",
        )
    } else if is_running {
        (
            (now - state.started_at).num_seconds().max(0) as u64,
            "running",
        )
    } else {
        (
            (now - state.started_at).num_seconds().max(0) as u64,
            "stopped",
        )
    };

    println!("Operation: {op_id}");
    println!("Status:    {status}");
    println!("Started:   {}", state.started_at.to_rfc3339());
    println!("Runtime:   {}", format_duration(runtime_seconds));
    println!();

    let creds = state.all_credentials.len();
    let buckets = classify_hashes(&state.all_hashes);
    let hashes_total = buckets.total();

    // Mirror the loot view's split (display.rs:EXPLOITABLE_PRIORITY_MAX): the
    // raw map mixes a handful of real exploit primitives in with hundreds of
    // BloodHound ACL edges, so a single "discovered" count is alarmist noise.
    let (exploitable_ids, findings_count): (Vec<&String>, usize) = {
        let mut ids = Vec::new();
        let mut findings = 0usize;
        for (id, vuln) in &state.discovered_vulnerabilities {
            if vuln.priority <= super::loot::EXPLOITABLE_PRIORITY_MAX {
                ids.push(id);
            } else {
                findings += 1;
            }
        }
        (ids, findings)
    };
    let exploited = exploitable_ids
        .iter()
        .filter(|id| state.exploited_vulnerabilities.contains(**id))
        .count();
    let exploitable = exploitable_ids.len();

    println!("Credentials: {creds}");
    println!("Hashes:      {hashes_total} total");
    if hashes_total > 0 {
        // Only show non-zero buckets — empty rows are visual noise and the
        // common case (e.g. no kerberoast pass yet) shouldn't push real
        // counts down the screen.
        let rows: &[(&str, usize)] = &[
            ("NTLM (auth-usable)", buckets.ntlm_user),
            ("Machine accounts", buckets.machine_account),
            ("Trust keys", buckets.trust_key),
            ("Kerberoast TGS", buckets.kerberoast_tgs),
            ("AS-REP TGT", buckets.asrep_tgt),
            ("Other", buckets.other),
        ];
        for (label, count) in rows {
            if *count > 0 {
                println!("  {label:<19} {count}");
            }
        }
    }
    println!("Vulns: {exploitable} exploitable ({exploited} exploited), {findings_count} findings");
    println!();

    super::loot::print_runtime_summary(&state);

    // Token usage & estimated cost (from Redis counters set by workers)
    match ares_core::token_usage::get_token_usage(conn, op_id).await {
        Ok(Some(usage)) if usage.input_tokens > 0 || usage.output_tokens > 0 => {
            let in_tok = usage.input_tokens;
            let out_tok = usage.output_tokens;
            let total_tok = in_tok + out_tok;

            println!(
                "\nTokens: {} (in: {}  out: {})",
                format_number(total_tok),
                format_number(in_tok),
                format_number(out_tok)
            );

            if !usage.models.is_empty() {
                let mut model_names: Vec<_> = usage.models.keys().collect();
                model_names.sort();
                let label = if model_names.len() > 1 {
                    "Models"
                } else {
                    "Model"
                };
                println!(
                    "{label}:  {}",
                    model_names
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                );

                let (total_cost, breakdown, unpriced) =
                    ares_core::token_usage::estimate_usage_cost(&usage);

                if let Some(cost) = total_cost {
                    let suffix = if breakdown.len() > 1 {
                        " (blended)"
                    } else {
                        ""
                    };
                    println!("Cost:   ${cost:.4}{suffix}");
                } else if !usage.model.is_empty() {
                    println!("Cost:   unavailable");
                }

                // Per-model breakdown for multi-model operations
                if breakdown.len() > 1 {
                    for item in &breakdown {
                        println!(
                            "  - {}: {} tokens (${:.4})",
                            item.model, item.total_tokens, item.cost
                        );
                    }
                }

                if !unpriced.is_empty() {
                    println!("Unpriced models: {}", unpriced.join(", "));
                }
            }
        }
        _ => {}
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash_row(user: &str, hash_type: &str, value: &str) -> Hash {
        Hash {
            id: format!("h-{user}-{hash_type}"),
            username: user.to_string(),
            hash_value: value.to_string(),
            hash_type: hash_type.to_string(),
            domain: "contoso.local".to_string(),
            cracked_password: None,
            source: "test".into(),
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
            aes_key: None,
            is_previous: false,
            source_host: None,
            is_trust_key: false,
            trust_pair_label: None,
        }
    }

    #[test]
    fn classify_buckets_real_inflation_repro() {
        // The pathological op that lit this up: a handful of human creds
        // alongside a forest-wide DCSync (every user + every machine
        // account) plus a kerberoast pass. The raw count overstates auth
        // material by ~95%; the bucket breakdown shows where it went.
        let mut hashes = Vec::new();
        for i in 0..400 {
            hashes.push(hash_row(&format!("user{i}"), "NTLM", "deadbeef"));
        }
        for i in 0..500 {
            hashes.push(hash_row(&format!("host{i}$"), "NTLM", "cafef00d"));
        }
        for i in 0..1800 {
            hashes.push(hash_row(
                &format!("svc{i}"),
                "kerberoast",
                "$krb5tgs$23$*svc$REALM$cifs/host.realm*$abc",
            ));
        }
        for i in 0..20 {
            hashes.push(hash_row(
                &format!("asrep{i}"),
                "asrep",
                "$krb5asrep$23$user@REALM:abc$def",
            ));
        }

        let b = classify_hashes(&hashes);
        assert_eq!(b.ntlm_user, 400);
        assert_eq!(b.machine_account, 500);
        assert_eq!(b.kerberoast_tgs, 1800);
        assert_eq!(b.asrep_tgt, 20);
        assert_eq!(b.total(), 2720);
    }

    #[test]
    fn classify_kerberoast_detected_by_value_prefix_when_type_missing() {
        // Some ingestion paths leave hash_type empty / "unknown". The
        // value prefix is the load-bearing signal — don't let an untyped
        // TGS slip into the NTLM auth-usable bucket.
        let hashes = vec![hash_row("svc", "", "$krb5tgs$23$*svc$REALM$cifs/x*$abc")];
        let b = classify_hashes(&hashes);
        assert_eq!(b.kerberoast_tgs, 1);
        assert_eq!(b.ntlm_user, 0);
    }

    #[test]
    fn classify_trust_key_not_counted_as_machine_account() {
        // Trust accounts are `$`-suffixed but operationally distinct —
        // they're forging material, not random machine creds. Order in
        // classify_hashes matters; this pins it.
        let mut h = hash_row("FABRIKAM$", "NTLM", "deadbeef");
        h.is_trust_key = true;
        let b = classify_hashes(&[h]);
        assert_eq!(b.trust_key, 1);
        assert_eq!(b.machine_account, 0);
    }

    #[test]
    fn classify_empty_returns_all_zeros() {
        let b = classify_hashes(&[]);
        assert_eq!(b.total(), 0);
    }
}
