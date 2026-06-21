//! auto_seimpersonate -- convert a credited `seimpersonate` primitive into a
//! real SYSTEM shell and chain a privilege-bearing follow-up.
//!
//! When a task's output captures `whoami /priv` showing `SeImpersonatePrivilege`
//! enabled (typically reached via MSSQL `xp_cmdshell` running as a service
//! account), `result_processing` publishes a `seimpersonate` vulnerability and
//! marks it exploited so the scoreboard credits the primitive. Historically the
//! comment there claimed "the follow-on potato dispatch is left for the existing
//! privesc agent to consume opportunistically" — but nothing ever consumed it:
//! `is_automation_owned_vuln` blocks the generic exploitation path from
//! dispatching `seimpersonate`, no automation read the credited token, and there
//! is no Rust-side potato executor. The net effect was a scoreboard tick with no
//! SYSTEM shell and no progress toward Domain Admin.
//!
//! This module closes that gap. It detects credited `seimpersonate` primitives
//! and dispatches a dedicated `privesc` task that re-establishes code execution
//! on the host, escalates SeImpersonate -> SYSTEM via a potato / PrintSpoofer,
//! and then chains a SYSTEM-context win (local SAM/LSA secrets, machine-account
//! RBCD, or coerce+relay of a signing-disabled DC).

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::automation::mssql_exploitation::find_mssql_credential;
use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// A SYSTEM-escalation follow-up for one host with a credited `seimpersonate`
/// primitive.
struct SeImpersonateWork {
    vuln_id: String,
    target_ip: String,
    host_label: String,
    hostname: String,
    domain: String,
    credential: ares_core::models::Credential,
}

/// Derive the domain from a fully-qualified hostname
/// (e.g. `sql01.contoso.local` -> `contoso.local`). Returns an empty string for
/// a bare hostname.
fn domain_from_hostname(hostname: &str) -> String {
    hostname
        .find('.')
        .map(|i| hostname[i + 1..].to_lowercase())
        .unwrap_or_default()
}

/// Collect SYSTEM-escalation work items from state (pure logic, no async).
///
/// A `seimpersonate` vulnerability is actionable when it has been credited
/// (present in `exploited_vulnerabilities`), we can resolve a target IP, we
/// don't already have admin on that host (an existing secretsdump means SYSTEM
/// is moot), and we hold a usable credential to re-establish code execution.
fn collect_seimpersonate_work(state: &StateInner) -> Vec<SeImpersonateWork> {
    state
        .discovered_vulnerabilities
        .values()
        .filter_map(|vuln| {
            if vuln.vuln_type != "seimpersonate" {
                return None;
            }
            // Only act once the primitive is actually credited.
            if !state.exploited_vulnerabilities.contains(&vuln.vuln_id) {
                return None;
            }
            // One escalation attempt per host.
            if state.is_processed(DEDUP_SEIMPERSONATE, &vuln.vuln_id) {
                return None;
            }

            // Resolve the target IP from details first, then the vuln target.
            let target_ip = vuln
                .details
                .get("target_ip")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .or_else(|| {
                    Some(vuln.target.clone()).filter(|t| !t.is_empty() && t.contains('.'))
                })?;

            // Already own this host via admin/secretsdump -> SYSTEM is redundant.
            // Every DEDUP_SECRETSDUMP key is composite (`{ip}:{domain}:{user}`,
            // `{ip}:{domain}:pth_admin`, `{ip}:{domain}:krbtgt_extraction_*`), so
            // a bare-IP exact match never fires — probe by the `{ip}:` prefix.
            if state.has_processed_prefix(DEDUP_SECRETSDUMP, &format!("{target_ip}:")) {
                return None;
            }

            let host_label = vuln
                .details
                .get("host")
                .and_then(|v| v.as_str())
                .unwrap_or(&target_ip)
                .to_string();

            // Recover hostname/domain from the matching host record when present.
            let host = state.hosts.iter().find(|h| h.ip == target_ip);
            let hostname = host.map(|h| h.hostname.clone()).unwrap_or_default();
            let domain = domain_from_hostname(&hostname);

            // Need a credential to reconnect and re-arm xp_cmdshell.
            let credential = find_mssql_credential(state, &domain)?;

            Some(SeImpersonateWork {
                vuln_id: vuln.vuln_id.clone(),
                target_ip,
                host_label,
                hostname,
                domain,
                credential,
            })
        })
        .collect()
}

/// The objective wishlist embedded in every SeImpersonate escalation payload.
/// Held as a function so the payload builder can be tested without recopying the
/// string array.
fn seimpersonate_objectives() -> Vec<&'static str> {
    vec![
        "GOAL: turn the already-confirmed SeImpersonatePrivilege on this host into NT AUTHORITY\\SYSTEM, then convert SYSTEM into a domain-privilege win. The privilege is already proven held — do NOT re-run whoami /priv to re-observe it; act on it.",
        "1. Re-establish code execution: connect to the host's MSSQL instance with the supplied credential, EXECUTE AS the impersonatable sysadmin login if needed, and re-enable xp_cmdshell. (This is how the SeImpersonate context was reached originally.)",
        "2. Escalate to SYSTEM via the SeImpersonate primitive: stage and run a potato (GodPotato / PrintSpoofer / SweetPotato) through xp_cmdshell. Confirm with `whoami` returning `nt authority\\system`. Call task_complete with that proof if no further chaining is possible in this task.",
        "3. From SYSTEM, capture domain-usable secrets: dump the local SAM + LSA secrets (impacket-secretsdump local / reg save SAM+SYSTEM+SECURITY). Any machine-account hash, cached domain credential, or local admin hash published by the parser is a win -> call task_complete.",
        "4. If this host is a domain member (not a DC), use the SYSTEM/machine-account context to pivot toward a DC: trigger RBCD with the machine account, or coerce the machine and relay to a DC that has SMB signing disabled. First confirmed DC hash / DCSync output -> call task_complete.",
        "STOP CONDITION: call task_complete as soon as ANY of these landed: (a) SYSTEM shell proven, (b) local SAM/LSA secrets dumped, (c) a DC hash captured. If the potato fails to land SYSTEM after a couple of attempts, call task_complete describing exactly what failed (binary blocked, no writable path, AV) so the orchestrator can route an alternative.",
    ]
}

/// Build the JSON payload submitted to the `exploit` queue for a SeImpersonate
/// escalation work item.
fn build_seimpersonate_payload(item: &SeImpersonateWork) -> serde_json::Value {
    json!({
        "technique": "seimpersonate_escalation",
        "vuln_type": "seimpersonate",
        "vuln_id": item.vuln_id,
        "target_ip": item.target_ip,
        "hostname": item.hostname,
        "domain": item.domain,
        "host": item.host_label,
        "credential": {
            "username": item.credential.username,
            "password": item.credential.password,
            "domain": item.credential.domain,
        },
        "objectives": seimpersonate_objectives(),
    })
}

/// Monitors for credited `seimpersonate` primitives and dispatches a SYSTEM
/// escalation + privilege-bearing follow-up for each. Interval: 45s.
pub async fn auto_seimpersonate(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(Duration::from_secs(45));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        if !dispatcher.is_technique_allowed("seimpersonate") {
            continue;
        }

        let work: Vec<SeImpersonateWork> = {
            let state = dispatcher.state.read().await;
            collect_seimpersonate_work(&state)
        };

        for item in work {
            let payload = build_seimpersonate_payload(&item);
            let priority = dispatcher.effective_priority("seimpersonate");
            match dispatcher
                .throttled_submit("exploit", "privesc", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        target = %item.target_ip,
                        host = %item.host_label,
                        "SeImpersonate -> SYSTEM escalation dispatched"
                    );

                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_SEIMPERSONATE, item.vuln_id.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_SEIMPERSONATE, &item.vuln_id)
                        .await;
                }
                Ok(None) => {
                    debug!(target = %item.target_ip, "SeImpersonate escalation task deferred");
                }
                Err(e) => {
                    warn!(err = %e, target = %item.target_ip, "Failed to dispatch SeImpersonate escalation");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ares_core::models::{Credential, Host, VulnerabilityInfo};
    use std::collections::HashMap;

    fn make_cred(username: &str, domain: &str) -> Credential {
        Credential {
            id: uuid::Uuid::new_v4().to_string(),
            username: username.to_string(),
            password: "P@ssw0rd!".to_string(), // pragma: allowlist secret
            domain: domain.to_string(),
            source: String::new(),
            is_admin: false,
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
        }
    }

    fn make_host(ip: &str, hostname: &str) -> Host {
        Host {
            ip: ip.to_string(),
            hostname: hostname.to_string(),
            os: String::new(),
            roles: Vec::new(),
            services: Vec::new(),
            is_dc: false,
            owned: false,
        }
    }

    fn seimpersonate_vuln(ip: &str, host_label: &str) -> VulnerabilityInfo {
        let mut details = HashMap::new();
        details.insert("host".into(), serde_json::Value::String(host_label.into()));
        details.insert("target_ip".into(), serde_json::Value::String(ip.into()));
        VulnerabilityInfo {
            vuln_id: format!("seimpersonate_{host_label}"),
            vuln_type: "seimpersonate".to_string(),
            target: ip.to_string(),
            discovered_by: "result_processing".to_string(),
            discovered_at: chrono::Utc::now(),
            details,
            recommended_agent: "privesc".to_string(),
            priority: 2,
        }
    }

    /// Insert a credited seimpersonate vuln plus a usable credential and host.
    fn primed_state() -> StateInner {
        let mut state = StateInner::new("test".into());
        let vuln = seimpersonate_vuln("192.168.58.20", "sql01");
        state.exploited_vulnerabilities.insert(vuln.vuln_id.clone());
        state
            .discovered_vulnerabilities
            .insert(vuln.vuln_id.clone(), vuln);
        state
            .hosts
            .push(make_host("192.168.58.20", "sql01.contoso.local"));
        state.credentials.push(make_cred("alice", "contoso.local"));
        state
    }

    #[test]
    fn domain_from_hostname_extracts_suffix() {
        assert_eq!(domain_from_hostname("sql01.contoso.local"), "contoso.local");
        assert_eq!(domain_from_hostname("SQL01.CONTOSO.LOCAL"), "contoso.local");
        assert_eq!(domain_from_hostname("sql01"), "");
    }

    #[test]
    fn collect_empty_state_produces_no_work() {
        let state = StateInner::new("test".into());
        assert!(collect_seimpersonate_work(&state).is_empty());
    }

    #[test]
    fn collect_credited_primitive_produces_work() {
        let state = primed_state();
        let work = collect_seimpersonate_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].target_ip, "192.168.58.20");
        assert_eq!(work[0].host_label, "sql01");
        assert_eq!(work[0].hostname, "sql01.contoso.local");
        assert_eq!(work[0].domain, "contoso.local");
        assert_eq!(work[0].credential.username, "alice");
        assert_eq!(work[0].vuln_id, "seimpersonate_sql01");
    }

    #[test]
    fn collect_skips_uncredited_primitive() {
        // Discovered but not yet in exploited_vulnerabilities -> not actionable.
        let mut state = primed_state();
        state.exploited_vulnerabilities.clear();
        assert!(collect_seimpersonate_work(&state).is_empty());
    }

    #[test]
    fn collect_skips_already_dispatched() {
        let mut state = primed_state();
        state.mark_processed(DEDUP_SEIMPERSONATE, "seimpersonate_sql01".into());
        assert!(collect_seimpersonate_work(&state).is_empty());
    }

    #[test]
    fn collect_skips_host_we_already_own() {
        // Existing secretsdump on the host means SYSTEM is redundant. Production
        // writers use composite `{ip}:{domain}:{user}` keys (never a bare IP),
        // so the guard must match on the `{ip}:` prefix.
        let mut state = primed_state();
        state.mark_processed(
            DEDUP_SECRETSDUMP,
            "192.168.58.20:contoso.local:administrator".into(),
        );
        assert!(collect_seimpersonate_work(&state).is_empty());
    }

    #[test]
    fn collect_not_suppressed_by_other_host_secretsdump() {
        // A secretsdump on a *different* host must not suppress this one.
        let mut state = primed_state();
        state.mark_processed(
            DEDUP_SECRETSDUMP,
            "192.168.58.99:contoso.local:administrator".into(),
        );
        assert_eq!(collect_seimpersonate_work(&state).len(), 1);
    }

    #[test]
    fn collect_requires_a_credential() {
        let mut state = primed_state();
        state.credentials.clear();
        assert!(collect_seimpersonate_work(&state).is_empty());
    }

    #[test]
    fn collect_ignores_non_seimpersonate_vulns() {
        let mut state = primed_state();
        // Flip the vuln type but keep it credited; should be ignored.
        for v in state.discovered_vulnerabilities.values_mut() {
            v.vuln_type = "esc1".into();
        }
        assert!(collect_seimpersonate_work(&state).is_empty());
    }

    #[test]
    fn collect_falls_back_to_vuln_target_when_details_missing_ip() {
        let mut state = StateInner::new("test".into());
        let mut vuln = seimpersonate_vuln("192.168.58.21", "sql02");
        vuln.details.remove("target_ip");
        state.exploited_vulnerabilities.insert(vuln.vuln_id.clone());
        state
            .discovered_vulnerabilities
            .insert(vuln.vuln_id.clone(), vuln);
        state.credentials.push(make_cred("bob", "contoso.local"));
        let work = collect_seimpersonate_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].target_ip, "192.168.58.21");
        // No matching host record -> empty hostname/domain, still dispatchable.
        assert_eq!(work[0].hostname, "");
        assert_eq!(work[0].domain, "");
    }

    #[test]
    fn payload_structure_is_well_formed() {
        let work = &collect_seimpersonate_work(&primed_state())[0..1][0];
        let payload = build_seimpersonate_payload(work);
        assert_eq!(payload["technique"], "seimpersonate_escalation");
        assert_eq!(payload["vuln_type"], "seimpersonate");
        assert_eq!(payload["target_ip"], "192.168.58.20");
        assert_eq!(payload["host"], "sql01");
        assert_eq!(payload["domain"], "contoso.local");
        assert_eq!(payload["credential"]["username"], "alice");
        assert!(payload["objectives"].is_array());
        assert!(!payload["objectives"].as_array().unwrap().is_empty());
    }
}
