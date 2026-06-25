//! Validate `domain` arguments on outgoing LLM tool calls.
//!
//! The LLM occasionally fat-fingers domain names in tool arguments
//! (e.g. `child.contossso.local` instead of `child.contoso.local`).
//! Tools accept the typo silently, then auth fails, credential lineage breaks,
//! and downstream consumers (cross-forest forge, ADCS enum, credential_resolver)
//! get misdirected. The publishing-side guard already keeps these typos out of
//! `state.domains`, but the typo'd value still rides on credential records and
//! pollutes per-credential routing.
//!
//! This module rejects tool calls whose `domain` argument doesn't match any
//! domain that authoritative recon has discovered. The LLM gets a synchronous
//! error listing valid domains and retries with the right spelling.

use tracing::warn;

use ares_core::state::RedisStateReader;
use ares_llm::{ToolCall, ToolExecResult};

use crate::orchestrator::task_queue::TaskQueue;
use crate::worker::credential_resolver::requires_exact_realm;

/// Inspect a tool call's `domain` argument; return a synthetic error result
/// if it looks like a hallucinated FQDN. Returns `None` to allow the call.
///
/// Allow rules:
/// - No `domain` arg, or empty → allow.
/// - Domain has no dot (workgroup-style label like `WORKGROUP`) → allow.
/// - Domain matches `state.domains` ∪ DC-map keys ∪ trusted-domain keys
///   (case-insensitive) → allow.
/// - Known-domain set is empty (early in the op, no recon yet) → allow.
///
/// Otherwise: reject with an error listing the known domains.
pub(super) async fn check_domain_arg(
    queue: &TaskQueue,
    operation_id: &str,
    call: &ToolCall,
) -> Option<ToolExecResult> {
    let supplied = call.arguments.get("domain").and_then(|v| v.as_str())?;
    let supplied = supplied.trim();
    if supplied.is_empty() || !supplied.contains('.') {
        return None;
    }
    let supplied_lc = supplied.to_lowercase();

    let mut conn = queue.connection();
    let reader = RedisStateReader::new(operation_id.to_string());

    let domains = reader.get_domains(&mut conn).await.unwrap_or_default();
    let dc_keys: Vec<String> = reader
        .get_dc_map(&mut conn)
        .await
        .unwrap_or_default()
        .into_keys()
        .collect();
    let trusted: Vec<String> = reader
        .get_trusted_domains(&mut conn)
        .await
        .unwrap_or_default()
        .into_keys()
        .collect();

    let mut known: Vec<String> = domains
        .into_iter()
        .chain(dc_keys)
        .chain(trusted)
        .map(|d| d.to_lowercase())
        .collect();
    known.sort();
    known.dedup();

    if known.is_empty() {
        return None;
    }
    if known.iter().any(|d| d == &supplied_lc) {
        return None;
    }

    // Also consult cred/hash records: their `domain` field may legitimately
    // carry NetBIOS-style or freshly-discovered values that haven't yet been
    // promoted into the canonical domains set. Only reject if the supplied
    // value is foreign to every channel.
    if let Ok(creds) = reader.get_credentials(&mut conn).await {
        if creds
            .iter()
            .any(|c| c.domain.eq_ignore_ascii_case(supplied))
        {
            return None;
        }
    }

    warn!(
        tool = %call.name,
        supplied = %supplied,
        known = ?known,
        "Rejecting tool call: domain argument not in known domains"
    );

    let suggestion = closest_match(&supplied_lc, &known);
    let message = match suggestion {
        Some(s) => format!(
            "Unknown domain '{}'. Known domains: [{}]. Did you mean '{}'?",
            supplied,
            known.join(", "),
            s
        ),
        None => format!(
            "Unknown domain '{}'. Known domains: [{}]. Use one of these exactly, or call a recon tool first to discover the correct FQDN.",
            supplied,
            known.join(", ")
        ),
    };

    Some(ToolExecResult {
        output: String::new(),
        error: Some(message),
        discoveries: None,
    })
}

/// Reject authenticated exact-realm tool calls aimed at a domain we have no
/// way to authenticate to. The LDAP simple-bind enumeration/modify and
/// kerberoast tools in [`requires_exact_realm`] need a principal *in the
/// target realm* — the credential resolver deliberately refuses cross-realm
/// fallback for them (realm-strict), so when the only owned creds belong to an
/// unrelated forest (e.g. `alice`@child.contoso.local fired at the
/// fabrikam.local DC) the tool runs unauthenticated, returns LDAP `0x52e`,
/// and the task gets requeued — a pure cycle-waster that recurs every round.
///
/// Fires only when ALL hold, to avoid false positives:
/// - the tool is in the exact-realm set, minus `enumerate_domain_trusts`
///   (the trust *discovery* escape hatch is never blocked),
/// - we already own at least one credential/hash (past initial foothold; an
///   empty-state op may still want unauthenticated/null-session attempts),
/// - no owned principal's realm is in the same forest tree as the target
///   (shared DNS suffix ≥ 2 labels), and
/// - the target realm is not a known trusted domain (no cross-realm Kerberos
///   path the resolver could forge a ticket for).
///
/// Returns a synthetic error with remediation so the LLM stops re-dispatching
/// the doomed bind and instead pivots (foothold in the realm, or trust enum).
pub(super) async fn check_unauthable_realm(
    queue: &TaskQueue,
    operation_id: &str,
    call: &ToolCall,
) -> Option<ToolExecResult> {
    if call.name == "enumerate_domain_trusts" || !requires_exact_realm(&call.name) {
        return None;
    }

    let target = call
        .arguments
        .get("target_domain")
        .or_else(|| call.arguments.get("domain"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty() && s.contains('.'))?;
    let target_lc = target.to_lowercase();

    let mut conn = queue.connection();
    let reader = RedisStateReader::new(operation_id.to_string());

    let creds = reader.get_credentials(&mut conn).await.unwrap_or_default();
    let hashes = reader.get_hashes(&mut conn).await.unwrap_or_default();

    // No foothold yet — let unauthenticated/null-session attempts proceed.
    let owned_realms: Vec<String> = creds
        .iter()
        .filter(|c| !c.password.is_empty())
        .map(|c| c.domain.clone())
        .chain(
            hashes
                .iter()
                .filter(|h| !h.hash_value.is_empty())
                .map(|h| h.domain.clone()),
        )
        .filter(|d| !d.is_empty())
        .collect();
    if owned_realms.is_empty() {
        return None;
    }

    // Any owned principal in the same forest tree as the target can bind
    // (intra-forest trust is transitive). Only unrelated forests are doomed.
    if owned_realms
        .iter()
        .any(|d| realms_related(&target_lc, &d.to_lowercase()))
    {
        return None;
    }

    // A discovered trust to the target realm means a cross-realm Kerberos path
    // (forged inter-realm ticket) may exist — don't block those.
    let trusted = reader
        .get_trusted_domains(&mut conn)
        .await
        .unwrap_or_default();
    if trusted.keys().any(|d| d.eq_ignore_ascii_case(target)) {
        return None;
    }

    warn!(
        tool = %call.name,
        target = %target,
        owned = ?owned_realms,
        "Rejecting tool call: no owned principal can authenticate to target realm"
    );

    Some(ToolExecResult {
        output: String::new(),
        error: Some(format!(
            "No owned credential or hash for domain '{target}', and no trust to it is known. \
             An authenticated bind to this domain will fail with LDAP 0x52e. Capture a foothold \
             in '{target}' first (a credential or hash for one of its principals), or — if a \
             domain/forest trust exists — discover it with enumerate_domain_trusts and pivot via \
             a cross-realm Kerberos ticket. Do not retry this tool against '{target}' until then."
        )),
        discoveries: None,
    })
}

/// True when realms `a` and `b` sit in the same forest tree and so trust each
/// other transitively: equal, or sharing a DNS suffix of ≥ 2 labels (e.g.
/// `child.contoso.local` and `contoso.local` share
/// `contoso.local`). Unrelated forests share only the TLD-style tail
/// (`child.contoso.local` vs `fabrikam.local` share just `local`, 1 label)
/// and are NOT related — cross-forest auth needs an explicit trust.
fn realms_related(a: &str, b: &str) -> bool {
    if a.eq_ignore_ascii_case(b) {
        return true;
    }
    let a_labels = a.rsplit('.');
    let b_labels = b.rsplit('.');
    let shared = a_labels
        .zip(b_labels)
        .take_while(|(x, y)| x.eq_ignore_ascii_case(y))
        .count();
    shared >= 2
}

/// Return the known domain with the smallest edit distance to `supplied`,
/// if any are within distance 3. Used only to nudge the LLM in the error.
fn closest_match(supplied: &str, known: &[String]) -> Option<String> {
    known
        .iter()
        .map(|d| (d.clone(), edit_distance(supplied, d)))
        .filter(|(_, dist)| *dist <= 3)
        .min_by_key(|(_, dist)| *dist)
        .map(|(d, _)| d)
}

fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (n, m) = (a.len(), b.len());
    if n == 0 {
        return m;
    }
    if m == 0 {
        return n;
    }
    let mut prev: Vec<usize> = (0..=m).collect();
    let mut curr = vec![0usize; m + 1];
    for i in 1..=n {
        curr[0] = i;
        for j in 1..=m {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[m]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edit_distance_basic() {
        assert_eq!(edit_distance("contoso.local", "contoso.local"), 0);
        assert_eq!(
            edit_distance("child.contossso.local", "child.contoso.local"),
            2
        );
        assert_eq!(
            edit_distance("child.contosssso.local", "child.contoso.local"),
            3
        );
        assert!(edit_distance("foo.bar", "completely.different") > 5);
    }

    #[test]
    fn closest_match_picks_nearest() {
        let known = vec![
            "fabrikam.local".to_string(),
            "child.contoso.local".to_string(),
            "contoso.local".to_string(),
        ];
        let picked = closest_match("child.contossso.local", &known);
        assert_eq!(picked.as_deref(), Some("child.contoso.local"));
    }

    #[test]
    fn closest_match_returns_none_when_far() {
        let known = vec!["fabrikam.local".to_string()];
        assert!(closest_match("totally.unrelated.domain", &known).is_none());
    }

    #[test]
    fn realms_related_exact_and_case_insensitive() {
        assert!(realms_related("contoso.local", "contoso.local"));
        assert!(realms_related("Contoso.Local", "contoso.local"));
    }

    #[test]
    fn realms_related_parent_and_child_same_forest() {
        // child ↔ parent: shared suffix `contoso.local` (2 labels).
        assert!(realms_related("child.contoso.local", "contoso.local"));
        assert!(realms_related("contoso.local", "child.contoso.local"));
    }

    #[test]
    fn realms_related_siblings_same_forest() {
        // two children of the same parent share `contoso.local`.
        assert!(realms_related("a.contoso.local", "b.contoso.local"));
    }

    #[test]
    fn realms_related_separate_forests_share_only_tld() {
        // The bug case: north child vs a foreign forest root share only `local`.
        assert!(!realms_related("north.contoso.local", "fabrikam.local"));
        assert!(!realms_related("contoso.local", "fabrikam.local"));
    }
}
