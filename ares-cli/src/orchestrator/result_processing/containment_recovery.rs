//! Classify red-tool failures that suggest blue has taken a containment
//! action (account disabled, host firewalled, krbtgt rotated, certificate
//! revoked). Each signal maps 1:1 to a `SharedState::publish_*` method on
//! the containment publisher; the driver in `process_completed_task`
//! iterates the returned list and dispatches.
//!
//! The classifier is intentionally conservative: it only fires on
//! well-known error strings and only when there's enough context on the
//! task to make the observation actionable (a `cred_key` for revocation,
//! a `task_target_ip` for isolation, a Kerberos-hitting technique for
//! krbtgt rotation, a certificate-based technique for cert revocation).
//!
//! False positives are cheaper than false negatives here because
//! [`SharedState::publish_credential_revoked`] / `_host_isolated` /
//! `_krbtgt_rotated` / `_certificate_revoked` are idempotent per identity
//! key — a duplicate emit is a no-op — and the downstream queue filter
//! treats an observation as advisory (skip the affected work-item, don't
//! crash the op). Under-firing means the demo never adapts to blue.

use serde_json::Value;

use super::collect_result_text_parts;

/// A single containment observation extracted from a task result.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ContainmentSignal {
    CredentialRevoked {
        username: String,
        domain: String,
        source: String,
    },
    HostIsolated {
        ip: String,
        hostname: String,
        source: String,
    },
    KrbtgtRotated {
        domain: String,
        source: String,
    },
    CertificateRevoked {
        serial: String,
        ca: String,
        source: String,
    },
}

/// Case-insensitive substring match against any tool-output text on the
/// result payload.
fn any_text_contains(result: &Option<Value>, needle: &str) -> bool {
    let Some(payload) = result else {
        return false;
    };
    let needle_lower = needle.to_lowercase();
    collect_result_text_parts(payload)
        .iter()
        .any(|t| t.to_lowercase().contains(&needle_lower))
}

/// True when any tool-output text contains at least one of `needles`.
fn any_text_contains_any(result: &Option<Value>, needles: &[&str]) -> bool {
    needles.iter().any(|n| any_text_contains(result, n))
}

/// Techniques that authenticate with a certificate. On
/// `KDC_ERR_CLIENT_REVOKED` inside one of these, the classifier attributes
/// the failure to certificate revocation rather than account disablement.
fn is_certificate_backed_technique(technique: &str) -> bool {
    let t = technique.to_lowercase();
    matches!(
        t.as_str(),
        "certipy_auth" | "certipy_req" | "certipy_shadow" | "pkinit"
    ) || t.contains("certipy")
        || t.contains("esc1")
        || t.contains("esc4")
        || t.contains("esc8")
        || t.contains("adcs")
        || t.contains("pkinit")
}

/// Tools that talk to a specific host over SMB / WinRM / LDAP / WMI. If
/// they hit network-unreachable errors, the target is a plausible
/// candidate for `HostIsolated`. Filters out HTTP recon and general
/// scanning where unreachable can mean "closed port on a live host".
fn is_host_pivot_technique(technique: &str) -> bool {
    let t = technique.to_lowercase();
    t.contains("smb")
        || t.contains("winrm")
        || t.contains("ldap")
        || t.contains("wmi")
        || t.contains("nxc")
        || t.contains("netexec")
        || t.contains("secretsdump")
        || t.contains("dcsync")
        || t.contains("psexec")
        || t.contains("evil_winrm")
}

/// Well-known network-unreachable substrings that show up in the various
/// Python / Rust tool stacks red currently drives.
const NETWORK_UNREACHABLE_MARKERS: &[&str] = &[
    "STATUS_HOST_UNREACHABLE",
    "STATUS_NETWORK_UNREACHABLE",
    "STATUS_IO_TIMEOUT",
    "No route to host",
    "Network is unreachable",
    "Connection timed out",
    "connect: timed out",
    "Errno 110",
    "Errno 113",
    "ETIMEDOUT",
];

/// Well-known "credential rejected" substrings. Includes the Kerberos
/// `KDC_ERR_CLIENT_REVOKED` variant — the driver decides whether that
/// belongs to a cert-revocation or account-disable path based on the
/// invoking technique.
const CREDENTIAL_REJECT_MARKERS: &[&str] = &[
    "STATUS_LOGON_FAILURE",
    "INVALID_CREDENTIALS",
    "invalidCredentials",
    "The user name or password is incorrect",
    "KDC_ERR_C_PRINCIPAL_UNKNOWN",
];

/// Inspect a completed task and return any containment signals it surfaces.
///
/// - `cred_key`: `user@domain` for the credential the task was dispatched
///   with (already extracted by the caller from `pending_tasks`).
/// - `task_domain`: realm the task was targeting, if known.
/// - `task_target_ip`: canonical target address the task was pointed at.
///
/// Empty result = no signals; the caller should still run its existing
/// lockout / retry logic.
pub(crate) fn classify_containment_signals(
    result: &Option<Value>,
    technique: Option<&str>,
    cred_key: Option<&str>,
    task_domain: Option<&str>,
    task_target_ip: Option<&str>,
) -> Vec<ContainmentSignal> {
    let mut signals = Vec::new();
    let tech = technique.unwrap_or("");

    // 1. KDC_ERR_CLIENT_REVOKED under a cert-backed technique → certificate revoked.
    //    Under a password-backed technique → treat as credential revoked.
    let client_revoked = any_text_contains(result, "KDC_ERR_CLIENT_REVOKED");

    if client_revoked && is_certificate_backed_technique(tech) {
        signals.push(ContainmentSignal::CertificateRevoked {
            serial: String::new(), // Extraction from the raw PKINIT reject line is deferred.
            ca: String::new(),
            source: format!("KDC_ERR_CLIENT_REVOKED via {tech}"),
        });
    }

    // 2. STATUS_LOGON_FAILURE / INVALID_CREDENTIALS on a task using a stored cred
    //    → credential revoked. Only fires when we know which principal was used
    //    (cred_key set) — otherwise we don't have a target for the observation.
    if let Some(key) = cred_key {
        let credential_rejected = any_text_contains_any(result, CREDENTIAL_REJECT_MARKERS)
            || (client_revoked && !is_certificate_backed_technique(tech));
        if credential_rejected {
            if let Some((username, domain)) = key.split_once('@') {
                let marker =
                    credential_reject_marker_text(result).unwrap_or("STATUS_LOGON_FAILURE");
                signals.push(ContainmentSignal::CredentialRevoked {
                    username: username.to_string(),
                    domain: domain.to_string(),
                    source: format!("{marker} via {tech}"),
                });
            }
        }
    }

    // 3. KRB_AP_ERR_MODIFIED → krbtgt likely rotated. Fires on the realm the
    //    task was targeting, or on the cred's realm when task_domain is empty.
    if any_text_contains(result, "KRB_AP_ERR_MODIFIED") {
        let realm = task_domain
            .filter(|d| !d.is_empty())
            .map(str::to_string)
            .or_else(|| {
                cred_key
                    .and_then(|k| k.split_once('@'))
                    .map(|(_, d)| d.to_string())
            })
            .unwrap_or_default();
        if !realm.is_empty() {
            signals.push(ContainmentSignal::KrbtgtRotated {
                domain: realm,
                source: format!("KRB_AP_ERR_MODIFIED via {tech}"),
            });
        }
    }

    // 4. Network unreachable + host-pivot technique + known target IP → host isolated.
    if let Some(ip) = task_target_ip {
        if is_host_pivot_technique(tech)
            && any_text_contains_any(result, NETWORK_UNREACHABLE_MARKERS)
        {
            let marker = network_unreachable_marker_text(result).unwrap_or("network unreachable");
            signals.push(ContainmentSignal::HostIsolated {
                ip: ip.to_string(),
                hostname: String::new(),
                source: format!("{marker} via {tech}"),
            });
        }
    }

    signals
}

fn credential_reject_marker_text(result: &Option<Value>) -> Option<&'static str> {
    for m in CREDENTIAL_REJECT_MARKERS {
        if any_text_contains(result, m) {
            return Some(*m);
        }
    }
    if any_text_contains(result, "KDC_ERR_CLIENT_REVOKED") {
        return Some("KDC_ERR_CLIENT_REVOKED");
    }
    None
}

fn network_unreachable_marker_text(result: &Option<Value>) -> Option<&'static str> {
    for m in NETWORK_UNREACHABLE_MARKERS {
        if any_text_contains(result, m) {
            return Some(*m);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn out(text: &str) -> Option<Value> {
        Some(json!({ "tool_outputs": [text] }))
    }

    #[test]
    fn credential_revoked_on_status_logon_failure_with_cred_key() {
        let result = out("[-] contoso.local\\svc_mssql:P@ss STATUS_LOGON_FAILURE");
        let s = classify_containment_signals(
            &result,
            Some("nxc_smb"),
            Some("svc_mssql@contoso.local"),
            Some("contoso.local"),
            Some("192.168.58.10"),
        );
        assert!(s.iter().any(
            |sig| matches!(sig, ContainmentSignal::CredentialRevoked { username, domain, .. }
                if username == "svc_mssql" && domain == "contoso.local")
        ));
    }

    #[test]
    fn credential_revoked_needs_cred_key() {
        let result = out("STATUS_LOGON_FAILURE somewhere");
        let s = classify_containment_signals(
            &result,
            Some("nxc_smb"),
            None, // no cred_key => can't attribute
            Some("contoso.local"),
            Some("192.168.58.10"),
        );
        assert!(!s
            .iter()
            .any(|sig| matches!(sig, ContainmentSignal::CredentialRevoked { .. })));
    }

    #[test]
    fn certificate_revoked_on_kdc_client_revoked_under_certipy() {
        let result = out("KDC_ERR_CLIENT_REVOKED");
        let s = classify_containment_signals(
            &result,
            Some("certipy_auth"),
            None,
            Some("contoso.local"),
            Some("192.168.58.10"),
        );
        assert!(s
            .iter()
            .any(|sig| matches!(sig, ContainmentSignal::CertificateRevoked { .. })));
    }

    #[test]
    fn kdc_client_revoked_under_password_flow_is_credential_revoked() {
        let result = out("KDC_ERR_CLIENT_REVOKED on the wire");
        let s = classify_containment_signals(
            &result,
            Some("nxc_smb"),
            Some("alice@contoso.local"),
            Some("contoso.local"),
            Some("192.168.58.10"),
        );
        assert!(s
            .iter()
            .any(|sig| matches!(sig, ContainmentSignal::CredentialRevoked { .. })));
        assert!(!s
            .iter()
            .any(|sig| matches!(sig, ContainmentSignal::CertificateRevoked { .. })));
    }

    #[test]
    fn krbtgt_rotated_on_krb_ap_err_modified() {
        let result = out("KRB_AP_ERR_MODIFIED — decrypt integrity check failed");
        let s = classify_containment_signals(
            &result,
            Some("secretsdump"),
            Some("alice@contoso.local"),
            Some("contoso.local"),
            Some("192.168.58.240"),
        );
        assert!(s.iter().any(
            |sig| matches!(sig, ContainmentSignal::KrbtgtRotated { domain, .. }
                if domain == "contoso.local")
        ));
    }

    #[test]
    fn host_isolated_requires_host_pivot_technique() {
        let result = out("STATUS_HOST_UNREACHABLE");
        let s_smb = classify_containment_signals(
            &result,
            Some("nxc_smb"),
            None,
            None,
            Some("192.168.58.20"),
        );
        assert!(s_smb.iter().any(
            |sig| matches!(sig, ContainmentSignal::HostIsolated { ip, .. }
                if ip == "192.168.58.20")
        ));

        // Same failure text on an HTTP recon tool must NOT flip host-isolated,
        // because HTTP timeouts are noisy and mean many things.
        let s_http = classify_containment_signals(
            &result,
            Some("http_probe"),
            None,
            None,
            Some("192.168.58.20"),
        );
        assert!(!s_http
            .iter()
            .any(|sig| matches!(sig, ContainmentSignal::HostIsolated { .. })));
    }

    #[test]
    fn host_isolated_needs_target_ip() {
        let result = out("STATUS_HOST_UNREACHABLE");
        let s = classify_containment_signals(&result, Some("nxc_smb"), None, None, None);
        assert!(!s
            .iter()
            .any(|sig| matches!(sig, ContainmentSignal::HostIsolated { .. })));
    }

    #[test]
    fn empty_result_yields_no_signals() {
        assert!(classify_containment_signals(&None, Some("nxc_smb"), None, None, None).is_empty());
    }

    #[test]
    fn benign_output_yields_no_signals() {
        let result = out("[+] contoso.local\\alice:P@ss (Pwn3d!)");
        let s = classify_containment_signals(
            &result,
            Some("nxc_smb"),
            Some("alice@contoso.local"),
            Some("contoso.local"),
            Some("192.168.58.10"),
        );
        assert!(s.is_empty());
    }
}
