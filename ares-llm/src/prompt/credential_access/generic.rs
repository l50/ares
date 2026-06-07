//! Generic fallback and technique-with-credentials prompt branches.
//!
//! These prompts MUST NOT inline credential values into example tool-call
//! signatures. The worker resolves credentials at dispatch time from operation
//! state. The LLM only sees principal-only signatures (target, username,
//! domain, dc_ip) and a non-secret capability label.

use std::collections::HashMap;

use serde_json::Value;
use tera::Context;

use crate::prompt::helpers::{cred_capability_label, insert_state_context};
use crate::prompt::templates::{
    render_template_with_context, TASK_CREDACCESS_FALLBACK, TASK_CREDACCESS_WITH_CREDS,
};
use crate::prompt::StateSnapshot;

use super::Params;

/// Try to generate a technique enforcement prompt WITH credentials (Branch 7).
/// Returns `Some` if conditions match, `None` otherwise.
pub(super) fn try_generate_with_creds(
    task_id: &str,
    payload: &Value,
    p: &Params<'_>,
    state: Option<&StateSnapshot>,
) -> Option<anyhow::Result<String>> {
    if p.techniques.is_empty() || !p.has_creds {
        return None;
    }

    let dc_ip = p.dc_ip;
    let domain = p.domain;
    let username = p.username;
    let cred_capability = cred_capability_label(payload, p.hash_value);

    // When the orchestrator dispatched this task with a `just_dc_user` hint
    // (e.g. krbtgt extraction from `auto_krbtgt_extraction`), surface it as
    // an explicit argument in the secretsdump signature so the LLM agent
    // forwards it to the tool. Without this, the agent emits a full DCSync
    // which hits DRSUAPI hardening or returns redundantly large output, and
    // any cross-realm syntax slip becomes a STATUS_LOGON_FAILURE that bails
    // the task back to enumeration loops.
    let just_dc_user = payload
        .get("just_dc_user")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());
    let secretsdump_sig = if let Some(target_user) = just_dc_user {
        format!(
            "secretsdump(target='{dc_ip}', username='{username}', domain='{domain}', \
             just_dc_user='{target_user}') - DCSync just the {target_user} hash; \
             do NOT omit just_dc_user — a full dump will be rejected or duplicated"
        )
    } else {
        format!(
            "secretsdump(target='{dc_ip}', username='{username}', domain='{domain}') \
             - dump hashes (requires admin)"
        )
    };

    // Example signatures show only LLM-callable fields; the worker injects
    // password/hash/aes/ticket from state at dispatch time.
    let technique_map: HashMap<&str, String> = [
        (
            "sysvol_script_search",
            format!(
                "sysvol_script_search(target='{dc_ip}', username='{username}', domain='{domain}') \
                 - ~2 seconds, finds hardcoded passwords in login scripts"
            ),
        ),
        (
            "gpp_password_finder",
            format!(
                "gpp_password_finder(target='{dc_ip}', username='{username}', domain='{domain}') \
                 - ~2 seconds, finds GPP/cpassword credentials"
            ),
        ),
        (
            "ldap_search_descriptions",
            format!(
                "ldap_search_descriptions(target='{dc_ip}', username='{username}', domain='{domain}') \
                 - finds passwords in LDAP description fields"
            ),
        ),
        (
            "kerberoast",
            format!(
                "kerberoast(domain='{domain}', username='{username}', dc_ip='{dc_ip}') \
                 - service account hashes (uses correct DC for the domain)"
            ),
        ),
        ("secretsdump", secretsdump_sig),
        (
            "lsassy",
            format!(
                "lsassy(target='{dc_ip}', username='{username}', domain='{domain}') \
                 - LSASS memory dump"
            ),
        ),
        (
            "laps_dump",
            format!(
                "laps_dump(target='{dc_ip}', username='{username}', domain='{domain}') \
                 - LAPS local admin passwords"
            ),
        ),
    ]
    .into_iter()
    .collect();

    let mut instructions = Vec::new();
    for (i, technique) in p.techniques.iter().enumerate() {
        let idx = i + 1;
        if let Some(desc) = technique_map.get(technique.as_str()) {
            instructions.push(format!("{idx}. {desc}"));
        } else {
            instructions.push(format!("{idx}. {technique}(...)"));
        }
    }

    if instructions.is_empty() {
        return None;
    }

    let targets_display = if p.targets.is_empty() {
        "(none)".to_string()
    } else {
        p.targets.join(", ")
    };

    let mut ctx = Context::new();
    ctx.insert("task_id", task_id);
    ctx.insert("domain", domain);
    ctx.insert(
        "dc_ip_display",
        if dc_ip.is_empty() { "(unset)" } else { dc_ip },
    );
    ctx.insert("targets_display", &targets_display);
    ctx.insert(
        "user_display",
        if username.is_empty() {
            "(unset)"
        } else {
            username
        },
    );
    ctx.insert("cred_capability", cred_capability);
    ctx.insert("instructions_text", &instructions.join("\n"));
    insert_state_context(&mut ctx, state, "credential_access", Some(dc_ip));

    Some(render_template_with_context(
        TASK_CREDACCESS_WITH_CREDS,
        &ctx,
    ))
}

/// Generate the generic fallback prompt.
pub(super) fn generate_fallback(
    task_id: &str,
    payload: &Value,
    p: &Params<'_>,
    state: Option<&StateSnapshot>,
) -> anyhow::Result<String> {
    let dc_ip = p.dc_ip;

    let cred_type = if p.has_password {
        "password"
    } else if p.has_hash {
        if p.hash_is_pth {
            "nthash"
        } else {
            "hash (non-NTLM)"
        }
    } else {
        "none"
    };
    let hash_note = if p.has_hash && !p.hash_is_pth {
        "NOTE: Provided hash is not NTLM pass-the-hash compatible; \
         do not attempt secretsdump/lsassy with it."
    } else {
        ""
    };
    let source = payload
        .get("credential_source")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let hash_type = payload
        .get("hash_type")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let techniques_display = if p.techniques.is_empty() {
        "auto-select".to_string()
    } else {
        p.techniques.join(", ")
    };
    let targets_display = if p.targets.is_empty() {
        "(none)".to_string()
    } else {
        p.targets.join(", ")
    };

    let mut ctx = Context::new();
    ctx.insert("task_id", task_id);
    ctx.insert("domain", p.domain);
    ctx.insert("targets_display", &targets_display);
    ctx.insert(
        "dc_ip_display",
        if dc_ip.is_empty() { "(unset)" } else { dc_ip },
    );
    ctx.insert(
        "user_display",
        if p.username.is_empty() {
            "(unset)"
        } else {
            p.username
        },
    );
    ctx.insert("cred_type", cred_type);
    ctx.insert("techniques_display", &techniques_display);
    if !hash_type.is_empty() {
        ctx.insert("hash_type", hash_type);
    }
    if !source.is_empty() {
        ctx.insert("source", source);
    }
    if !p.reason.is_empty() {
        ctx.insert("reason", p.reason);
    }
    if !hash_note.is_empty() {
        ctx.insert("hash_note", hash_note);
    }
    insert_state_context(&mut ctx, state, "credential_access", Some(dc_ip));

    render_template_with_context(TASK_CREDACCESS_FALLBACK, &ctx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Build the smallest Params that satisfies `try_generate_with_creds`'s
    /// preconditions (`!techniques.is_empty() && has_creds`).
    fn params_with_secretsdump() -> Params<'static> {
        Params {
            hash_value: None,
            hash_is_pth: false,
            techniques: vec!["secretsdump".to_string()],
            targets: vec!["10.0.0.10"],
            dc_ip: "10.0.0.10",
            domain: "contoso.local",
            username: "alice",
            password: "Welcome123",
            reason: "",
            ticket_path: None,
            no_pass: false,
            has_password: true,
            has_hash: false,
            has_creds: true,
            excluded_users: "",
        }
    }

    /// The rendered credaccess_with_creds prompt must explicitly forbid the
    /// wrong-first-tool warmups that the agent has historically picked
    /// instead of the assigned `secretsdump` (smbexec / wmiexec / psexec /
    /// evil_winrm / nmap_scan / smb_signing_check / ldap_search) — the
    /// previous list named only `smb_sweep` and `kerberos_user_enum`, which
    /// the LLM rationalized around. If a future edit drops these names,
    /// this test fires.
    #[test]
    fn with_creds_prompt_forbids_wrong_first_tools() {
        let p = params_with_secretsdump();
        let rendered = try_generate_with_creds("task-test", &json!({}), &p, None)
            .expect("preconditions are met (techniques + has_creds)")
            .expect("template renders");

        for needle in [
            "smbexec",
            "wmiexec",
            "psexec",
            "evil_winrm",
            "nmap_scan",
            "smb_signing_check",
            "ldap_search",
            "enumerate_domain_trusts",
            "bloodhound",
        ] {
            assert!(
                rendered.contains(needle),
                "credaccess_with_creds prompt should mention `{needle}` in its DO NOT block. \
                 Rendered output:\n{rendered}"
            );
        }
    }

    /// The "first tool call must be technique #1" rule is the positive
    /// counterpart to the DO NOT list. Both must be present — if either
    /// drops out the agent reverts to exploratory warmup behavior.
    #[test]
    fn with_creds_prompt_demands_first_tool_be_technique_one() {
        let p = params_with_secretsdump();
        let rendered = try_generate_with_creds("task-test", &json!({}), &p, None)
            .expect("preconditions are met")
            .expect("template renders");

        assert!(
            rendered.contains("first tool call must be technique #1")
                || rendered.contains("FIRST tool call must be technique #1"),
            "prompt must instruct that the first tool call is technique #1. \
             Rendered output:\n{rendered}"
        );
    }
}
