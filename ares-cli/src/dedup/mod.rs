pub(crate) mod credentials;
pub(crate) mod domains;
pub(crate) mod hashes;
pub(crate) mod labels;
pub(crate) mod users;

#[cfg(test)]
mod tests;

use regex::Regex;
use std::sync::LazyLock;

/// Strip trailing DNS root dot and NetExec "0." artifact from domain strings
/// (e.g. `child.contoso.local.` → `child.contoso.local`,
/// `contoso.local0` → `contoso.local`).
pub(super) fn strip_trailing_dot(s: &str) -> &str {
    let s = s.trim_end_matches('.');
    // NetExec sometimes appends "0" to domain TLDs. Strip if the char
    // before the trailing 0 is alphabetic (i.e. TLD-like, not "host10").
    match s.strip_suffix('0') {
        Some(clean) if clean.ends_with(|c: char| c.is_ascii_alphabetic()) => clean,
        _ => s,
    }
}

/// Auto-generated Windows hostname pattern (`WIN-` + 11 alphanumerics + optional `$`).
/// Used to filter ghost machine accounts that the agent created itself via
/// NoPAC / MachineAccountQuota — not real lab hosts, just our own residue.
static GHOST_MACHINE_ACCOUNT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^WIN-[A-Z0-9]{11}\$?$").unwrap());

/// True if `username` looks like an auto-generated Windows machine account
/// (e.g. `WIN-G9FWV8ZNSCL$`) — typically agent-created via NoPAC.
pub(crate) fn is_ghost_machine_account(username: &str) -> bool {
    GHOST_MACHINE_ACCOUNT_RE.is_match(username.trim())
}

/// Well-known built-in AD groups that are not, on their own, a privilege-
/// escalation target: holding an ACL over them (or being added to them) does
/// not advance toward Domain Admin. BloodHound emits GenericAll/WriteDacl
/// edges against these by the dozen; dispatching each as an exploit task
/// floods the queue with doomed attempts and starves decisive escalations.
///
/// Deliberately conservative — escalation-relevant groups (DnsAdmins, Account
/// Operators, Backup/Server/Print Operators, Cert Publishers, Schema/
/// Enterprise/Domain Admins, Group Policy Creator Owners) are NOT listed here,
/// so genuine ACL paths are never filtered.
static LOW_VALUE_ACL_TARGETS: &[&str] = &[
    "cloneable domain controllers",
    "iis_iusrs",
    "pre-windows 2000 compatible access",
    "ras and ias servers",
    "windows authorization access group",
    "terminal server license servers",
    "storage replica administrators",
    "incoming forest trust builders",
    "remote desktop users",
    "distributed com users",
    "performance log users",
    "performance monitor users",
    "event log readers",
    "domain guests",
    "guests",
];

/// True if `target` is a well-known built-in principal that is not a viable
/// ACL-abuse escalation target (see [`LOW_VALUE_ACL_TARGETS`]). Normalizes the
/// `name@domain`, `DOMAIN\name`, and bare-`name` forms before matching; a raw
/// SID (no resolvable name) is treated as not-low-value so it is still tried.
pub(crate) fn is_low_value_acl_target(target: &str) -> bool {
    let t = target.trim();
    if t.is_empty() {
        return false;
    }
    // Strip realm suffix (name@domain) then NetBIOS prefix (DOMAIN\name).
    let t = t.split('@').next().unwrap_or(t);
    let t = t.rsplit('\\').next().unwrap_or(t).trim().to_lowercase();
    LOW_VALUE_ACL_TARGETS.contains(&t.as_str())
}

pub(crate) use credentials::{dedup_credentials, sanitize_credentials};
pub(crate) use domains::normalize_state_domains;
pub(crate) use hashes::dedup_hashes;
pub(crate) use labels::normalize_source_label;
pub(crate) use users::dedup_users;
