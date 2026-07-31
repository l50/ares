//! Forward-time state capture — extracts the prior state a faithful revert
//! needs and that is only observable at mutation time, out of the tool's own
//! output. Stored on [`MutationRecord::hint`](super::journal::MutationRecord).
//!
//! Only post-hoc captures (readable from the forward tool's stdout) live here.
//! Captures that require a read *before* the write (original UPN / attribute
//! value) belong in the executor itself and are out of scope for this pass.

use serde_json::{json, Value};

/// Whether a mutating call actually changed target state.
///
/// A zero exit code only proves the tool ran. Several mutating tools are
/// "make it so" operations that succeed loudly while changing nothing: noPac
/// aborts before creating its machine account, `sp_configure` reports
/// `changed from 1 to 1` when the option was already set, and rbcd.py logs
/// `Not modifying the delegation rights` when the SID is already delegated.
///
/// Journaling those produces a record of a mutation that never happened, and
/// teardown then either reverts state we did not create — deleting a
/// lab-provisioned setting — or reports it as un-revertible residue. Both were
/// observed live before this gate existed.
///
/// Tools with no known no-op signature return `true`: the default must be to
/// journal, so a mutation is never silently dropped from the revert plan.
pub fn mutation_took_effect(tool: &str, args: &Value, output: &str) -> bool {
    match tool {
        "add_computer" => {
            !matches!(
                args.get("action").and_then(Value::as_str).unwrap_or("add"),
                "delete" | "del" | "remove"
            ) && !ares_tools::privesc::add_computer_refused(output)
        }
        "nopac" => scrape_created_computer(output).is_some(),
        "mssql_enable_xp_cmdshell" | "mssql_linked_enable_xpcmdshell" => {
            !output.contains("changed from 1 to 1")
        }
        "rbcd_write" => {
            // impacket-rbcd exits 0 even when it wrote nothing: an unresolvable
            // -delegate-to/-delegate-from bails out of write() early, and an
            // already-present ACE is left alone. Both would otherwise journal a
            // mutation that never happened, which teardown then "reverts".
            let lower = output.to_lowercase();
            !lower.contains("not modifying the delegation rights")
                && !lower.contains("can already impersonate")
                && !lower.contains("does not exist!")
                && !lower.contains("user not found in ldap")
        }
        _ => true,
    }
}

/// Capture the state a mutation is about to destroy, before it runs.
///
/// [`hint_for`] reads the tool's own stdout, which is necessarily *after* the
/// change. That is fine for a mutation that mints something new — a DeviceID,
/// a machine account — because the new name is the thing teardown needs. It is
/// useless for a mutation that overwrites, because the value teardown needs is
/// gone by the time the tool speaks.
///
/// A password reset is the only such mutation today. `bloodyAD set password`
/// writes `unicodePwd`, so the original plaintext is unrecoverable — but the
/// original *NT hash* is a value operation state may already hold from an
/// earlier DCSync, and `restore_password_hash` can write it back over SAMR.
/// Capturing it here is what turns an `Impossible` revert into a `Clean` one.
///
/// Returns `None` when state holds no hash for the victim, which is the common
/// case for the automated path: `auto_dacl_abuse` deliberately skips the reset
/// when material for the target is already known, so the resets it does
/// dispatch are exactly the ones with nothing to capture.
pub fn prior_state_hint(
    tool: &str,
    args: &Value,
    hashes: &[ares_core::models::Hash],
) -> Option<Value> {
    if tool != "bloodyad_set_password" {
        return None;
    }
    let victim = args.get("target_user").and_then(Value::as_str)?;
    let victim_l = bare_account(victim);
    let domain_l = args
        .get("domain")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_lowercase();

    hashes
        .iter()
        .filter(|h| bare_account(&h.username) == victim_l)
        .filter(|h| {
            let d = h.domain.to_lowercase();
            domain_l.is_empty() || d.is_empty() || d == domain_l || domain_l.starts_with(&d)
        })
        .filter_map(|h| nt_component(&h.hash_value).map(|nt| (h, nt)))
        .max_by_key(|(h, _)| h.attack_step)
        .map(|(_, nt)| json!({ "prior_nt_hash": nt }))
}

/// Reduce `DOMAIN\user`, `user@domain` or a bare name to a lowercase account.
fn bare_account(name: &str) -> String {
    let mut n = name.trim();
    if let Some((_, rest)) = n.rsplit_once('\\') {
        n = rest;
    }
    if let Some((head, _)) = n.split_once('@') {
        n = head;
    }
    n.trim().to_ascii_lowercase()
}

/// Pull the NT half out of an `LM:NT` or bare-NT hash, if it is well formed.
fn nt_component(hash_value: &str) -> Option<String> {
    let nt = hash_value.trim().rsplit(':').next()?.trim();
    (nt.len() == 32 && nt.chars().all(|c| c.is_ascii_hexdigit())).then(|| nt.to_lowercase())
}

/// Extract a cleanup hint from a successful mutating call's output, if any.
pub fn hint_for(tool: &str, args: &Value, output: &str) -> Option<Value> {
    match tool {
        "pywhisker" => {
            // The DeviceID needed to remove the Key Credential is only minted
            // by the add action and printed to stdout.
            let action = args.get("action").and_then(Value::as_str).unwrap_or("add");
            if action != "add" {
                return None;
            }
            scrape_device_id(output).map(|id| json!({ "device_id": id }))
        }
        "nopac" => {
            // noPac mints a random machine account whose name is only in stdout;
            // capture it so teardown can delete the orphaned computer.
            scrape_created_computer(output).map(|name| json!({ "created_computer": name }))
        }
        "add_computer" => {
            // The add path mints its own name, so the forward args do not name
            // the object that was created. Capture what impacket reported or
            // teardown's action-flip deletes the wrong account, or none.
            let action = args.get("action").and_then(Value::as_str).unwrap_or("add");
            if matches!(action, "delete" | "del" | "remove") {
                return None;
            }
            ares_tools::parsers::scrape_added_machine_account(output).map(|(name, _)| {
                let sam = if name.ends_with('$') {
                    name.to_string()
                } else {
                    format!("{name}$")
                };
                json!({ "created_computer": sam })
            })
        }
        _ => None,
    }
}

/// Pull the machine-account name noPac created from lines like
/// `[*] MachineAccount "WIN-3MG3G0LEUAD$" password = …` or
/// `[*] Adding Computer Account "WIN-…$"`. Returns the sAMAccountName (`…$`).
fn scrape_created_computer(output: &str) -> Option<String> {
    for marker in ["MachineAccount \"", "Computer Account \""] {
        if let Some(i) = output.find(marker) {
            let rest = &output[i + marker.len()..];
            if let Some(end) = rest.find('"') {
                let name = rest[..end].trim();
                if name.len() > 1 && name.ends_with('$') {
                    return Some(name.to_string());
                }
            }
        }
    }
    None
}

/// Pull the DeviceID GUID that pywhisker prints after adding a Key Credential
/// (e.g. `[+] ... DeviceID: 1a2b3c4d-....`).
fn scrape_device_id(output: &str) -> Option<String> {
    let idx = output.find("DeviceID:")?;
    let rest = &output[idx + "DeviceID:".len()..];
    let token = rest.split_whitespace().next()?.trim();
    if token.is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash_of(user: &str, domain: &str, value: &str, step: i32) -> ares_core::models::Hash {
        serde_json::from_value(json!({
            "username": user,
            "domain": domain,
            "hash_value": value,
            "attack_step": step,
        }))
        .expect("hash fixture")
    }

    #[test]
    fn prior_state_captures_the_victims_nt_hash() {
        let args = json!({ "target_user": "alice", "domain": "contoso.local" });
        let hashes = vec![
            hash_of(
                "bob",
                "contoso.local",
                "aad3b435b51404eeaad3b435b51404ee:11111111111111111111111111111111",
                1,
            ),
            hash_of(
                "alice",
                "contoso.local",
                "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
                2,
            ),
        ];
        let hint = prior_state_hint("bloodyad_set_password", &args, &hashes)
            .expect("alice's hash is in state and must be captured");
        assert_eq!(hint["prior_nt_hash"], "31d6cfe0d16ae931b73c59d7e0c089c0");
    }

    #[test]
    fn prior_state_is_none_when_state_holds_nothing_for_the_victim() {
        let args = json!({ "target_user": "alice", "domain": "contoso.local" });
        let hashes = vec![hash_of(
            "bob",
            "contoso.local",
            "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            1,
        )];
        assert!(
            prior_state_hint("bloodyad_set_password", &args, &hashes).is_none(),
            "this is the common automated case and it must degrade to unrevertable, not to a wrong hash"
        );
    }

    #[test]
    fn prior_state_rejects_a_malformed_hash() {
        let args = json!({ "target_user": "alice", "domain": "contoso.local" });
        let hashes = vec![hash_of(
            "alice",
            "contoso.local",
            "$krb5tgs$23$*alice*$abcdef",
            1,
        )];
        assert!(
            prior_state_hint("bloodyad_set_password", &args, &hashes).is_none(),
            "roast ciphertext is not an NT hash and writing it back would brick the account"
        );
    }

    #[test]
    fn prior_state_matches_a_decorated_principal() {
        let args = json!({ "target_user": "CONTOSO\\alice", "domain": "contoso.local" });
        let hashes = vec![hash_of(
            "alice@contoso.local",
            "contoso.local",
            "31d6cfe0d16ae931b73c59d7e0c089c0",
            1,
        )];
        assert!(prior_state_hint("bloodyad_set_password", &args, &hashes).is_some());
    }

    #[test]
    fn prior_state_ignores_tools_that_do_not_overwrite() {
        let args = json!({ "target_user": "alice", "domain": "contoso.local" });
        let hashes = vec![hash_of(
            "alice",
            "contoso.local",
            "31d6cfe0d16ae931b73c59d7e0c089c0",
            1,
        )];
        assert!(prior_state_hint("pywhisker", &args, &hashes).is_none());
    }

    #[test]
    fn xp_cmdshell_already_enabled_is_not_a_mutation() {
        // sp_configure reports success either way; only the from/to pair says
        // whether anything changed. GOAD ships xp_cmdshell on, so this is the
        // common case, and journaling it invites teardown to disable a
        // provisioned vulnerability.
        let noop = "Configuration option 'xp_cmdshell' changed from 1 to 1. Run RECONFIGURE.";
        assert!(!mutation_took_effect(
            "mssql_enable_xp_cmdshell",
            &json!({}),
            noop
        ));

        let real = "Configuration option 'xp_cmdshell' changed from 0 to 1. Run RECONFIGURE.";
        assert!(mutation_took_effect(
            "mssql_enable_xp_cmdshell",
            &json!({}),
            real
        ));
    }

    #[test]
    fn rbcd_write_that_changed_nothing_is_not_a_mutation() {
        let noop = "[*] alice$ can already impersonate users on dc01$\n\
                    [*] Not modifying the delegation rights.";
        assert!(!mutation_took_effect("rbcd_write", &json!({}), noop));

        let real = "[*] Delegation rights modified successfully!";
        assert!(mutation_took_effect("rbcd_write", &json!({}), real));
    }

    /// Verbatim output from impacket-rbcd 0.13.0.dev0 when `-delegate-from`
    /// cannot be resolved. It exits 0, so without this the orchestrator
    /// journals a delegation entry that was never written and teardown then
    /// reports having reverted it.
    #[test]
    fn rbcd_write_with_an_unresolvable_principal_is_not_a_mutation() {
        let unresolved =
            "[-] User not found in LDAP: S-1-5-21-412342169-2221029212-88264412-1010\n\
                          [-] Account to escalate does not exist! \
                          (forgot \"$\" for a computer account? wrong domain?)";
        assert!(!mutation_took_effect("rbcd_write", &json!({}), unresolved));

        let bad_target = "[-] Account to modify does not exist! \
                          (forgot \"$\" for a computer account? wrong domain?)";
        assert!(!mutation_took_effect("rbcd_write", &json!({}), bad_target));
    }

    #[test]
    fn nopac_without_a_created_account_is_not_a_mutation() {
        // Observed live: noPac reports success having created nothing, which
        // journaled a phantom entry teardown then flagged as NEEDS-CAPTURE
        // residue that did not exist.
        assert!(!mutation_took_effect(
            "nopac",
            &json!({}),
            "[-] Cannot exploit, quota reached"
        ));
        assert!(mutation_took_effect(
            "nopac",
            &json!({}),
            "[*] Adding Computer Account \"WIN-ABCDEF12$\""
        ));
    }

    #[test]
    fn tools_without_a_known_noop_signature_are_always_journaled() {
        // The default must be to journal: dropping a real mutation from the
        // revert plan is worse than journaling one that changed nothing.
        assert!(mutation_took_effect(
            "addspn",
            &json!({}),
            "anything at all"
        ));
        assert!(mutation_took_effect("dacl_edit", &json!({}), ""));
    }

    /// impacket-addcomputer exits 0 on an add it refused. A name collision is
    /// the dangerous one: journaling it as a creation makes teardown delete an
    /// object this operation never created, and since teardown authenticates as
    /// a domain admin it has the rights to succeed.
    #[test]
    fn add_computer_that_refused_to_create_is_not_a_mutation() {
        for refused in [
            "[-] Account WS01$ already exists! If you just want to set a password, use -no-add.",
            "[-] User alice machine quota exceeded!",
            "[-] Failed to add a new computer. The server denied the operation.",
            "[-] SMB SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED",
        ] {
            assert!(
                !mutation_took_effect("add_computer", &json!({}), refused),
                "{refused}"
            );
        }

        let created = "[*] Successfully added machine account WS01$ with password P@ssw0rd!.";
        assert!(mutation_took_effect("add_computer", &json!({}), created));
    }

    /// A delete is not a creation. Journaling one makes `undo_plan` invert it
    /// into a second delete of the same name — harmless if nothing was
    /// recreated in between, destructive if something was.
    #[test]
    fn add_computer_delete_is_not_journalled_as_a_creation() {
        assert!(!mutation_took_effect(
            "add_computer",
            &json!({ "action": "delete", "computer_name": "ws01" }),
            "[*] Successfully deleted WS01$."
        ));
    }

    #[test]
    fn captures_pywhisker_device_id_on_add() {
        let out = "[*] Searching for the target account\n\
                   [+] KeyCredential generated with DeviceID: 4b1c9f2a-1234-4a2b-9c3d-abcdef012345\n\
                   [*] Saving to disk";
        let hint = hint_for("pywhisker", &json!({ "action": "add" }), out).unwrap();
        assert_eq!(
            hint["device_id"],
            json!("4b1c9f2a-1234-4a2b-9c3d-abcdef012345")
        );
    }

    /// `build_add_computer` mints the name, so the journal's only record of what
    /// was created is impacket's banner. Miss it and teardown is blocked.
    #[test]
    fn captures_minted_machine_account_on_add() {
        let out = "[*] Successfully added machine account ARES-1A2B3C4D$ \
                   with password ArDEADBEEFCAFE1234!7z.";
        let hint = hint_for("add_computer", &json!({}), out).expect("created name");
        assert_eq!(hint["created_computer"], json!("ARES-1A2B3C4D$"));
    }

    /// The banner prints the bare name when impacket was given one; the hint is
    /// a sAMAccountName, which always carries the `$`.
    #[test]
    fn captured_machine_account_is_normalized_to_a_sam_account_name() {
        let out = "[*] Successfully added machine account ARES-1A2B3C4D with password x.";
        let hint = hint_for("add_computer", &json!({}), out).unwrap();
        assert_eq!(hint["created_computer"], json!("ARES-1A2B3C4D$"));
    }

    /// A delete created nothing, so there is nothing to capture — and a hint
    /// here would invert into a second delete of the same name.
    #[test]
    fn no_hint_for_add_computer_delete() {
        let out = "[*] Successfully added machine account ARES-1A2B3C4D$ with password x.";
        assert!(hint_for("add_computer", &json!({ "action": "delete" }), out).is_none());
    }

    /// addcomputer exits 0 on a refused add. No banner means no account, so no
    /// hint — otherwise teardown deletes whatever already owned the name.
    #[test]
    fn no_hint_when_add_was_refused() {
        let refused = "[-] Account ARES-1A2B3C4D$ already exists! \
                       If you just want to set a password, use -no-add.";
        assert!(hint_for("add_computer", &json!({}), refused).is_none());
    }

    #[test]
    fn no_hint_for_pywhisker_remove() {
        assert!(hint_for("pywhisker", &json!({ "action": "remove" }), "DeviceID: x").is_none());
    }

    #[test]
    fn no_hint_when_device_id_absent() {
        assert!(hint_for("pywhisker", &json!({ "action": "add" }), "no id here").is_none());
    }

    #[test]
    fn no_hint_for_other_tools() {
        assert!(hint_for("rbcd_write", &json!({}), "DeviceID: x").is_none());
    }

    #[test]
    fn captures_nopac_created_computer() {
        let out = "[*] Selected Target dc01\n\
                   [*] MachineAccount \"WIN-3MG3G0LEUAD$\" password = aB3xY...\n\
                   [*] Successfully added";
        let hint = hint_for("nopac", &json!({}), out).unwrap();
        assert_eq!(hint["created_computer"], json!("WIN-3MG3G0LEUAD$"));
    }

    #[test]
    fn captures_nopac_via_computer_account_marker() {
        let out = "[*] Adding Computer Account \"WIN-ABCDEF12$\"\n[*] done";
        let hint = hint_for("nopac", &json!({}), out).unwrap();
        assert_eq!(hint["created_computer"], json!("WIN-ABCDEF12$"));
    }

    #[test]
    fn no_nopac_hint_when_name_absent() {
        assert!(hint_for("nopac", &json!({}), "[*] failed to add").is_none());
    }
}
