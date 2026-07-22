//! Undo registry — maps each journaled mutation to its inverse plan and a
//! reversibility class. The teardown engine consumes an [`UndoPlan`] to (a)
//! print what *would* happen (`--dry-run`) and (b) dispatch the inverse plus a
//! read-back validation probe.
//!
//! Inverse construction is deliberately uniform: for action-parameterized tools
//! (pywhisker, dacl_edit, addspn, and the ones given an `action` branch) the
//! reverse is the *same* forward arguments with the `action` key overridden, so
//! all targeting/auth keys carry over untouched. Tools that reverse via a
//! different command (xp_cmdshell → mssql_command) build fresh args from the
//! forward call's auth/target keys.

use serde_json::{json, Value};

use super::journal::MutationRecord;

/// How faithfully a mutation can be reversed automatically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reversibility {
    /// Inverse is a single tool call built from the forward args; read-back
    /// can confirm it. No forward-time capture needed.
    Clean,
    /// Reversible only with state captured at forward time (pywhisker DeviceID,
    /// original UPN/attribute, saved-template path). Blocked until that
    /// capture lands in `record.hint`.
    NeedsCapture,
    /// Partially reversible; leaves residue that needs an out-of-band scrub
    /// (AdminSDHolder SDProp propagation, GPO SYSVOL+LDAP artifacts).
    Hard,
    /// No faithful inverse (a reset password's original plaintext is unknowable).
    Impossible,
    /// Not a target mutation we know how to reverse.
    Unsupported,
}

impl Reversibility {
    pub fn label(self) -> &'static str {
        match self {
            Reversibility::Clean => "CLEAN",
            Reversibility::NeedsCapture => "NEEDS-CAPTURE",
            Reversibility::Hard => "HARD",
            Reversibility::Impossible => "IMPOSSIBLE",
            Reversibility::Unsupported => "UNSUPPORTED",
        }
    }
}

/// A read-back probe that confirms a revert actually took effect. `tool` +
/// `args` are dispatched, then `expect_absent` (a needle expected to be GONE
/// from the output on success) is checked. Kept intentionally simple for v1;
/// per-tool structured validators can replace the substring check later.
#[derive(Debug, Clone)]
pub struct ValidateProbe {
    pub tool: String,
    pub args: Value,
    pub expect_absent: Option<String>,
}

/// The plan for reversing one journaled mutation.
#[derive(Debug, Clone)]
pub struct UndoPlan {
    pub class: Reversibility,
    /// Inverse tool + args, when one can be built now. `None` when
    /// `NeedsCapture`/`Hard`/`Impossible`/`Unsupported` block automatic revert.
    pub inverse: Option<(String, Value)>,
    /// Independent read-back probe run after a successful revert.
    pub validate: Option<ValidateProbe>,
    /// Human-readable description of the intended reversal.
    pub note: String,
}

impl UndoPlan {
    fn manual(class: Reversibility, note: impl Into<String>) -> Self {
        Self {
            class,
            inverse: None,
            validate: None,
            note: note.into(),
        }
    }
}

/// Clone forward args and override a single key (typically `action`).
fn with_override(args: &Value, key: &str, val: &str) -> Value {
    let mut m = args.as_object().cloned().unwrap_or_default();
    m.insert(key.to_string(), json!(val));
    Value::Object(m)
}

/// Non-empty string field from an argument object.
fn astr<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
}

/// Build a `bloodyad_get_object` read-back probe that reuses the forward call's
/// connection/auth keys. `expect_absent` is the needle that must be GONE from
/// the read output once the mutation is reversed.
fn get_object_probe(
    forward: &Value,
    target: &str,
    attr: &str,
    expect_absent: &str,
) -> ValidateProbe {
    let mut m = serde_json::Map::new();
    for k in ["domain", "dc_ip", "username", "ticket_path", "hash"] {
        if let Some(v) = forward.get(k) {
            m.insert(k.to_string(), v.clone());
        }
    }
    m.insert("target".into(), json!(target));
    m.insert("attr".into(), json!(attr));
    ValidateProbe {
        tool: "bloodyad_get_object".into(),
        args: Value::Object(m),
        expect_absent: Some(expect_absent.to_string()),
    }
}

/// pywhisker reverses cleanly only when the add's DeviceID was captured into
/// the journal hint; otherwise it is blocked as needs-capture.
fn pywhisker_plan(record: &MutationRecord) -> UndoPlan {
    let device_id = record
        .hint
        .as_ref()
        .and_then(|h| h.get("device_id"))
        .and_then(Value::as_str);
    match device_id {
        Some(did) => {
            let mut args = with_override(&record.args, "action", "remove");
            if let Some(o) = args.as_object_mut() {
                o.insert("device_id".into(), json!(did));
            }
            UndoPlan {
                class: Reversibility::Clean,
                inverse: Some(("pywhisker".into(), args)),
                validate: None,
                note: "remove the KeyCredential (msDS-KeyCredentialLink) by captured DeviceID"
                    .into(),
            }
        }
        None => UndoPlan::manual(
            Reversibility::NeedsCapture,
            "remove the KeyCredential — DeviceID was not captured from the add output",
        ),
    }
}

/// Build the inverse plan for a journaled mutation.
pub fn undo_plan(record: &MutationRecord) -> UndoPlan {
    let a = &record.args;
    match record.tool.as_str() {
        // ── CLEAN: action-flip on the same forward args ──────────────
        "add_computer" => UndoPlan {
            class: Reversibility::Clean,
            inverse: Some(("add_computer".into(), with_override(a, "action", "delete"))),
            validate: astr(a, "computer_name").map(|name| {
                // After delete, `get object <name>$` should no longer return
                // the account — its name is absent from the read output.
                get_object_probe(a, &format!("{name}$"), "sAMAccountName", name)
            }),
            note: "delete the created machine account".into(),
        },
        "rbcd_write" => UndoPlan {
            class: Reversibility::Clean,
            inverse: Some(("rbcd_write".into(), with_override(a, "action", "remove"))),
            validate: astr(a, "target_computer").zip(astr(a, "attacker_sid")).map(
                |(target, sid)| {
                    get_object_probe(a, target, "msDS-AllowedToActOnBehalfOfOtherIdentity", sid)
                },
            ),
            note: "remove the RBCD delegation entry (msDS-AllowedToActOnBehalfOfOtherIdentity)".into(),
        },
        "dacl_edit" => UndoPlan {
            class: Reversibility::Clean,
            inverse: Some(("dacl_edit".into(), with_override(a, "action", "remove"))),
            validate: None,
            note: "remove the added ACE".into(),
        },
        "bloodyad_add_group_member" => UndoPlan {
            class: Reversibility::Clean,
            inverse: Some((
                "bloodyad_add_group_member".into(),
                with_override(a, "action", "remove"),
            )),
            validate: astr(a, "group").zip(astr(a, "target_user")).map(|(group, user)| {
                // After remove, the member list of the group must not contain
                // the target user.
                get_object_probe(a, group, "member", user)
            }),
            note: "remove the added group member".into(),
        },
        "bloodyad_add_genericall" => UndoPlan {
            class: Reversibility::Clean,
            inverse: Some((
                "bloodyad_add_genericall".into(),
                with_override(a, "action", "remove"),
            )),
            validate: None,
            note: "remove the GenericAll ACE".into(),
        },
        "addspn" => UndoPlan {
            class: Reversibility::Clean,
            inverse: Some(("addspn".into(), with_override(a, "action", "remove"))),
            validate: None,
            note: "remove the added SPN".into(),
        },
        "mssql_enable_xp_cmdshell" => UndoPlan {
            class: Reversibility::Clean,
            inverse: Some(("mssql_command".into(), xp_cmdshell_disable_args(a))),
            validate: None,
            note: "disable xp_cmdshell (sp_configure 'xp_cmdshell',0)".into(),
        },

        // ── HARD: reversible core but leaves residue needing a scrub ──
        // No clean tool inverse: the deployed bloodyAD exposes no `aclEntry`
        // remove (verified on-box), and SDProp has already propagated copies
        // of the ACE to every protected group — those must be scrubbed by hand.
        "adminsd_holder_add_ace" => UndoPlan::manual(
            Reversibility::Hard,
            "AdminSDHolder ACE — no clean tool inverse (deployed bloodyAD has no `remove aclEntry`), \
             and SDProp has already propagated copies to protected groups (Domain Admins, …); \
             manual scrub required",
        ),
        "pygpoabuse_immediate_task" | "sharpgpoabuse" => UndoPlan::manual(
            Reversibility::Hard,
            "no tool inverse — requires scripted SYSVOL (ScheduledTasks.xml) + LDAP \
             (gPCMachineExtensionNames, versionNumber) scrub; task may already have run as SYSTEM",
        ),
        "certipy_template_esc4" => UndoPlan::manual(
            Reversibility::Hard,
            "restore the certificate template from the -save-old JSON (needs the captured \
             template-config path)",
        ),

        // ── NEEDS-CAPTURE: blocked until forward-time state is journaled ──
        "pywhisker" => pywhisker_plan(record),
        "bloodyad_set_object_attr" => UndoPlan::manual(
            Reversibility::NeedsCapture,
            "restore the original attribute value — needs a read-before-write capture",
        ),
        "certipy_account_update" => UndoPlan::manual(
            Reversibility::NeedsCapture,
            "restore the original userPrincipalName — needs a read-before-write capture",
        ),
        "certipy_ca" => certipy_ca_plan(a),
        "nopac" | "krbrelayup" => UndoPlan::manual(
            Reversibility::NeedsCapture,
            "delete the machine account this created — needs the account name from tool output",
        ),

        // ── IMPOSSIBLE ───────────────────────────────────────────────
        "bloodyad_set_password" => UndoPlan::manual(
            Reversibility::Impossible,
            "original plaintext is unknowable — optional lab-reset to a baseline password",
        ),

        _ => UndoPlan::manual(
            Reversibility::Unsupported,
            "no known inverse for this tool",
        ),
    }
}

/// Build `mssql_command` args that disable xp_cmdshell, reusing the forward
/// call's auth/target keys and dropping any enable-specific keys.
fn xp_cmdshell_disable_args(forward: &Value) -> Value {
    let mut m = forward.as_object().cloned().unwrap_or_default();
    m.remove("query");
    m.insert(
        "query".into(),
        json!(
            "EXEC sp_configure 'show advanced options',1; RECONFIGURE; \
               EXEC sp_configure 'xp_cmdshell',0; RECONFIGURE;"
        ),
    );
    Value::Object(m)
}

/// `certipy_ca` covers several sub-actions; only `add-officer` has a clean
/// inverse (`remove-officer`). Others (backup, issue-request) are not target
/// mutations we auto-revert.
fn certipy_ca_plan(a: &Value) -> UndoPlan {
    let action = a
        .get("action")
        .and_then(Value::as_str)
        .or_else(|| a.get("ca_action").and_then(Value::as_str))
        .unwrap_or("");
    if action.contains("add-officer") || a.get("add_officer").is_some() {
        UndoPlan {
            class: Reversibility::Clean,
            inverse: Some((
                "certipy_ca".into(),
                with_override(a, "action", "remove-officer"),
            )),
            validate: None,
            note: "remove the CA officer we added".into(),
        }
    } else {
        UndoPlan::manual(
            Reversibility::Unsupported,
            "certipy_ca sub-action is not an auto-revertible mutation",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rec(tool: &str, args: Value) -> MutationRecord {
        MutationRecord::from_call("privesc", "t", tool, &args)
    }

    #[test]
    fn rbcd_write_reverses_with_action_remove() {
        let p = undo_plan(&rec(
            "rbcd_write",
            json!({ "target_ip": "192.168.58.240", "delegate_to": "dc01$", "action": "write" }),
        ));
        assert_eq!(p.class, Reversibility::Clean);
        let (tool, args) = p.inverse.unwrap();
        assert_eq!(tool, "rbcd_write");
        assert_eq!(args["action"], json!("remove"));
        // targeting keys carried over
        assert_eq!(args["delegate_to"], json!("dc01$"));
    }

    #[test]
    fn xp_cmdshell_reverses_via_mssql_command_disable() {
        let p = undo_plan(&rec(
            "mssql_enable_xp_cmdshell",
            json!({ "target": "192.168.58.30", "username": "sa" }),
        ));
        assert_eq!(p.class, Reversibility::Clean);
        let (tool, args) = p.inverse.unwrap();
        assert_eq!(tool, "mssql_command");
        assert!(args["query"].as_str().unwrap().contains("'xp_cmdshell',0"));
        assert_eq!(args["username"], json!("sa"));
    }

    #[test]
    fn password_reset_is_impossible_with_no_inverse() {
        let p = undo_plan(&rec("bloodyad_set_password", json!({ "target": "alice" })));
        assert_eq!(p.class, Reversibility::Impossible);
        assert!(p.inverse.is_none());
    }

    #[test]
    fn adminsdholder_is_hard_with_no_auto_inverse() {
        // Deployed bloodyAD has no `remove aclEntry`; SDProp propagation is
        // manual regardless — so we must NOT claim an automatic inverse.
        let p = undo_plan(&rec(
            "adminsd_holder_add_ace",
            json!({ "principal": "alice" }),
        ));
        assert_eq!(p.class, Reversibility::Hard);
        assert!(p.inverse.is_none());
    }

    #[test]
    fn certipy_ca_add_officer_reverses_to_remove_officer() {
        let p = undo_plan(&rec(
            "certipy_ca",
            json!({ "action": "add-officer", "ca": "contoso-CA" }),
        ));
        assert_eq!(p.class, Reversibility::Clean);
        assert_eq!(p.inverse.unwrap().1["action"], json!("remove-officer"));
    }

    #[test]
    fn unknown_tool_is_unsupported() {
        let p = undo_plan(&rec("nmap_scan", json!({})));
        assert_eq!(p.class, Reversibility::Unsupported);
    }

    #[test]
    fn rbcd_write_carries_a_readback_probe() {
        let p = undo_plan(&rec(
            "rbcd_write",
            json!({ "target_computer": "dc01$", "attacker_sid": "S-1-5-21-1-2-3-1105",
                    "domain": "contoso.local", "dc_ip": "192.168.58.240", "username": "alice" }),
        ));
        let probe = p
            .validate
            .expect("rbcd revert should have a read-back probe");
        assert_eq!(probe.tool, "bloodyad_get_object");
        assert_eq!(probe.args["target"], json!("dc01$"));
        assert_eq!(probe.expect_absent.as_deref(), Some("S-1-5-21-1-2-3-1105"));
    }

    #[test]
    fn pywhisker_is_needs_capture_without_hint() {
        let p = undo_plan(&rec(
            "pywhisker",
            json!({ "target_samaccountname": "dc01$" }),
        ));
        assert_eq!(p.class, Reversibility::NeedsCapture);
        assert!(p.inverse.is_none());
    }

    #[test]
    fn pywhisker_is_clean_with_captured_device_id() {
        let mut r = rec(
            "pywhisker",
            json!({ "target_samaccountname": "dc01$", "action": "add" }),
        );
        r.hint = Some(json!({ "device_id": "GUID-123" }));
        let p = undo_plan(&r);
        assert_eq!(p.class, Reversibility::Clean);
        let (tool, args) = p.inverse.unwrap();
        assert_eq!(tool, "pywhisker");
        assert_eq!(args["action"], json!("remove"));
        assert_eq!(args["device_id"], json!("GUID-123"));
    }
}
