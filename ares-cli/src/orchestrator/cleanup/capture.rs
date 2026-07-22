//! Forward-time state capture — extracts the prior state a faithful revert
//! needs and that is only observable at mutation time, out of the tool's own
//! output. Stored on [`MutationRecord::hint`](super::journal::MutationRecord).
//!
//! Only post-hoc captures (readable from the forward tool's stdout) live here.
//! Captures that require a read *before* the write (original UPN / attribute
//! value) belong in the executor itself and are out of scope for this pass.

use serde_json::{json, Value};

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
