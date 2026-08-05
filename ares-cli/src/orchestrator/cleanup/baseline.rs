//! The range's provisioned passwords, for restoring accounts a reset overwrote.
//!
//! `bloodyad_set_password` was classed `Impossible` because the account's
//! original plaintext is unknowable from inside an operation — by construction,
//! `auto_dacl_abuse` only resets a target whose material state does *not*
//! already hold. But the range knows: GOAD provisions every user from a lab
//! config, so the pre-op password for any account an operation can reset is
//! sitting in that file the whole time.
//!
//! Pointing `ARES_LAB_BASELINE_CONFIG` at it turns the reset from an
//! unrecoverable mutation into a `Clean` one — teardown sets the account back
//! to exactly what the range provisioned.
//!
//! Deliberately read at runtime from a path outside this repo. No lab
//! credential is ever compiled in, and an unset var simply leaves the mutation
//! classed as it was before.

use std::collections::HashMap;
use std::sync::OnceLock;

use serde_json::Value;
use tracing::{info, warn};

/// Path to a GOAD-style lab config (`{"lab":{"domains":{…}}}`).
pub const BASELINE_CONFIG_ENV: &str = "ARES_LAB_BASELINE_CONFIG";

/// Optional deployment overlay merged over the base config.
pub const BASELINE_OVERLAY_ENV: &str = "ARES_LAB_BASELINE_OVERLAY";

/// `(domain, sam)` both lowercased → provisioned password.
type PasswordMap = HashMap<(String, String), String>;

static BASELINE: OnceLock<PasswordMap> = OnceLock::new();

/// The password the range provisioned for `sam` in `domain`, if a lab config
/// is configured and names that account.
pub fn provisioned_password(domain: &str, sam: &str) -> Option<String> {
    let sam = sam.trim().trim_end_matches('$');
    BASELINE
        .get_or_init(load)
        .get(&(domain.trim().to_lowercase(), sam.to_lowercase()))
        .cloned()
}

fn load() -> PasswordMap {
    let Ok(path) = std::env::var(BASELINE_CONFIG_ENV) else {
        return PasswordMap::new();
    };
    let mut map = match read_users(&path) {
        Ok(m) => m,
        Err(e) => {
            warn!(
                path = %path,
                err = %e,
                "Lab baseline config unreadable — password resets stay classed IMPOSSIBLE and \
                 teardown will report them for manual restore"
            );
            return PasswordMap::new();
        }
    };
    if let Ok(overlay) = std::env::var(BASELINE_OVERLAY_ENV) {
        match read_users(&overlay) {
            Ok(o) => map.extend(o),
            Err(e) => {
                warn!(path = %overlay, err = %e, "Lab baseline overlay unreadable — using base config alone")
            }
        }
    }
    info!(
        accounts = map.len(),
        "Loaded lab baseline passwords — password resets are now restorable at teardown"
    );
    map
}

/// Flatten `lab.domains.<domain>.users.<sam>.password` into the lookup map.
fn read_users(path: &str) -> anyhow::Result<PasswordMap> {
    let raw = std::fs::read_to_string(path)?;
    let doc: Value = serde_json::from_str(&raw)?;
    let mut map = PasswordMap::new();

    let Some(domains) = doc
        .get("lab")
        .and_then(|l| l.get("domains"))
        .and_then(Value::as_object)
    else {
        anyhow::bail!("no lab.domains object");
    };

    for (domain, body) in domains {
        let Some(users) = body.get("users").and_then(Value::as_object) else {
            continue;
        };
        for (sam, user) in users {
            let Some(password) = user.get("password").and_then(Value::as_str) else {
                continue;
            };
            if password.is_empty() {
                continue;
            }
            map.insert(
                (domain.to_lowercase(), sam.trim().to_lowercase()),
                password.to_string(),
            );
        }
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn write(dir: &std::path::Path, name: &str, body: Value) -> String {
        let p = dir.join(name);
        std::fs::write(&p, body.to_string()).unwrap();
        p.to_string_lossy().into_owned()
    }

    #[test]
    fn read_users_flattens_every_domain() {
        let dir = std::env::temp_dir().join(format!("ares-baseline-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = write(
            &dir,
            "config.json",
            json!({"lab": {"domains": {
                "contoso.local": {"users": {
                    "alice": {"password": "Provisioned1!"},
                    "bob": {"password": "Provisioned2!"},
                }},
                "FABRIKAM.local": {"users": {"carol": {"password": "Provisioned3!"}}},
            }}}),
        );

        let map = read_users(&path).unwrap();
        assert_eq!(map.len(), 3);
        assert_eq!(
            map.get(&("contoso.local".into(), "alice".into())).unwrap(),
            "Provisioned1!"
        );
        // Domain keys are lowercased so a config's casing cannot miss a lookup.
        assert_eq!(
            map.get(&("fabrikam.local".into(), "carol".into())).unwrap(),
            "Provisioned3!"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn read_users_skips_entries_without_a_password() {
        let dir = std::env::temp_dir().join(format!("ares-baseline-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = write(
            &dir,
            "config.json",
            json!({"lab": {"domains": {"contoso.local": {"users": {
                "alice": {"password": "Provisioned1!"},
                "svc": {"description": "no password field"},
                "blank": {"password": ""},
            }}}}}),
        );

        let map = read_users(&path).unwrap();
        assert_eq!(map.len(), 1);
        assert!(map.contains_key(&("contoso.local".into(), "alice".into())));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn read_users_rejects_a_document_that_is_not_a_lab_config() {
        let dir = std::env::temp_dir().join(format!("ares-baseline-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = write(&dir, "config.json", json!({"something": "else"}));
        assert!(read_users(&path).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }
}
