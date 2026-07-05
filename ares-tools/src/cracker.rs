use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;
use serde_json::Value;

use crate::args::{optional_bool, optional_i64, optional_str, required_str};
use crate::executor::CommandBuilder;
use crate::ToolOutput;

/// Monotonic sequence for per-crack-job session names. Combined with the PID it
/// yields a name that no other in-flight or prior crack job can reuse.
static CRACK_SESSION_SEQ: AtomicU64 = AtomicU64::new(0);

/// A process-unique session name for a crack job (`ares-<tool>-<pid>-<seq>`).
///
/// hashcat and John both key their restore/`.rec`/log files off the session
/// name and default to a single shared name. A crack job that is SIGKILLed on
/// timeout leaves that shared restore file behind; the next job under the same
/// name inherits the stale state and refuses to start ("already an instance",
/// GPU idle at 0%). A per-job name plus `--restore-disable` removes the shared
/// mutable state entirely, so neither a concurrent job nor a dead one's
/// leftovers can wedge a fresh run.
fn next_crack_session(tool: &str) -> String {
    let seq = CRACK_SESSION_SEQ.fetch_add(1, Ordering::Relaxed);
    format!("ares-{tool}-{}-{}", std::process::id(), seq)
}

/// Default wordlists tried in order.
const DEFAULT_WORDLISTS: &[&str] = &[
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/wordlists/seclists/Passwords/Common-Credentials/Pwdb_top-10000000.txt",
];
const DEFAULT_MAX_TIME_MINUTES: i64 = 20;

/// Default hashcat rules tried during the rules phase.
/// best64 covers common mutations (capitalize, suffix digits/symbols);
/// d3ad0ne is broader and catches passwords like MyPrettyPassword123#.
const DEFAULT_RULES: &[&str] = &[
    "/usr/share/hashcat/rules/best64.rule",
    "/usr/share/hashcat/rules/d3ad0ne.rule",
];

/// Auto-detect hashcat mode from a hash, honoring the embedded Kerberos etype.
///
/// The etype number in `$krb5tgs$<etype>$…` / `$krb5asrep$<etype>$…` selects the
/// mode. Mapping every Kerberos hash to the RC4 mode (13100/18200) is wrong for
/// the AES tickets impacket-GetUserSPNs / GetNPUsers return whenever the target
/// account has AES keys — which is the AD/GOAD default. Feeding an AES (etype
/// 17/18) hash to an RC4 mode makes hashcat reject it with a token-length error,
/// so the hash never cracks even when its plaintext is in the wordlist.
///
/// - TGS-REP (Kerberoast):  etype 23 -> 13100, 17 -> 19600, 18 -> 19700
/// - AS-REP (AS-REP roast): 18200 (impacket only emits the RC4 `$krb5asrep$`
///   form; hashcat's AES modes 19800/19900 are a different `$krb5pa$` primitive)
/// - NetNTLMv2 (`USER::DOMAIN:CHALLENGE:NT_PROOF:BLOB`, Responder / PetitPotam
///   captures) -> 5600. Without this branch a captured machine-account hash is
///   handed to hashcat as mode 1000 (NTLM 32-hex) and rejected as malformed,
///   dropping the crack on the floor.
/// - Otherwise -> 1000 (NTLM)
fn detect_hashcat_mode(hash_value: &str) -> i64 {
    // The etype is the integer field immediately after the `$krb5tgs$` prefix.
    fn etype(rest: &str) -> Option<u32> {
        rest.split('$').next()?.parse().ok()
    }
    if let Some(rest) = hash_value.strip_prefix("$krb5tgs$") {
        match etype(rest) {
            Some(17) => 19600,
            Some(18) => 19700,
            _ => 13100, // etype 23 (RC4) and any unrecognized etype
        }
    } else if hash_value.starts_with("$krb5asrep$") {
        18200
    } else if is_netntlmv2_format(hash_value) {
        5600
    } else {
        1000
    }
}

/// Structural check for NetNTLMv2 hashcat-5600 layout. Cheap, no-allocation.
/// Format: `USER::DOMAIN:CHALLENGE(16hex):NT_PROOF(32hex):BLOB(>=16hex)`.
fn is_netntlmv2_format(s: &str) -> bool {
    let s = s.trim();
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return false;
    }
    // parts[0] = username (non-empty), parts[1] = "" (the `::`),
    // parts[2] = domain (may be empty), parts[3..6] hex with required lengths.
    if parts[0].is_empty() || !parts[1].is_empty() {
        return false;
    }
    let challenge = parts[3];
    let nt_proof = parts[4];
    let blob = parts[5];
    challenge.len() == 16
        && challenge.chars().all(|c| c.is_ascii_hexdigit())
        && nt_proof.len() == 32
        && nt_proof.chars().all(|c| c.is_ascii_hexdigit())
        && blob.len() >= 16
        && blob.chars().all(|c| c.is_ascii_hexdigit())
}

/// Build a dynamic wordlist from known usernames.
///
/// Generates username-derived password candidates: lowercase, capitalized, uppercased,
/// with common suffixes ("", "1", "123", "!", "2024", "2025", "2026").
fn build_dynamic_wordlist(known_usernames: &[&str]) -> Option<tempfile::NamedTempFile> {
    if known_usernames.is_empty() {
        return None;
    }
    let suffixes = [
        "", "1", "123", "!", "#", "@", "1!", "123!", "123#", "2024", "2025", "2026",
    ];
    let mut file = tempfile::NamedTempFile::new().ok()?;
    for username in known_usernames {
        let base_variants = [
            username.to_lowercase(),
            capitalize(username),
            username.to_uppercase(),
        ];
        for variant in &base_variants {
            for suffix in &suffixes {
                let _ = writeln!(file, "{variant}{suffix}");
            }
        }
        // Also try first.last split candidates
        if let Some((first, last)) = username.split_once('.') {
            for part in [first, last] {
                for suffix in &suffixes {
                    let _ = writeln!(file, "{}{suffix}", capitalize(part));
                    let _ = writeln!(file, "{}{suffix}", part.to_lowercase());
                }
            }
        }
    }
    file.flush().ok()?;
    Some(file)
}

fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(c) => c.to_uppercase().to_string() + &chars.as_str().to_lowercase(),
    }
}

/// Crack a hash using hashcat with a wordlist attack.
///
/// Tries multiple wordlists in order (rockyou, seclists). When `use_dynamic_wordlist`
/// is true (default), also prepends a username-derived candidate list.
pub async fn crack_with_hashcat(args: &Value) -> Result<ToolOutput> {
    let hash_value = required_str(args, "hash_value")?;
    let explicit_wordlist = optional_str(args, "wordlist_path");
    let explicit_rules = optional_str(args, "rules_file");
    let max_time_minutes = optional_i64(args, "max_time_minutes")
        .unwrap_or(DEFAULT_MAX_TIME_MINUTES)
        .max(DEFAULT_MAX_TIME_MINUTES);
    let max_time_secs = max_time_minutes * 60;
    let use_dynamic = optional_bool(args, "use_dynamic_wordlist").unwrap_or(true);

    let mode =
        optional_i64(args, "hashcat_mode").unwrap_or_else(|| detect_hashcat_mode(hash_value));

    // Serialize the whole crack job through the single hashcat slot. hashcat
    // owns the GPU as one instance; two jobs collide on the shared session and
    // the loser bails leaving the GPU idle. The orchestrator serializes crack
    // *tasks*, but the agent loop dispatches every tool call in one LLM turn
    // concurrently, so two `crack_with_hashcat` calls in a single turn would
    // otherwise race. Held until this function returns (drop releases it).
    let _hashcat_permit = crate::concurrency::acquire_hashcat_permit().await;

    // Per-job session so a prior job SIGKILLed on timeout can't leave a stale
    // restore file that wedges this run. `--restore-disable` (below) stops
    // hashcat writing one at all; the unique name is belt-and-suspenders for
    // any hashcat run that overlaps this one on the same box.
    let session = next_crack_session("hc");

    // Write hash to a temp file that persists until command completes.
    let mut hash_file = tempfile::NamedTempFile::new()?;
    hash_file.write_all(hash_value.as_bytes())?;
    hash_file.flush()?;

    let hash_path = hash_file.path().to_string_lossy().to_string();

    // Build wordlist order: explicit wordlist OR default cascade
    let wordlists: Vec<&str> = if let Some(wl) = explicit_wordlist {
        vec![wl]
    } else {
        DEFAULT_WORDLISTS
            .iter()
            .filter(|p| std::path::Path::new(p).exists())
            .copied()
            .collect()
    };

    // Optional dynamic wordlist from known_usernames JSON array
    let dynamic_file = if use_dynamic {
        let usernames: Vec<&str> = args
            .get("known_usernames")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<&str>>())
            .unwrap_or_default();
        build_dynamic_wordlist(&usernames)
    } else {
        None
    };

    // Build rules list: explicit rule OR default cascade
    let rules: Vec<&str> = if let Some(r) = explicit_rules {
        vec![r]
    } else {
        DEFAULT_RULES
            .iter()
            .filter(|p| std::path::Path::new(p).exists())
            .copied()
            .collect()
    };

    // Split time budget: 60% for straight wordlist passes, 40% for rules passes.
    // This ensures rules get meaningful runtime without starving the wordlist phase.
    let has_rules = !rules.is_empty() && !wordlists.is_empty();
    let wordlist_budget = if has_rules {
        max_time_secs * 60 / 100
    } else {
        max_time_secs
    };
    let rules_budget = max_time_secs - wordlist_budget;

    let total_lists = wordlists.len() + if dynamic_file.is_some() { 1 } else { 0 };
    let per_list_secs = if total_lists > 0 {
        wordlist_budget / total_lists as i64
    } else {
        wordlist_budget
    }
    .max(60); // At least 60s per list

    let mut all_output = String::new();

    // Try dynamic wordlist first (username-derived candidates = most likely)
    if let Some(ref dyn_file) = dynamic_file {
        let dyn_path = dyn_file.path().to_string_lossy().to_string();
        let timeout_secs = (per_list_secs + 60) as u64;
        let result = CommandBuilder::new("hashcat")
            .flag("-m", mode.to_string())
            .arg("-a")
            .arg("0")
            .arg(&hash_path)
            .arg(&dyn_path)
            .flag("--runtime", per_list_secs.to_string())
            .flag("--session", &session)
            .arg("--restore-disable")
            .arg("--force")
            .timeout_secs(timeout_secs)
            .execute()
            .await;
        if let Ok(out) = result {
            all_output.push_str(&out.combined());
            all_output.push('\n');
        }
    }

    // Try each wordlist (straight attack, no rules)
    for wordlist in &wordlists {
        let timeout_secs = (per_list_secs + 60) as u64;
        let result = CommandBuilder::new("hashcat")
            .flag("-m", mode.to_string())
            .arg("-a")
            .arg("0")
            .arg(&hash_path)
            .arg(*wordlist)
            .flag("--runtime", per_list_secs.to_string())
            .flag("--session", &session)
            .arg("--restore-disable")
            .arg("--force")
            .timeout_secs(timeout_secs)
            .execute()
            .await;
        if let Ok(out) = result {
            all_output.push_str(&out.combined());
            all_output.push('\n');
        }
    }

    // Rules-based attack: rockyou + mutation rules (catches passwords like
    // MyPrettyPassword123# that are rule-derived variants of common words).
    if has_rules {
        let rules_per_combo = if !rules.is_empty() {
            (rules_budget / rules.len() as i64).max(60)
        } else {
            rules_budget
        };
        // Use only the primary wordlist (rockyou) for rules — applying rules
        // to all wordlists would blow the time budget.
        let rules_wordlist = wordlists.first().copied().unwrap_or(DEFAULT_WORDLISTS[0]);
        for rule in &rules {
            let timeout_secs = (rules_per_combo + 60) as u64;
            let result = CommandBuilder::new("hashcat")
                .flag("-m", mode.to_string())
                .arg("-a")
                .arg("0")
                .arg(&hash_path)
                .arg(rules_wordlist)
                .flag("-r", rule.to_string())
                .flag("--runtime", rules_per_combo.to_string())
                .flag("--session", &session)
                .arg("--restore-disable")
                .arg("--force")
                .timeout_secs(timeout_secs)
                .execute()
                .await;
            if let Ok(out) = result {
                all_output.push_str(&out.combined());
                all_output.push('\n');
            }
        }
    }

    // Always run `hashcat --show` to retrieve cracked results.
    // This handles both freshly cracked hashes and potfile hits
    // (hashcat exits code 1 when all hashes are already cracked,
    // printing no cracked output — --show retrieves them).
    let show_result = CommandBuilder::new("hashcat")
        .flag("-m", mode.to_string())
        .arg(&hash_path)
        .arg("--show")
        .flag("--session", &session)
        .arg("--restore-disable")
        .arg("--force")
        .timeout_secs(30)
        .execute()
        .await?;

    // Combine all output so the caller can see the full run
    Ok(ToolOutput {
        stdout: format!(
            "{all_output}\n--- hashcat --show ---\n{}",
            show_result.stdout
        ),
        stderr: show_result.stderr,
        exit_code: show_result.exit_code,
        success: show_result.success,
    })
}

/// Crack a hash using John the Ripper with a wordlist attack.
///
/// Tries multiple wordlists in order. After john finishes, runs
/// `john --show` to retrieve cracked results.
pub async fn crack_with_john(args: &Value) -> Result<ToolOutput> {
    let hash_value = required_str(args, "hash_value")?;
    let hash_format = optional_str(args, "hash_format");
    let explicit_wordlist = optional_str(args, "wordlist_path");
    let max_time_minutes = optional_i64(args, "max_time_minutes")
        .unwrap_or(DEFAULT_MAX_TIME_MINUTES)
        .max(DEFAULT_MAX_TIME_MINUTES);
    let max_time_secs = max_time_minutes * 60;
    let use_dynamic = optional_bool(args, "use_dynamic_wordlist").unwrap_or(true);

    // Write hash to a temp file that persists until both commands complete.
    let mut hash_file = tempfile::NamedTempFile::new()?;
    hash_file.write_all(hash_value.as_bytes())?;
    hash_file.flush()?;

    let hash_path = hash_file.path().to_string_lossy().to_string();
    let format_arg = hash_format.map(|f| format!("--format={f}"));

    // Per-job John session so concurrent (or crash-leftover) runs don't collide
    // on the default `.rec` restore file. `--show` reads the shared pot and
    // needs no session.
    let session_arg = format!("--session={}", next_crack_session("jtr"));

    // Build wordlist order
    let wordlists: Vec<&str> = if let Some(wl) = explicit_wordlist {
        vec![wl]
    } else {
        DEFAULT_WORDLISTS
            .iter()
            .filter(|p| std::path::Path::new(p).exists())
            .copied()
            .collect()
    };

    // Optional dynamic wordlist
    let dynamic_file = if use_dynamic {
        let usernames: Vec<&str> = args
            .get("known_usernames")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<&str>>())
            .unwrap_or_default();
        build_dynamic_wordlist(&usernames)
    } else {
        None
    };

    let total_lists = wordlists.len() + if dynamic_file.is_some() { 1 } else { 0 };
    let per_list_secs = if total_lists > 0 {
        max_time_secs / total_lists as i64
    } else {
        max_time_secs
    }
    .max(60);

    let mut all_output = String::new();

    // Dynamic wordlist first
    if let Some(ref dyn_file) = dynamic_file {
        let dyn_path = dyn_file.path().to_string_lossy().to_string();
        let timeout_secs = (per_list_secs + 60) as u64;
        let mut cmd = CommandBuilder::new("john")
            .arg(&hash_path)
            .arg(format!("--wordlist={dyn_path}"))
            .arg(format!("--max-run-time={per_list_secs}"))
            .arg(&session_arg);
        if let Some(ref fa) = format_arg {
            cmd = cmd.arg(fa);
        }
        if let Ok(out) = cmd.timeout_secs(timeout_secs).execute().await {
            all_output.push_str(&out.combined());
            all_output.push('\n');
        }
    }

    // Try each wordlist
    for wordlist in &wordlists {
        let timeout_secs = (per_list_secs + 60) as u64;
        let mut cmd = CommandBuilder::new("john")
            .arg(&hash_path)
            .arg(format!("--wordlist={wordlist}"))
            .arg(format!("--max-run-time={per_list_secs}"))
            .arg(&session_arg);
        if let Some(ref fa) = format_arg {
            cmd = cmd.arg(fa);
        }
        if let Ok(out) = cmd.timeout_secs(timeout_secs).execute().await {
            all_output.push_str(&out.combined());
            all_output.push('\n');
        }
    }

    // Run `john --show` to get the cracked results.
    let mut show_cmd = CommandBuilder::new("john").arg("--show").arg(&hash_path);
    if let Some(ref fa) = format_arg {
        show_cmd = show_cmd.arg(fa);
    }
    let show_result = show_cmd.timeout_secs(30).execute().await?;

    Ok(ToolOutput {
        stdout: format!("{all_output}\n--- john --show ---\n{}", show_result.stdout),
        stderr: show_result.stderr,
        exit_code: show_result.exit_code,
        success: show_result.success,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::mock;
    use serde_json::json;

    #[test]
    fn detect_hashcat_mode_krb5tgs() {
        assert_eq!(detect_hashcat_mode("$krb5tgs$23$*user"), 13100);
    }

    #[test]
    fn detect_hashcat_mode_krb5tgs_aes() {
        // impacket-GetUserSPNs returns AES tickets for AES-capable accounts
        // (the AD/GOAD default). etype 17/18 must map to the AES TGS modes, not
        // RC4's 13100 — otherwise hashcat rejects the hash and it never cracks.
        // AES layout has no `*` after the etype: `$krb5tgs$17$user$realm$spn*$…`.
        assert_eq!(
            detect_hashcat_mode("$krb5tgs$17$user$realm$spn*$aabb$ccdd"),
            19600
        );
        assert_eq!(
            detect_hashcat_mode("$krb5tgs$18$user$realm$spn*$aabb$ccdd"),
            19700
        );
    }

    #[test]
    fn detect_hashcat_mode_krb5asrep() {
        // impacket AS-REP roasting emits the RC4 `$krb5asrep$` form regardless
        // of etype; mode 18200 is the only AS-REP mode that consumes it.
        assert_eq!(detect_hashcat_mode("$krb5asrep$23$user"), 18200);
    }

    #[test]
    fn detect_hashcat_mode_netntlmv2() {
        // Responder-style capture: user::DOMAIN:16hex:32hex:>=16hex
        let h = "dc01$::CONTOSO:1122334455667788:9c8e64ac5db4e4a72b1cd2e1cd2e1cd2:0101000000000000aabbccdd";
        assert_eq!(detect_hashcat_mode(h), 5600);

        // Missing the `::` between user and domain → not NetNTLMv2.
        let not = "dc01$:CONTOSO:1122334455667788:9c8e64ac5db4e4a72b1cd2e1cd2e1cd2:0101000000000000aabbccdd";
        assert_ne!(detect_hashcat_mode(not), 5600);

        // Wrong CHALLENGE length → not NetNTLMv2.
        let not2 = "dc01$::CONTOSO:11223344556677:9c8e64ac5db4e4a72b1cd2e1cd2e1cd2:0101000000000000aabbccdd";
        assert_ne!(detect_hashcat_mode(not2), 5600);

        // bare NTLM (NT only) still falls back to 1000.
        assert_eq!(
            detect_hashcat_mode("aad3b435b51404eeaad3b435b51404ee"),
            1000,
        );
    }

    #[test]
    fn detect_hashcat_mode_ntlm() {
        assert_eq!(detect_hashcat_mode("aad3b435b51404ee"), 1000);
    }

    #[test]
    fn capitalize_normal() {
        assert_eq!(capitalize("hello"), "Hello");
    }

    #[test]
    fn capitalize_empty() {
        assert_eq!(capitalize(""), "");
    }

    #[test]
    fn capitalize_single_char() {
        assert_eq!(capitalize("a"), "A");
    }

    #[test]
    fn build_dynamic_wordlist_empty_usernames() {
        assert!(build_dynamic_wordlist(&[]).is_none());
    }

    #[test]
    fn build_dynamic_wordlist_creates_file() {
        let file = build_dynamic_wordlist(&["admin", "john.smith"]);
        assert!(file.is_some());
        let file = file.unwrap();
        let contents = std::fs::read_to_string(file.path()).unwrap();
        assert!(contents.contains("admin"));
        assert!(contents.contains("Admin"));
        assert!(contents.contains("ADMIN"));
        assert!(contents.contains("admin123"));
        assert!(contents.contains("John"));
        assert!(contents.contains("smith"));
    }

    #[test]
    fn default_wordlists_defined() {
        assert!(!DEFAULT_WORDLISTS.is_empty());
    }

    #[test]
    fn default_rules_defined() {
        assert!(!DEFAULT_RULES.is_empty());
    }

    #[tokio::test]
    async fn crack_with_hashcat_executes() {
        mock::push(mock::success()); // --show at the end
        let args = json!({
            "hash_value": "aad3b435b51404eeaad3b435b51404ee",
            "use_dynamic_wordlist": false
        });
        assert!(crack_with_hashcat(&args).await.is_ok());
    }

    #[tokio::test]
    async fn crack_with_hashcat_with_explicit_wordlist() {
        mock::push(mock::success()); // wordlist pass
        mock::push(mock::success()); // --show
        let args = json!({
            "hash_value": "$krb5tgs$23$*user",
            "wordlist_path": "/tmp/wordlist.txt",
            "use_dynamic_wordlist": false
        });
        assert!(crack_with_hashcat(&args).await.is_ok());
    }

    #[tokio::test]
    async fn crack_with_hashcat_with_dynamic_wordlist() {
        mock::push(mock::success()); // dynamic wordlist pass
        mock::push(mock::success()); // --show
        let args = json!({
            "hash_value": "aad3b435b51404ee",
            "use_dynamic_wordlist": true,
            "known_usernames": ["admin", "john.smith"]
        });
        assert!(crack_with_hashcat(&args).await.is_ok());
    }

    #[tokio::test]
    async fn crack_with_john_executes() {
        mock::push(mock::success()); // --show
        let args = json!({
            "hash_value": "aad3b435b51404ee",
            "use_dynamic_wordlist": false
        });
        assert!(crack_with_john(&args).await.is_ok());
    }

    #[tokio::test]
    async fn crack_with_john_with_format() {
        mock::push(mock::success()); // --show
        let args = json!({
            "hash_value": "$krb5asrep$23$user",
            "hash_format": "krb5asrep",
            "use_dynamic_wordlist": false
        });
        assert!(crack_with_john(&args).await.is_ok());
    }

    #[tokio::test]
    async fn crack_with_john_with_dynamic_wordlist() {
        mock::push(mock::success()); // dynamic pass
        mock::push(mock::success()); // --show
        let args = json!({
            "hash_value": "aad3b435b51404ee",
            "use_dynamic_wordlist": true,
            "known_usernames": ["admin"]
        });
        assert!(crack_with_john(&args).await.is_ok());
    }
}
