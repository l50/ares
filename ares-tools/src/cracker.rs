use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;
use serde_json::Value;
use tracing::info;

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

/// Runtime cap for the known-plaintext reuse pass. The seed list — every
/// plaintext the op has already recovered plus this box's hashcat potfile — is
/// tiny (a few hundred entries at most), so hashcat exhausts it in well under a
/// second even at AES256 ticket speed and this cap almost never binds. Kept
/// separate from (and run before) the main wordlist/rules budget so reusing a
/// known password never steals grind time from a genuinely new hash.
const KNOWN_PW_PASS_SECS: i64 = 120;

/// Default hashcat rules tried during the rules phase.
/// best64 covers common mutations (capitalize, suffix digits/symbols);
/// d3ad0ne is broader and catches passwords like MyPrettyPassword123#.
const DEFAULT_RULES: &[&str] = &[
    "/usr/share/hashcat/rules/best64.rule",
    "/usr/share/hashcat/rules/d3ad0ne.rule",
];

/// `nice` adjustment for hashcat passes (negative = higher CPU priority).
///
/// During an op the box runs the whole worker fleet (impacket, certipy,
/// bloodhound, coercer, …) and load routinely exceeds core count. That starves
/// hashcat's host-side candidate-feeding thread, so the GPU sits idle between
/// bursts (observed live: one hashcat, GPU at 0% util, load 12.9 on 8 cores).
/// For the one expensive mode — AES kerberoast, 19700, ~1000x slower per
/// candidate than RC4/NTLM — the throughput collapse means a deep-in-rockyou
/// plaintext is never reached before the pass's `--runtime` cap, so the crack
/// "completes" `no_plaintext` even though the password is in the wordlist (0
/// AES kerberoast cracks across 11 ops, while the same hash cracks in ~1 min on
/// an idle box). Elevating hashcat's priority keeps the GPU fed. Overridable via
/// `ARES_HASHCAT_NICE`. A negative value needs root (the fleet runs as root);
/// without privilege GNU `nice` warns and still runs hashcat at normal priority,
/// so this is safe everywhere and simply a no-op without privilege.
const HASHCAT_NICE: &str = "-15";

/// A hashcat `CommandBuilder` wrapped in `nice` for elevated CPU priority.
/// Every hashcat pass goes through this so none of them get CPU-starved.
fn niced_hashcat() -> CommandBuilder {
    let adj = std::env::var("ARES_HASHCAT_NICE").unwrap_or_else(|_| HASHCAT_NICE.to_string());
    CommandBuilder::new("nice")
        .arg("-n")
        .arg(adj)
        .arg("hashcat")
}

/// Default wall-clock floor (minutes) for AES kerberoast crack jobs. AES256/128 TGS
/// (modes 19700/19600) are ~1000x slower per candidate than RC4/NTLM, so on a
/// loaded box they need a larger budget to still reach a deep plaintext before
/// each pass's `--runtime` cap. Overridable with
/// `ARES_AES_KERBEROAST_MAX_TIME_MINUTES` when a range needs deeper grinding.
const DEFAULT_AES_KERBEROAST_MAX_TIME_MINUTES: i64 = 45;

fn aes_kerberoast_max_time_minutes() -> i64 {
    std::env::var("ARES_AES_KERBEROAST_MAX_TIME_MINUTES")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|&n| n >= DEFAULT_MAX_TIME_MINUTES)
        .unwrap_or(DEFAULT_AES_KERBEROAST_MAX_TIME_MINUTES)
}

/// Modes whose per-candidate cost is high enough to warrant the larger budget.
fn is_expensive_aes_mode(mode: i64) -> bool {
    matches!(mode, 19600 | 19700)
}

/// Whether `hash_value` is an AES Kerberos TGS ticket (etype 17/18). John the
/// Ripper's `krb5tgs` format is RC4 (etype-23) only and rejects these outright
/// ("No password hashes loaded"), so a john fallback on an AES kerberoast ticket
/// burns a crack slot on a guaranteed miss and emits a confusing parse error.
/// hashcat modes 19600/19700 are the only path that loads them.
fn is_aes_krb5tgs(hash_value: &str) -> bool {
    hash_value
        .strip_prefix("$krb5tgs$")
        .and_then(|rest| rest.split('$').next())
        .and_then(|e| e.parse::<u32>().ok())
        .is_some_and(|e| e == 17 || e == 18)
}

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

/// Resolve the hashcat mode for a crack job, letting the hash's own contents
/// override a wrong caller-supplied mode.
///
/// The Kerberos etype embedded in `$krb5tgs$<etype>$` / `$krb5asrep$<etype>$` is
/// ground truth: an etype-18 ticket is AES256 and only mode 19700 can parse it.
/// The LLM cracker, however, is schema-nudged toward `hashcat_mode=13100` (RC4)
/// and passes it for *every* Kerberos hash — so hashcat rejects the AES tickets
/// impacket returns by default with "Separator unmatched", and the hash never
/// cracks even when its plaintext is in the wordlist. For Kerberos hashes we
/// therefore ignore the override and trust the etype. An explicit mode still
/// applies to non-Kerberos hashes, where auto-detect only knows the NTLM
/// fallback and the caller may legitimately pick a better mode (5600 NetNTLMv2,
/// 3000 LM, …).
fn resolve_hashcat_mode(explicit: Option<i64>, hash_value: &str) -> i64 {
    let is_kerberos = hash_value.starts_with("$krb5tgs$") || hash_value.starts_with("$krb5asrep$");
    if is_kerberos {
        detect_hashcat_mode(hash_value)
    } else {
        explicit.unwrap_or_else(|| detect_hashcat_mode(hash_value))
    }
}

/// The hashcat `-m` mode a crack job will run for `hash_value`, with no explicit
/// override — i.e. exactly what [`resolve_hashcat_mode`] picks for an
/// automation-dispatched (non-LLM) crack. Exposed so the orchestrator can group
/// roastable hashes into same-mode batches: one hashcat run over a file of many
/// same-mode tickets cracks every crackable one in the first wordlist pass,
/// instead of serializing a full crack budget per ticket. Grouping by this
/// function guarantees every hash in a batch resolves to the mode the tool then
/// runs off the batch's first line.
pub fn hashcat_mode_for(hash_value: &str) -> i64 {
    resolve_hashcat_mode(None, hash_value)
}

/// Distill hashcat's combined pass output into a one-word signal for the crack
/// verdict log. A `no_plaintext` result is otherwise undiagnosable: the raw
/// hashcat output never reaches the role log (only this structured line does),
/// so a crack that failed because the GPU kernel never ran (`device_error`)
/// looks identical to an honest wordlist sweep that found nothing (`exhausted`).
/// That distinction is the whole ballgame for AES kerberoast (mode 19700), whose
/// crackable tickets have repeatedly come back `no_plaintext` in ops while
/// cracking in seconds when re-run by hand — a runtime/environment failure, not
/// an absent password. Ordered most-severe first so a device fault wins over a
/// later "Exhausted" from an earlier cheap pass.
fn hashcat_run_signal(output: &str) -> &'static str {
    if output.contains("Not enough allocatable device memory")
        || output.contains("clBuildProgram")
        || output.contains("cuModuleLoad")
        || output.contains("No devices found")
        || output.contains("self-test failed")
    {
        "device_error"
    } else if output.contains("already an instance") || output.contains("is already running") {
        "session_conflict"
    } else if output.contains("Token length exception") || output.contains("Separator unmatched") {
        "hash_rejected"
    } else if output.contains("Cracked") {
        "cracked"
    } else if output.contains("Exhausted") {
        "exhausted"
    } else if output.contains("Stopped") || output.contains("Aborted") {
        "stopped_early"
    } else {
        // No run status at all: the pass was almost certainly killed (timeout /
        // signal) before hashcat printed a verdict — e.g. a slow AES kernel
        // build that outran the pass timeout, or a wedged GPU.
        "no_status"
    }
}

/// Short label for the hash primitive, for structured crack-result logs.
fn hash_kind(hash_value: &str) -> &'static str {
    if hash_value.starts_with("$krb5tgs$") {
        "krb5tgs"
    } else if hash_value.starts_with("$krb5asrep$") {
        "krb5asrep"
    } else {
        "ntlm-or-other"
    }
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

/// Resolve this box's hashcat potfile — the persistent, cross-op record of
/// every plaintext hashcat has recovered. We read hashcat's DEFAULT location
/// (and never pass `--potfile-path`, so the existing potfile keeps accumulating
/// exactly as before) so a password cracked in a prior op, or recovered from a
/// different-etype ticket for the same account, can be reused as a candidate.
///
/// hashcat's implicit potfile auto-matches only *identical* hash strings; an
/// AS-REP/TGS ticket re-issued for the same account has fresh ciphertext (and
/// may be a different etype), so it never hits that auto-match and would
/// otherwise re-grind the full wordlist. Feeding the potfile plaintexts back as
/// a wordlist closes that gap.
fn default_hashcat_potfile() -> Option<PathBuf> {
    // Tests stay hermetic: a real potfile on the dev/CI box would add an
    // unmocked hashcat pass and desync the mock queue (an empty mock queue
    // falls through to real execution). The pure parsers below are tested
    // directly instead.
    #[cfg(test)]
    {
        None
    }
    #[cfg(not(test))]
    {
        if let Ok(explicit) = std::env::var("ARES_HASHCAT_POTFILE") {
            let p = PathBuf::from(explicit);
            if p.is_file() {
                return Some(p);
            }
        }
        let mut candidates: Vec<PathBuf> = Vec::new();
        if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
            candidates.push(PathBuf::from(xdg).join("hashcat/hashcat.potfile"));
        }
        if let Ok(home) = std::env::var("HOME") {
            candidates.push(PathBuf::from(&home).join(".local/share/hashcat/hashcat.potfile"));
            candidates.push(PathBuf::from(&home).join(".hashcat/hashcat.potfile"));
        }
        candidates.into_iter().find(|p| p.is_file())
    }
}

/// Extract candidate plaintexts from hashcat potfile lines.
///
/// Each line is `<hash>:<plaintext>`. The hash itself may contain `:`/`$`
/// (Kerberos, NetNTLMv2), so the plaintext is everything after the LAST `:`.
/// hashcat hex-encodes plaintexts with awkward bytes as `$HEX[..]`; those are
/// decoded. Best-effort: a password that itself contains `:` may be truncated
/// here, which only costs that one reuse — a candidate is merely tested offline
/// against the hash, so a wrong candidate never produces a wrong crack.
fn parse_potfile_plaintexts(contents: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in contents.lines() {
        let line = line.trim_end_matches(['\r', '\n']);
        let Some((_, plain)) = line.rsplit_once(':') else {
            continue;
        };
        let plain = decode_hashcat_hex(plain);
        if !plain.is_empty() && plain.len() <= 128 {
            out.push(plain);
        }
    }
    out
}

/// Decode a hashcat `$HEX[..]`-wrapped plaintext; pass anything else through.
fn decode_hashcat_hex(s: &str) -> String {
    if let Some(hex) = s.strip_prefix("$HEX[").and_then(|h| h.strip_suffix(']')) {
        if !hex.is_empty() && hex.len() % 2 == 0 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
            let bytes: Vec<u8> = (0..hex.len())
                .step_by(2)
                .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
                .collect();
            if let Ok(decoded) = String::from_utf8(bytes) {
                return decoded;
            }
        }
    }
    s.to_string()
}

/// Build the known-plaintext seed wordlist: every password the op has already
/// recovered (`known_passwords` — cracked *and* harvested cleartext) plus this
/// box's potfile plaintexts, deduped. Tried FIRST, before rockyou, so any
/// password the system already knows re-cracks a fresh or different-etype
/// ticket for the same account — or any account reusing that password — in
/// milliseconds instead of re-grinding the full wordlist. Returns `None` when
/// there is nothing to try.
fn build_known_password_wordlist(known_passwords: &[&str]) -> Option<tempfile::NamedTempFile> {
    let mut raw: Vec<String> = known_passwords.iter().map(|s| s.to_string()).collect();
    if let Some(potfile) = default_hashcat_potfile() {
        if let Ok(contents) = std::fs::read_to_string(&potfile) {
            raw.extend(parse_potfile_plaintexts(&contents));
        }
    }

    let mut seen = std::collections::HashSet::new();
    let mut file: Option<tempfile::NamedTempFile> = None;
    for candidate in raw {
        let candidate = candidate.trim();
        if candidate.is_empty() || candidate.len() > 128 {
            continue;
        }
        if !seen.insert(candidate.to_string()) {
            continue;
        }
        if file.is_none() {
            file = Some(tempfile::NamedTempFile::new().ok()?);
        }
        if let Some(f) = file.as_mut() {
            let _ = writeln!(f, "{candidate}");
        }
    }
    if let Some(f) = file.as_mut() {
        f.flush().ok()?;
    }
    file
}

/// Pull the `known_passwords` string array out of the tool params.
fn known_passwords_from_args(args: &Value) -> Vec<&str> {
    args.get("known_passwords")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default()
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

    let mode = resolve_hashcat_mode(optional_i64(args, "hashcat_mode"), hash_value);

    // Expensive AES kerberoast modes get a larger wall-clock floor so a throttled
    // sweep still reaches a deep-in-rockyou plaintext before each pass's
    // `--runtime` cap; cheaper modes (RC4/NTLM) exhaust rockyou fast and don't
    // need it. An explicit larger caller value still wins.
    let min_minutes = if is_expensive_aes_mode(mode) {
        aes_kerberoast_max_time_minutes()
    } else {
        DEFAULT_MAX_TIME_MINUTES
    };
    let max_time_minutes = optional_i64(args, "max_time_minutes")
        .unwrap_or(min_minutes)
        .max(min_minutes);
    let max_time_secs = max_time_minutes * 60;
    let use_dynamic = optional_bool(args, "use_dynamic_wordlist").unwrap_or(true);

    // Gate the whole crack job through the hashcat pool. hashcat owns the GPU
    // as a small fixed pool; the process-level permit is held
    // until this function returns (drop releases it). AES Kerberoast also takes
    // a mode-specific exclusive permit before the global hashcat permit because
    // one T4-sized GPU cannot reliably fit two 19600/19700 kernels at once.
    let _aes_permit = if is_expensive_aes_mode(mode) {
        Some(crate::concurrency::acquire_aes_kerberoast_permit().await)
    } else {
        None
    };
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

    // AES kerberoast (mode 19600/19700) is ~1000x slower per candidate than
    // RC4/NTLM, so the full 6-pass cascade (dynamic + two wordlists + two rule
    // sets) rebuilds the expensive AES kernel on every pass and, on a loaded box,
    // burns its whole budget on that overhead before the grind that matters ever
    // finishes — the observed failure mode (GPU idle, `no_plaintext` on a ticket
    // whose plaintext is in rockyou). Collapse AES to one lean pass: known
    // plaintexts (fast) + a single straight rockyou pass that gets the entire
    // budget. One kernel build, one long grind — proven to crack a deep rockyou
    // plaintext in ~75s even under op load. Cheap modes keep the full cascade.
    let lean_aes = is_expensive_aes_mode(mode);

    // Build wordlist order: explicit wordlist OR default cascade. Lean AES uses
    // rockyou only (the second wordlist is another AES kernel rebuild for little
    // marginal coverage).
    let wordlists: Vec<&str> = if let Some(wl) = explicit_wordlist {
        vec![wl]
    } else {
        DEFAULT_WORDLISTS
            .iter()
            .take(if lean_aes { 1 } else { DEFAULT_WORDLISTS.len() })
            .filter(|p| std::path::Path::new(p).exists())
            .copied()
            .collect()
    };

    // Optional dynamic wordlist from known_usernames JSON array — skipped for
    // lean AES (a tiny list isn't worth a separate AES kernel build).
    let dynamic_file = if use_dynamic && !lean_aes {
        let usernames: Vec<&str> = args
            .get("known_usernames")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<&str>>())
            .unwrap_or_default();
        build_dynamic_wordlist(&usernames)
    } else {
        None
    };

    // Build rules list: explicit rule OR default cascade. Skipped entirely for
    // lean AES — rockyou×rules is hopeless at AES speed under load and just
    // spends the budget rebuilding kernels instead of reaching the plaintext.
    let rules: Vec<&str> = if lean_aes {
        Vec::new()
    } else if let Some(r) = explicit_rules {
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

    // Known-plaintext reuse pass, run before every other list: try every
    // password the op has already recovered (cracked or harvested cleartext,
    // passed as `known_passwords`) plus this box's hashcat potfile. AD password
    // reuse is rampant, and a re-issued AS-REP/TGS ticket for an already-cracked
    // account has fresh ciphertext that hashcat's implicit potfile can't
    // auto-match — so without this the op re-grinds rockyou from scratch (slow
    // on AES tickets, and may exhaust its budget before re-finding a plaintext
    // it already knows). This pass cracks those in milliseconds.
    let known_pw_file = build_known_password_wordlist(&known_passwords_from_args(args));
    if let Some(ref kf) = known_pw_file {
        let kf_path = kf.path().to_string_lossy().to_string();
        let result = niced_hashcat()
            .flag("-m", mode.to_string())
            .arg("-a")
            .arg("0")
            .arg(&hash_path)
            .arg(&kf_path)
            .flag("--runtime", KNOWN_PW_PASS_SECS.to_string())
            .flag("--session", &session)
            .arg("--restore-disable")
            .arg("--force")
            .timeout_secs((KNOWN_PW_PASS_SECS + 60) as u64)
            .execute()
            .await;
        if let Ok(out) = result {
            all_output.push_str(&out.combined());
            all_output.push('\n');
        }
    }

    // Try dynamic wordlist first (username-derived candidates = most likely)
    if let Some(ref dyn_file) = dynamic_file {
        let dyn_path = dyn_file.path().to_string_lossy().to_string();
        let timeout_secs = (per_list_secs + 60) as u64;
        let result = niced_hashcat()
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
        let result = niced_hashcat()
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
            let result = niced_hashcat()
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
    let show_result = niced_hashcat()
        .flag("-m", mode.to_string())
        .arg(&hash_path)
        .arg("--show")
        .flag("--session", &session)
        .arg("--restore-disable")
        .arg("--force")
        .timeout_secs(30)
        .execute()
        .await?;

    // Combine all output so the caller can see the full run.
    let stdout = format!(
        "{all_output}\n--- hashcat --show ---\n{}",
        show_result.stdout
    );

    // Emit the crack verdict as a structured event. The tool's own stdout only
    // reaches the LLM turn; this line lands in the role log (and any OTLP export)
    // so the mode actually used and whether anything cracked are queryable
    // without reverse-engineering it from loot. Count via the same parser the
    // orchestrator uses to ingest creds, so the log agrees with the loot.
    // Inherits op.id/task.id from the enclosing tool span.
    let cracked = crate::parsers::parse_cracker_output(&stdout, args).len();
    info!(
        tool = "crack_with_hashcat",
        mode,
        // How many hashes this run actually loaded (batch size): a `no_plaintext`
        // on a large batch vs a single hash reads very differently.
        hashes = hash_value.lines().filter(|l| !l.trim().is_empty()).count(),
        hash_kind = hash_kind(hash_value),
        cracked_count = cracked,
        // Why the run ended, distilled from hashcat's own output — so a
        // `no_plaintext` that is actually a GPU/kernel failure is visible in the
        // role log instead of masquerading as "password not in wordlist".
        signal = hashcat_run_signal(&all_output),
        status = if cracked > 0 {
            "cracked"
        } else {
            "no_plaintext"
        },
        "crack job complete"
    );

    Ok(ToolOutput {
        stdout,
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

    // John's krb5tgs format is RC4-only. An AES kerberoast ticket (etype 17/18)
    // makes john load nothing ("No password hashes loaded") — a guaranteed miss
    // that wastes the single crack slot and litters the run history with parse
    // errors. hashcat (mode 19700/19600) is the only tool that cracks these, so
    // skip john and route the caller there. Not an error: a clean, explained
    // no-op so the cracker moves on instead of retrying john.
    if is_aes_krb5tgs(hash_value) {
        info!(
            tool = "crack_with_john",
            hash_kind = hash_kind(hash_value),
            status = "skipped_aes_krb5tgs",
            "AES kerberoast ticket cannot be loaded by john's RC4-only krb5tgs format; use crack_with_hashcat (mode 19700/19600)"
        );
        return Ok(ToolOutput {
            stdout: "crack_with_john skipped: AES kerberoast ticket (etype 17/18). John's \
                     krb5tgs format is RC4-only and cannot load it — use crack_with_hashcat, \
                     which auto-selects hashcat mode 19700 (AES256) / 19600 (AES128).\n"
                .to_string(),
            stderr: String::new(),
            exit_code: Some(0),
            success: true,
        });
    }

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

    // Known-plaintext reuse pass first — see the note in `crack_with_hashcat`.
    let known_pw_file = build_known_password_wordlist(&known_passwords_from_args(args));
    if let Some(ref kf) = known_pw_file {
        let kf_path = kf.path().to_string_lossy().to_string();
        let timeout_secs = (KNOWN_PW_PASS_SECS + 60) as u64;
        let mut cmd = CommandBuilder::new("john")
            .arg(&hash_path)
            .arg(format!("--wordlist={kf_path}"))
            .arg(format!("--max-run-time={KNOWN_PW_PASS_SECS}"))
            .arg(&session_arg);
        if let Some(ref fa) = format_arg {
            cmd = cmd.arg(fa);
        }
        if let Ok(out) = cmd.timeout_secs(timeout_secs).execute().await {
            all_output.push_str(&out.combined());
            all_output.push('\n');
        }
    }

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

    let stdout = format!("{all_output}\n--- john --show ---\n{}", show_result.stdout);

    // Structured crack verdict — see the note in `crack_with_hashcat`.
    let cracked = crate::parsers::parse_cracker_output(&stdout, args).len();
    info!(
        tool = "crack_with_john",
        john_format = hash_format.unwrap_or("auto"),
        hash_kind = hash_kind(hash_value),
        cracked_count = cracked,
        status = if cracked > 0 {
            "cracked"
        } else {
            "no_plaintext"
        },
        "crack job complete"
    );

    Ok(ToolOutput {
        stdout,
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
    fn hash_kind_labels() {
        assert_eq!(hash_kind("$krb5tgs$18$user$REALM$*spn*$aa$bb"), "krb5tgs");
        assert_eq!(hash_kind("$krb5asrep$23$user@REALM:aabb"), "krb5asrep");
        assert_eq!(hash_kind("aad3b435b51404ee"), "ntlm-or-other");
    }

    #[test]
    fn hashcat_run_signal_classifies_output() {
        // An honest sweep that found nothing.
        assert_eq!(
            hashcat_run_signal("Status...........: Exhausted\n"),
            "exhausted"
        );
        // A real crack.
        assert_eq!(
            hashcat_run_signal("$krb5tgs$18$u$R$aa:pw\nStatus...........: Cracked\n"),
            "cracked"
        );
        // GPU / kernel-init failures — the crack never actually ran the wordlist.
        assert_eq!(
            hashcat_run_signal("clBuildProgram(): CL_BUILD_PROGRAM_FAILURE\n"),
            "device_error"
        );
        assert_eq!(
            hashcat_run_signal("Not enough allocatable device memory for this attack\n"),
            "device_error"
        );
        // A device fault outranks a stray "Exhausted" from an earlier cheap pass
        // in the same combined output — the run still failed for a GPU reason.
        assert_eq!(
            hashcat_run_signal("Status...........: Exhausted\nclBuildProgram(): failure\n"),
            "device_error"
        );
        assert_eq!(
            hashcat_run_signal("Token length exception\n"),
            "hash_rejected"
        );
        // No verdict at all → pass was killed before hashcat printed a status.
        assert_eq!(hashcat_run_signal(""), "no_status");
    }

    #[test]
    fn expensive_aes_modes_get_larger_budget_floor() {
        // Only the slow AES kerberoast modes get the bigger wall-clock floor.
        assert!(is_expensive_aes_mode(19700)); // AES256 TGS
        assert!(is_expensive_aes_mode(19600)); // AES128 TGS
        assert!(!is_expensive_aes_mode(13100)); // RC4 TGS
        assert!(!is_expensive_aes_mode(18200)); // AS-REP
        assert!(!is_expensive_aes_mode(1000)); // NTLM
        assert!(!is_expensive_aes_mode(5600)); // NetNTLMv2

        // The default floor is larger than the cheap-mode default but stays
        // under the non-LLM crack reaper so the job isn't killed mid-run.
        const _: () = assert!(DEFAULT_AES_KERBEROAST_MAX_TIME_MINUTES > DEFAULT_MAX_TIME_MINUTES);
        const _: () = assert!(DEFAULT_AES_KERBEROAST_MAX_TIME_MINUTES * 60 < 6000);
    }

    #[test]
    fn is_aes_krb5tgs_detects_etype() {
        assert!(is_aes_krb5tgs("$krb5tgs$18$u$R$*spn*$aa$bb")); // AES256
        assert!(is_aes_krb5tgs("$krb5tgs$17$u$R$*spn*$aa$bb")); // AES128
        assert!(!is_aes_krb5tgs("$krb5tgs$23$*u$R$spn*$aa$bb")); // RC4 — john can load
        assert!(!is_aes_krb5tgs("$krb5asrep$23$u@R:aabb")); // AS-REP
        assert!(!is_aes_krb5tgs("aad3b435b51404ee")); // NTLM
    }

    #[tokio::test]
    async fn crack_with_john_skips_aes_krb5tgs() {
        // AES kerberoast ticket → john short-circuits before spawning anything
        // (no mock needed), returning a clean explained no-op pointing at hashcat.
        let args = json!({"hash_value": "$krb5tgs$18$svc$REALM$*spn*$aabb$ccdd"});
        let out = crack_with_john(&args).await.unwrap();
        assert!(out.success);
        assert!(out.stdout.contains("skipped"));
        assert!(out.stdout.contains("19700"));
    }

    #[test]
    fn resolve_mode_kerberos_ignores_wrong_override() {
        // The LLM (schema-nudged to 13100) forces RC4 for AES tickets; the
        // embedded etype wins so hashcat gets a mode that can parse the hash.
        assert_eq!(
            resolve_hashcat_mode(Some(13100), "$krb5tgs$18$user$REALM$*spn*$aa$bb"),
            19700
        );
        assert_eq!(
            resolve_hashcat_mode(Some(13100), "$krb5tgs$17$user$REALM$*spn*$aa$bb"),
            19600
        );
        // AS-REP stays on its only mode regardless of the override.
        assert_eq!(
            resolve_hashcat_mode(Some(1000), "$krb5asrep$23$user@REALM:aabb"),
            18200
        );
        // A correct RC4 kerberoast override still lands on 13100 (matches etype).
        assert_eq!(
            resolve_hashcat_mode(Some(13100), "$krb5tgs$23$*user$REALM$spn*$aa$bb"),
            13100
        );
    }

    #[test]
    fn resolve_mode_non_kerberos_honors_override() {
        // NetNTLMv2 isn't auto-detected, so respect the caller's explicit mode.
        assert_eq!(
            resolve_hashcat_mode(Some(5600), "user::DOMAIN:1122334455667788:aabb:ccdd"),
            5600
        );
        // No override -> auto-detect's NTLM fallback.
        assert_eq!(resolve_hashcat_mode(None, "aad3b435b51404ee"), 1000);
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
    fn decode_hashcat_hex_plain_passthrough() {
        assert_eq!(decode_hashcat_hex("P@ssw0rd!"), "P@ssw0rd!");
        // Not a valid $HEX[..] wrapper — passed through unchanged.
        assert_eq!(decode_hashcat_hex("$HEX[zz]"), "$HEX[zz]");
        assert_eq!(decode_hashcat_hex("$HEX[abc]"), "$HEX[abc]"); // odd length
    }

    #[test]
    fn decode_hashcat_hex_decodes_wrapper() {
        // `P@ss:w0rd` — a password containing a colon, hex-encoded by hashcat.
        assert_eq!(decode_hashcat_hex("$HEX[504073733a77307264]"), "P@ss:w0rd");
    }

    #[test]
    fn parse_potfile_plaintexts_ntlm_and_kerberos() {
        // NTLM (single colon) and an AS-REP line whose hash portion itself
        // contains colons — the plaintext is everything after the LAST colon.
        let pot = "\
e19ccf75ee54e06b06a5907af13cef42:Summer2024!
$krb5asrep$23$carol@FABRIKAM.LOCAL:8a7a0b3264590ef6a:P@ssw0rd!
$HEX[6c65742069743a676f]:ignored_only_first_field
";
        let mut got = parse_potfile_plaintexts(pot);
        got.sort();
        assert!(got.contains(&"Summer2024!".to_string()));
        assert!(got.contains(&"P@ssw0rd!".to_string()));
        // Every line yields one candidate (the last `:`-delimited field); the
        // point is that a colon-bearing Kerberos hash never panics or drops.
        assert_eq!(got.len(), 3);
    }

    #[test]
    fn build_known_password_wordlist_dedups_and_writes() {
        // Potfile discovery is disabled under cfg(test), so only the passed
        // known_passwords land in the file — deduped, blanks dropped.
        let file = build_known_password_wordlist(&["P@ssw0rd!", "P@ssw0rd!", "", "P@ssw0rd2!"]);
        assert!(file.is_some());
        let contents = std::fs::read_to_string(file.unwrap().path()).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2, "duplicate and empty must be dropped");
        assert!(lines.contains(&"P@ssw0rd!"));
        assert!(lines.contains(&"P@ssw0rd2!"));
    }

    #[test]
    fn build_known_password_wordlist_empty_is_none() {
        assert!(build_known_password_wordlist(&[]).is_none());
    }

    #[test]
    fn known_passwords_from_args_parses_array() {
        let args = json!({"known_passwords": ["a", "b", 3, "c"]});
        assert_eq!(known_passwords_from_args(&args), vec!["a", "b", "c"]);
        assert!(known_passwords_from_args(&json!({})).is_empty());
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
    async fn crack_with_hashcat_runs_known_password_pass_first() {
        // known_passwords present -> the reuse pass runs before --show.
        // Passes here: known-pw (1) + --show (1). No default wordlists exist on
        // the test box, so no wordlist/rules passes.
        mock::push(mock::success()); // known-plaintext reuse pass
        mock::push(mock::success()); // --show
        let args = json!({
            "hash_value": "$krb5asrep$23$user@CONTOSO.LOCAL:aabb:ccdd",
            "use_dynamic_wordlist": false,
            "known_passwords": ["P@ssw0rd!", "P@ssw0rd2!"]
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
