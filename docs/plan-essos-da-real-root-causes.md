# Plan: essos.local DA — real root causes

## 1. Problem

In `op-20260629-001546` and `op-20260629-074433` the orchestrator domained
`sevenkingdoms.local` and `north.sevenkingdoms.local` in ~6 minutes, then spent
~80 min (op1) and ~24 min (op2 — killed by user) attempting essos.local DA
without success. The cross-forest trust to essos has SID filtering enabled, so
`forge_inter_realm_and_dump` cannot yield a DCSync-capable PAC; every other
attack path (kerberoast, coercion-relay, ADCS, lateral, shadow creds) hit a
different orchestrator-side or environment-side gap. The actual blocker set is
wider than any single subsystem.

## 2. Evidence table

All file paths absolute. Log line numbers are from
`/var/log/ares/orchestrator.log` on EC2 instance `i-09c56c4e3c05fb0bc`
(`kali-ares`); slice copies live at `/tmp/op1.log` (lines 18243–34244 of the
master log) and `/tmp/op2.log` (lines 34245–49913) on the same EC2 box.

| Signal | op1 | op2 | Notes |
| --- | --- | --- | --- |
| `"Suppressing forge_inter_realm_and_dump"` log lines | **0** | **0** | Prior doc claim refuted. Suppression never fired. |
| `"Cross-forest forge dispatched ... target_domain=essos.local"` | 1 (op1:3303 / master:21545) | 1 (op2:7964 / master:42208) | Forge runs unconditionally. |
| `"forge_inter_realm_and_dump completed but no target krbtgt observed"` | 1 (op1:3406) | 1 (op2:8013) | Dump phase always returns 0 hashes for essos (DRSUAPI denial). |
| `"Dispatching create_inter_realm_ticket for SID-filtered trust"` | 1 (op1:3443) | 1 (op2:8050) | **Post-failure** fallback path at `trust.rs:2223-2241`, *not* the pre-suppression path at `trust.rs:1645-1697`. |
| `"Inter-realm ticket forged"` ccache | op1:3458 → `/tmp/ares-tickets/sevenkingdoms_local__essos_local__Administrator.ccache` | op2:8089 → same path | Redis hash `ares:op:*:kerberos_tickets` confirmed key `sevenkingdoms.local:essos.local:administrator`. Ccache file exists on disk (`ls -la /tmp/ares-tickets/` 3676 bytes, owned root, mode 644). |
| Unique coercion task IDs targeting MEEREEN 10.4.6.159 (orchestrator dispatch logs) | (not recounted) | **3** (PetitPotam unauth 07:44:49, LLM-driven DC coercion 07:45:18, DFSCoerce 07:50:48) | User prompt premise "64 + 20 + 9 dispatches against MEEREEN" is wrong — that count is across *all* hosts; MEEREEN received 3 unique dispatches in op2. |
| `Task completed` for coercion against 10.4.6.159 | (not recounted) | **3** (op2:300, 455, 3949), all "RPC_S_ACCESS_DENIED / NO_AUTH_RECEIVED" | All three reached SMB pipes but EFSRPC/MS-RPRN/MS-DFSNM returned access-denied; no inbound auth captured. |
| `RELAY_BIND_BUSY` warns | **717** | **1525** | NTLM relay listener thrash; fix out of scope here. |
| `kerberoast against essos.local` (op2 only) — 1 dispatch | n/a | op2:296, completed op2:342, "`KDC_ERR_ETYPE_NOSUPP` — no RC4, no TGS captured" | Kerberoast itself did **not** request a TGS (etype rejected pre-TGS-REP), so it did not contribute to lockout. |
| `sql_svc` first STATUS_ACCOUNT_LOCKED_OUT | n/a | op2:394 at 07:45:22 — spray task `credential_access_979788cc81c0` with `Spring2026` | **Lockout source is `password_spray`, not kerberoast.** 8 seconds after kerberoast finished. |
| Subsequent `User quarantined for 5 min` events for `sql_svc` (essos+north) | n/a | op2 lines 415, 621, 643, 1125, 1145, 1281, 1531, 1805, 1976 — **9 quarantines** in 3 min | Quarantine is per-`(user,domain)` but multiple sprays still kept hitting the locked principal across north + essos. |
| AES-only kerberoast retry after `KDC_ERR_ETYPE_NOSUPP` | n/a | **0** in op2 (no follow-up dispatch found in grep `targetedKerberoast.*essos` after 07:45:14) | Orchestrator does not flip RC4→AES and retry. |
| Inter-realm ccache consumption attempts (op1) — `Detected .ccache ticket — chaining secretsdump` | 7+ (op1:3560, 4714, 5707, 6056, 6647, 7241, +) | (op2 fewer; ticket forged later) | Auto-chain wires up follow-on secretsdump tasks. |
| Tool-side "CCache file is not found / Matching credential not found / Worker was supposed to inject Administrator ccache automatically, but it appears not present/loaded" | repeating, op1:3611, 3978, 5701, 6053, 6641, 6852, 7240, 8508, 8703, 8779, 8891, 10211, 11471 | op2:8567, 8569, +others | LLM workers consistently report the injected ccache is missing or not loaded. |
| Inter-realm referral ticket DCSync attempts — symptoms | `Policy SPN target name validation`, `KDC_ERR_S_PRINCIPAL_UNKNOWN` (target=IP), `invalid_checksum` (target=FQDN) | same | Cross-realm referral TGT cannot DCSync — see Bug C below. |
| `certipy_request` against ESSOS-CA 10.4.6.159 / 10.4.6.183 | op1:12166, 12773 — `ept_s_not_registered`, 120 s timeout | op2:7251, 7329, 7391 — same | ADCS RPC enrollment endpoint not registered/reachable. |
| `auto_golden_cert` dispatched targeting ESSOS-CA | n/a | op2:9608 → `exploit_1f0d01f2fd0c`, role=`credential_access` | Routed to wrong agent role. |
| LLM response: "Cannot execute … 'golden_cert' … certipy_ca/certipy_forge/certipy_auth … are not available in this agent's toolset. Available functions are limited to kerberoast/asrep_roast/secretsdump/lsassy/GPP/SYSVOL/LAPS…" | n/a | op2:9657-9660, task failed | credential_access role does not have certipy_* tools. |
| Shadow Credentials (pywhisker / `certipy shadow auto`) against essos.local low-priv users | n/a | op2:3394 (khal.drogo, pywhisker — PFX export failed: `OpenSSL.crypto has no attribute 'PKCS12'`); op2:3874 (viserys.targaryen — same OpenSSL failure); op2:13803 (viserys.targaryen, **succeeded** with certipy shadow, NTLM hash retrieved); op2:14258 (khal.drogo, **succeeded**, NTLM = `739120ebc4dd940310bc4bb5c9d37021`) | Late-op pivots that DID work. |
| Shadow-credentials NTLM hashes in Redis (`ares:op:op-20260629-074433:hashes` HKEYS, filtered for essos) | n/a | only `asrep:essos.local:missandei`, `ntlm:essos.local:essos$:1dab027b9f6a63f6faafb59150901ad0` | **Drogo/viserys hashes were NEVER persisted** despite the success messages. |
| Operation terminated | self-completed | killed by user 08:08:xx (after viserys/drogo shadow success at 08:06-08:07) | Op2 was killed ~60 s after the first essos low-priv hashes were retrieved by the LLM. |
| `dominated_domains` set (op2) | (n/a) | `redis-cli smembers` returns only `north.sevenkingdoms.local`, `sevenkingdoms.local` | No essos. |

## 3. Real failure modes

### Bug A — `is_filtered_inter_forest_trust` returns false at trust-follow time; suppression branch never executes

**Symptom (raw log).** Both ops log `Cross-forest forge dispatched ... target_domain=essos.local` (op1:3303, op2:7964) followed by `forge_inter_realm_and_dump completed but no target krbtgt observed — locking dedup, waking fallbacks` (op1:3406, op2:8013). The `info!("Suppressing forge_inter_realm_and_dump — SID filtering on cross-forest trust would reject ExtraSid; waking fallbacks")` message at `ares-cli/src/orchestrator/automation/trust.rs:1649-1654` (verified by `grep -n 'Suppressing forge_inter_realm' ares-cli/src/orchestrator/automation/trust.rs`) has **0 occurrences** in either op log.

**Root cause hypothesis.** `is_filtered_inter_forest_trust` at `trust.rs:189-214` (read by me 2026-06-29) consults `state.trusted_domains` keyed by the lowercase *target* domain name. If essos trust metadata has not yet populated (`auto_trust_enum` not yet completed, or the trust enum landed under a different key), the function falls through to `return false` per its `// No metadata — try the forge` comment at `trust.rs:209-213`. The fallback is intentional — the comment cites "false negatives cost the entire foreign domain" — but in this lab the cost calculus is inverted because the post-failure fallback at `trust.rs:2223-2241` does the *same* `dispatch_create_inter_realm_ticket` the suppression branch would have done. The forge run is pure waste plus a `rpc_s_access_denied` blowout that doesn't help anything downstream.

The operative evidence is that *neither* branch of `is_filtered_inter_forest_trust` produces the suppression log line — whatever detection happens at trust-enum time isn't reaching `auto_trust_follow`.

**Proposed fix sketch (conceptual).** Either (1) defer `auto_trust_follow` until `state.trusted_domains[target]` has been populated by `auto_trust_enum`, with a retry/backoff once metadata arrives, or (2) treat the post-failure fallback as authoritative and remove the speculative forge entirely for explicitly-named SID-filtered targets known to fail (essos.local is one). Option 2 is cleaner; option 1 preserves the "try the forge if you can't prove SID filtering" gamble for unknown trusts.

### Bug B — forged inter-realm ccache is published but downstream worker tools do not load it

**Symptom (raw log).** After the ticket persists (op1:3458, op2:8089) the orchestrator chains follow-on tasks via `S4U auto-chain: secretsdump dispatched with ticket` (op1:3562). Every consumer LLM agent reports the ccache is missing: `CCache file is not found. Skipping...` then `KDC_ERR_PREAUTH_FAILED` (op1:3611), `SASL/GSSAPI 'Matching credential not found' referencing missing ccache (/tmp/ares-tickets/sevenkingdoms_local__essos_local__Administrator.ccache)` (op1:5701, 6053, 6641, 8508, 10211; op2:8567). Repeats at least 13 times in op1, multiple in op2. On EC2 the file *does* exist on disk (`/tmp/ares-tickets/sevenkingdoms_local__essos_local__Administrator.ccache`, 3676 bytes, owner `root`, mode `644`) and the path is in Redis under `ares:op:*:kerberos_tickets`.

**Root cause hypothesis.** The credential resolver logs `credential_resolver: injecting inter-realm Kerberos ticket for cross-forest tool tool=ldap_acl_enumeration target_domain=essos.local ticket_path=/tmp/...ccache` (op1:3468), so the orchestrator *intends* to inject. But the worker LLM reports the tool dies because no `KRB5CCNAME` env var or `-k`/`-ticket-path` argument is reaching the impacket/ldap-search invocation. Two candidate locations to verify: the tool wrapper that builds the impacket command line (does it read the inter-realm path from the resolver and prepend `KRB5CCNAME=…` to env, or pass `-k -no-pass` *and* the cached file?), and the tool schema (does `ldap_search` / `secretsdump` accept a `ticket_path` arg at all, or does the resolver silently drop it?). The LLM repeatedly says "Tool schema also has no password parameter" / "tool interface doesn't include password field" (op1:545, 4710), which corroborates a schema-vs-injector mismatch rather than a filesystem-availability issue.

**Proposed fix sketch.** Audit the tool dispatch path between `credential_resolver` (the injecting side) and the actual worker process invocation: ensure that when the resolver decides to inject an inter-realm ccache, the worker invocation gets `KRB5CCNAME` in its environment AND the resulting impacket/ldap CLI is called with `-k -no-pass` (or equivalent). Surface a `warn!` if the resolver intends injection but the consuming tool schema has no ticket slot — silent drops are why this bug is invisible in the dispatcher logs.

### Bug C — Cross-realm referral ticket cannot DCSync even when correctly loaded (architectural)

**Symptom (raw log).** When workers do find/use the ccache, secretsdump returns:
`Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`; with `-just-dc-user krbtgt` and target=10.4.6.159 → `Kerberos SessionError KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found)`; with target=meereen.essos.local → `invalid_checksum`; `-use-vss` still hits the SPN validation message and exits with no dump. Examples: op1:3978, 6852, 8704, 10212, 11471 (multiple distinct task IDs spread across ~50 minutes).

**Root cause hypothesis.** The ccache file produced by `create_inter_realm_ticket` contains `ldap/meereen.essos.local` and `cifs/meereen.essos.local` *service* tickets requested through the cross-realm referral path (verified in the `output_tail` of op1:3458 / op2:8089). The PAC inside those tickets is the *referral* PAC, which the essos KDC's PAC validation strips of the source forest's RID-519 ExtraSid when SID filtering is on. impacket's DCSync via DRSUAPI requires either (a) DA / DC-bound principal in the *target* domain (the referral PAC isn't) or (b) the trusted-account NT hash (we have `ESSOS$` trust key but DCSync via trust key requires forging a new inter-realm TGT — which is exactly the path SID filtering blocks). So no matter how cleanly the ticket loads, DCSync against essos with this ccache is unwinnable. The orchestrator wastes ~10 distinct tasks across op1 chasing it.

**Proposed fix sketch.** Stop auto-chaining `secretsdump` after `create_inter_realm_ticket` when the trust to the target is SID-filtered. The ticket is still useful for LDAP enumeration (BloodHound `--no-pass --kerberos`, etc.) and for AS-REP / kerberoast against the foreign domain — but DCSync via DRSUAPI is wasted spend. Pair this with the suppression in Bug A so the orchestrator never produces the doomed forge dispatch + doomed DCSync chain in the first place.

### Bug D — `auto_golden_cert` dispatches to a role whose toolset lacks certipy

**Symptom (raw log).** op2:9608-9611: `auto_golden_cert: Golden Certificate pipeline dispatched task_id=exploit_1f0d01f2fd0c ca_host=10.4.6.183 domain=essos.local target_role="credential_access"`. The credential_access agent immediately responds (op2:9657): `Cannot execute requested 'golden_cert' exploitation steps because required tools (certipy_ca/certipy_forge/certipy_auth, certipy_find, and remote exec like psexec/wmiexec) are not available in this agent's toolset. Available functions are limited to kerberoast/asrep_roast/secretsdump/lsassy/GPP/SYSVOL/LAPS/LDAP description/sprays/etc.` Task fails (op2:9660). This is the only golden-cert dispatch in op2 — no retry on a different role.

**Root cause hypothesis.** `auto_golden_cert` (search for the dispatch site by grepping `auto_golden_cert` under `ares-cli/src/orchestrator/automation/`) sets `target_role="credential_access"`, but the credential_access agent's tool registry is the credential-harvesting / kerberoast / LDAP enumeration subset. Certipy_ca / certipy_forge / certipy_auth live in the privesc or exploit role's toolset. The pipeline name implies an end-to-end action, but the routing decision lands on a role that can't execute it. (Not verified by grep — code location TBD; the dispatch log line is the evidence the routing is wrong.)

**Proposed fix sketch.** Either route `auto_golden_cert` to the role whose toolset includes certipy_ca / certipy_forge / certipy_auth, or expand the credential_access role's toolset to include those. Routing change is lower-risk. The same problem likely exists for any pipeline whose constituent tools span roles; an audit pass across `automation/*.rs` for `target_role=` literals is warranted.

### Bug E — Kerberoast → password_spray sequencing locks out the only roastable SPN account

**Symptom (raw log).** op2:296 (07:45:11) Kerberoast against essos.local DC finds `sql_svc` (SPN `MSSQLSvc/braavos.essos.local`/`MSSQLSvc/braavos.essos.local:1433`). op2:342 (07:45:16): completes with `KDC_ERR_ETYPE_NOSUPP` — KDC refused TGS because the SPN account has only AES keys, no RC4. **No TGS-REP error counter increments** because the KDC refused at AS/TGS-REQ stage before any pre-auth failure. Then op2:394 (07:45:22): `password_spray` task `credential_access_979788cc81c0` reports `essos.local\sql_svc returned STATUS_ACCOUNT_LOCKED_OUT during spray attempt with password 'Spring2026'` — first password attempted, already locked. op2:415 (07:45:25): `User quarantined for 5 min: enumeration lockout detected user=sql_svc domain=essos.local`. Subsequent spray tasks (op2:621, 643, 1125, 1145, 1281, 1531, 1805, 1976) keep finding sql_svc locked across multiple domains in 3 min.

**Root cause hypothesis (two components).**

1. Kerberoast with default etype priority issues TGS-REQ for RC4 (etype 23). When the SPN account has `msDS-SupportedEncryptionTypes` set to AES-only, the KDC returns `KDC_ERR_ETYPE_NOSUPP` without producing a TGS. The orchestrator never re-attempts with AES-only TGS-REQ (etype 18/17). No retry dispatch found in op2 grep `targetedKerberoast.*essos` after 07:45:14.
2. The first password_spray task to touch sql_svc reports `STATUS_ACCOUNT_LOCKED_OUT` on attempt 1, which means sql_svc was *already* locked before this op started — likely artifact of the prior op1 (06:15-07:35Z, ~10 min before op2 launch). Once locked, the orchestrator's only adaptive behavior is the 5-min per-user quarantine; it does not switch to AES-only kerberoast (which uses the user's AES key and does not increment failed-password counters in the same way), and it does not wait out the 30-minute account lockout window.

**Proposed fix sketch.** On `KDC_ERR_ETYPE_NOSUPP` from kerberoast, dispatch a follow-up `targetedKerberoast` with etype hint `aes256-cts-hmac-sha1-96` / `aes128-cts-hmac-sha1-96` before any password_spray touches the same principal. Treat `STATUS_ACCOUNT_LOCKED_OUT` on a SPN-bearing account as a hard signal to (a) flip to AES kerberoast immediately and (b) propagate the lockout to every spray dispatcher's excluded-users list for ≥30 min (the AD default), not just 5 min.

### Bug F — Coercion against MEEREEN dedupes after first failure with no technique cycling

**Symptom (raw log).** op2 unique coercion dispatches against 10.4.6.159 (MEEREEN): only **3** — `Unauthenticated PetitPotam coercion dispatched ... dc=10.4.6.159` (op2:112, 07:44:49), `DC coercion dispatched ... dc=10.4.6.159` (op2:362, 07:45:18), `DFSCoerce (MS-DFSNM) coercion dispatched ... dc=10.4.6.159` (op2:3783, 07:50:48). All three completed with `RPC_S_ACCESS_DENIED` / `NO_AUTH_RECEIVED` for every probed pipe (op2:300, 455, 3949). No PrinterBug, ShadowCoerce, port-80 EFSRPC, or authenticated coercion attempt followed. The 3-attempt cadence over ~6 minutes against the single most valuable coercion target is far below saturation.

**Root cause hypothesis.** `auto_coercion` (around `coercion.rs:25-33`) dedups by DC IP on accept rather than on success. With the hard-coded `["petitpotam", "printerbug"]` technique pair, one access-denied response per DC locks that DC out of future automatic coercion regardless of technique. The handful of additional dispatches we see come from the LLM-driven `auto_coercion` and `auto_dfs_coercion` paths that schedule on their own timers — they happen to fire once each and then dedup. No phase-state struct exists to track `(technique_tried, attempts, last_error, cooldown_until)` and cycle through alternates.

**Proposed fix sketch.** Replace boolean dedup with phase state and cycle PetitPotam → DFSCoerce → PrinterBug → ShadowCoerce → EFSRPC-over-HTTP. Additionally, treat authenticated coercion as a distinct technique slot: once a same-forest credential is in hand (we held `essos.local\missandei:fr3edom` from op2 minute 1), retry coercion with auth before declaring the DC unreachable.

### Bug G — Successful shadow-credentials NTLM hashes not persisted to Redis

**Symptom (raw log).** op2:13803 (08:06:24): `Shadow credentials attack successful against essos.local DC 10.4.6.159. Added KeyCredential to viserys.targaryen, obtained TGT (saved to viserys.targaryen.ccache), retrieved NTLM hash...`. op2:14258 (08:07:02): `Shadow credentials succeeded against essos.local DC 10.4.6.159. Retrieved NTLM for essos.local\khal.drogo: 739120ebc4dd940310bc4bb5c9d37021. Certipy restored original KeyCredentialLink. Kerberos cache saved to khal.drogo.ccache.` Redis after the op terminated: `redis-cli hkeys ares:op:op-20260629-074433:hashes | grep -iE 'viserys|khal|drogo'` returns nothing. Only essos hashes captured are `asrep:essos.local:missandei` and the trust account `ntlm:essos.local:essos$:1dab02...`.

**Root cause hypothesis.** The LLM-driven shadow-credentials exploit completes and prints the NTLM hash to stdout, but the result-parsing path that should extract the hash and call `publish_hash` (or whatever the Redis-persistence path is for credentials) doesn't recognize the certipy / pywhisker stdout format. The hash appears verbatim in the task completion summary but is not extracted. Compare to other tools where extraction is wired correctly (secretsdump etc.).

**Proposed fix sketch.** Add a result extractor for the certipy shadow-credentials stdout format (`Retrieved NTLM for {domain}\{user}: {hash}` is one stable shape; certipy's structured JSON output is another) that calls the standard hash-publish path. Without persistence, these creds can't be picked up by any downstream automation in subsequent ticks.

### Bug H — Operation killed during essos-DA pivot window

**Symptom.** Op2 was killed by user at 08:08:xx (master log keeps going past 49913). The successful shadow-credentials hash retrievals for viserys.targaryen and khal.drogo landed at 08:06:24 and 08:07:02 — 60 to 90 seconds before kill. Even if Bug G were fixed, the orchestrator had no time to leverage those hashes for further escalation.

**Root cause hypothesis.** Operator-side decision, not a code bug. Including here for completeness: the *proximate* failure to reach essos DA in op2 may be "killed too early"; the *systemic* failures are A-G above.

**Proposed fix sketch.** None (operational note). Future essos-DA runs should let the op run at least 5 minutes past first essos low-priv hash extraction.

### Bug I — Per-credential deferred-queue saturation drops legitimate exploitation tasks

**Symptom (raw log, op-20260629-124605).** Starting ~20:11:40Z and continuing past 20:14:26Z, the orchestrator emits a sustained stream of `WARN automation.task: Deferred queue full while gating on cred — task dropped credential="missandei@essos.local" task_type="credential_access"` for every 15s tick. The dispatching sources are six distinct automation rules (`auto_credential_access`, `auto_credential_expansion`, `auto_local_admin_secretsdump`, `auto_laps_extraction`, `auto_share_enumeration`, `auto_credential_access@kerberoast`) all targeting the same `(user=missandei, domain=essos.local, target_ip∈{10.4.6.159, 10.4.6.183})` tuple. By 20:13:11Z the Lua enqueue script itself starts failing: `Failed to defer task, attempting direct submit err=Deferred enqueue script on ares:deferred:op-20260629-124605:credential_access`; by 20:13:26Z direct submit also fails: `Failed to defer cred-gated task`. Concurrent dispatcher state: `redis-cli LLEN tasks:queued = 0`, `LLEN tasks:in_progress = 0`, `KEYS task:* | wc -l = 1`, and the soft-cap log line reports `llm_count=11 max_tasks=8 role=credential_access role_count=2` — i.e. the role is *below* its concurrency ceiling but the cred-gate is rejecting redundant duplicates.

**Root cause hypothesis.** The cred-gated deferred queue holds at most N pending tasks per `(operation_id, role, credential)` tuple. Multiple automation rules fire on the same tick and each independently dispatches a `(missandei@essos.local, credential_access)` task. With N rules firing every ~15s and no dedup *before* enqueue, the queue fills with redundant copies of "secretsdump against meereen as missandei" within the first minute and stays saturated for the remainder of the op. Subsequent dispatches — including legitimately new vuln-driven exploitation tasks — are dropped silently from this saturated queue, while workers sit idle (`role_count=2` vs `max_tasks=8`). The Lua-script failure is downstream of the saturation: once the deferred set has accumulated past whatever size the script's compare-and-swap path tolerates, the script itself errors out.

This is *the* reason discovery (21 → 338 vulns over 1 hour) outran exploitation (stuck at 6) in this op: the dispatch pipeline is not bottlenecked on worker capacity, it's bottlenecked on the cred-gate queue not deduping at the producer side. The automation tier produces orders of magnitude more dispatches than the consumer can drain, with no flow control between them.

**Proposed fix sketch.**

1. Producer-side dedup: before enqueuing a `(user, domain, target_ip, technique)` task into the cred-gated queue, check whether an equivalent task is already in the deferred set or in `tasks:in_progress`. Drop the duplicate at the producer instead of accepting it into the queue and dropping the next legitimate task. This is cheaper than queue saturation and surfaces the redundancy at the source automation rule.
2. Make the Lua enqueue script idempotent on `(task_signature_hash)` so even if two automation rules race, only one ends up in the queue.
3. Audit the six automation rules listed above for the missandei case — most of them are firing on overlapping signals (vuln events, cred events, share events). Several are likely redundant in semantics: `auto_credential_expansion` and `auto_credential_access` both want to run secretsdump against the same DC with the same cred. Consolidate to one canonical dispatcher per `(technique, target)` tuple.

## 4. What we know we don't know

- **Whether Bug B (ccache not loaded by workers) is on the orchestrator side or the worker tool wrapper side.** The injection log fires; the worker can't find the file. Need to add `KRB5CCNAME` env logging on the worker process invocation to confirm whether the env var is set at exec time. Cannot determine purely from existing logs.
- **Why `is_filtered_inter_forest_trust` returns false at trust-follow time for essos.** Could be (a) `auto_trust_enum` hasn't run yet, (b) the trust enum stored the info under a different key, (c) the trust enum returned the trust as not-cross-forest. Needs a Redis dump of `state.trusted_domains` snapshot at the moment `auto_trust_follow` decides. A new op with explicit state logging would resolve this.
- **Whether the `STATUS_ACCOUNT_LOCKED_OUT` on the first sql_svc spray attempt** means sql_svc was already locked from before op2 launch (residual op1 state on the AD lab), or whether the spray itself triggered the lockout on attempt 1 (very tight lockout threshold of 1). Needs reading the AD lockout-policy SRV record or running a controlled op against a freshly-unlocked sql_svc.
- **Whether the cred-conflation pattern (`ntlm:north.sevenkingdoms.local:sql_svc` used against essos DC)** actually fires. Not seen in op2 logs; may be op1-specific or specific to a state where missandei isn't yet present. Needs targeted op or unit-test against `credential_access::select_kerberoast_work`.
- **Whether the certipy_request `ept_s_not_registered` against ESSOS-CA is a lab issue (ADCS service not started on the CA host) or a tool/transport issue (impacket-rpcdump can't enumerate the endpoint).** Multiple distinct attempts both with `target=10.4.6.159` and `target=10.4.6.183` (the actual CA per LLM context) all fail the same way. May simply mean the lab's ADCS instance is non-functional, in which case Bug D's fix matters less for this lab but matters for any lab with a working ADCS.

## 5. Out of scope / non-goals

- Re-doing the architectural assessment of the SID-filtered trust. The lab's trust *is* SID-filtered (the `forge_inter_realm_and_dump` 0-hash outcome and the cross-realm referral PAC stripping confirm it indirectly), so the suppression *should* fire — it just doesn't.
- RELAY_BIND_BUSY noise (717 op1, 1525 op2). Confirmed real, fix is outside this scope.
