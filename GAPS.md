# Attack Coverage Gaps — Open Items

What ares still does not reach in the GOAD curriculum, measured against 93 operations.

Companion to `docs/goad-checklist.md`, which inventories what the *lab* exposes. This document is
the other half, and it is deliberately **open items only** — techniques that already land reliably
have been removed. Their absence here means "working", not "unexamined".

## Method and provenance

- **Empirical** — all 93 `op-*.md` in `reports/red/` (2026-05-27 → 2026-07-30). Six are aborted
  stubs under 20 KB. The 94th `.md` in that directory is `_morning_status.md`, not an operation.
- **Code** — capability inventory of `ares-tools`, `ares-cli/src/orchestrator`,
  `ares-llm/src/tool_registry` at 2026-07-29.
- **Live logs** — `/var/log/ares/{orchestrator,acl}.log` on the operating box, scoped by op-id and
  timestamp window. Several findings below can only be established from logs, because a driver that
  builds work and never dispatches it leaves no artifact in the report at all.
- **Reference** — the 17 posts in mayfly277's GOAD series (https://mayfly277.github.io/categories/goad/),
  plus the per-host vulnerability spec of the lab build. The series states no MITRE ATT&CK IDs; any
  ID mapping here comes from ares.

**Trust rule used throughout**: a vulnerability's `Status: EXPLOITED` is not evidence. A
`### Key Events` timeline row is, as is a credential row whose `Source` column names a producing
tool. The two disagree in both directions.

**That rule is now known to be too weak, and every conclusion in this file that rests on a timeline row
alone is suspect.** `op-20260730-213328` renders seven `Vulnerability exploited: acl_*` timeline rows whose
task ids map, one for one, to `WARN Task failed` lines in the orchestrator log. The report cannot show
this; only the log can. The strengthened rule, used from here on: **a timeline row is evidence only when
the orchestrator log shows its `task_id` completing.** Where this document cites a timeline row without a
matching log check, treat it as unverified rather than as evidence. §7.7 is the finding.

**Status legend**: every status in this document carries two independent markers, because "the code
exists" and "it has been shown to work" diverge constantly — that divergence is the subject of this
file.

- **Implemented** — `—` not started · `WIP` in progress · `✔ code` landed in the repo, with the branch
  or commit named · `✔ env` landed on the operating box as an environment change rather than code.
- **Verified** — `—` none · `unit` unit tests only · `env` environment / box check · `op` observed
  working in a live operation, with the op id or date named.

**`✔ code` + `unit` is not evidence that a technique works against the lab. Only `op` is.** A unit test
proves a code path executes on the inputs its author imagined; it says nothing about whether the wire
protocol, the Python dependency chain, the target's policy or the queue ordering cooperate. Read
`Verified: unit` exactly as sceptically as `Verified: —`. That is the trust rule above, applied to this
document's own progress.

No marker at all is the default and means nothing has started: the absence of a `Status:` line on a
subsection reads as `—` / `—`.

**Naming**: lab principals are referred to by role, not name — this file is committed, and the
banned-token sweep in `.claude/CLAUDE.md` applies. The mapping is stable throughout:

| Role name used here | What it is |
| --- | --- |
| root domain / child domain / forest B | the three domains; forest B is the second forest across the outbound trust |
| root DC / child DC / forest-B DC | the three domain controllers |
| child SQL host / forest-B SQL host | the two MSSQL servers; the forest-B one is also the CA host |
| initial-access account | the account whose password sits in its own AD `description` |
| roastable-A / roastable-B | the two crackable Kerberoastable user accounts in the child domain |
| SPN service account | the MSSQL service account with the same password in child domain and forest B |
| AS-REP account (child) / AS-REP account (forest B) | the two `DONT_REQ_PREAUTH` accounts |
| gMSA / gMSA-reader | the group-managed service account and the machine account able to read it |
| LAPS-reader | the forest-B user in the LAPS readers list |
| edge N | position N in the root domain's 8-edge canonical ACL killchain |

---

## Parallel work coordination

Read this before starting any item in this document — more than one agent works from it at once.

**Merge history, compressed.** #350–#363 merged 2026-07-29 → 07-30, #364–#370 on 07-30, **#371–#374 on
07-30 late** (#371/#372 at 21:35, #373/#374 at 23:25 local). There are no open
PRs and nothing here is claimed-and-in-progress. Which rows each PR touched is recorded on the rows
themselves in §9; the per-PR ownership table, the branch sweep and the two duplicate write-ups of
`op-20260730-040759` have been deleted as spent. The ACL publish cap (#335, `acl_publish_cap: 200`) binds
and saturates — 200 of 257 vulns were ACL/GPO records in the first of these ops, converting none — which is
why §9 rejected capping publish volume as a coverage fix.

**Binary gate: do this first, always.** Every verdict below is interpretable only because the deployed
binary was checked against literals unique to the merges it claims to test; a stale binary has three times
turned an op into pure variance. Take the install time from
`ls -l --time-style=full-iso /usr/local/bin/ares`, then `grep -a -F` one shipped-code literal per change.
Two traps: `starts_with` literals get folded out by the optimizer, so gate on `contains`/format-string
literals; and test-only assertion strings never reach the release binary, so choosing one reads as a false
negative when the change did ship.

**The operating box is the EC2 instance** (`task ec2:exec`), not attacker-1, whose binary is months stale.
`ec2:exec`'s precondition breaks on any `CMD` containing a double quote — pipe a base64'd script instead.
Reports show roughly half of what matters; `/var/log/ares/orchestrator.log` scoped to the op window shows
the rest, and where the two disagree the log wins (§7.7).

### Operation verdict — `op-20260730-070442`, 2026-07-30, 16m10s, $6.38

**The first operation ever to run with the attack-path diversity knobs on**, which makes it the §8
experiment rather than another data point. #361 flipped all four in the shipped config
(`config/ares.yaml:96-116` — `selection_temperature: 0.7`, `novelty.enabled: true`,
`randomize_entry_foothold: true`, `emit_path_records: true`); #362 moved diversity recording to the dedup
path; #360 added the SID-membership guard and the status heartbeat; #363 split the runtime vuln counts.
All four merged between 23:12 and 00:59 local against an op start of 07:04:25Z, so the deploy window is
clean. Report at `reports/red/op-20260730-070442.md`.

**Binary gate: green — check this first, always.** `/usr/local/bin/ares` was installed at 07:03:44.6Z, 41
seconds before the op started, with workers up at 07:03:47. #360 is confirmed by
`Operation status heartbeat timed out (Redis unresponsive?)`, `heartbeat_interval_secs`,
`status_changed_at` and the `Enterprise Key Admins` literal that only exists post-#360; #363 by
`exploit credits have no vulnerability record` plus the *absence* of the pre-#363 wording. #361 is not
string-gateable (config only) and was confirmed against the deployed `/etc/ares/config.yaml`. #362 adds no
new literals and was confirmed two ways: `main` is linear #360→#361→#362→#363 with #363's literals present,
and all 57 emitted path records carry `"foothold":"-"`, which only the post-#362 dedup call site produces —
the pre-#362 site passed a credential key.

**Where the evidence below comes from matters.** Roughly half the findings in this section cannot be seen
in the report at all, and two of the report-only readings were **wrong** — see rows 14, 5 and §2.3. The
`ops runtime` headline, the report body, and the orchestrator/role logs disagree in ways that are
themselves findings.

Outcome: 3/3 domains, 2/2 forests, DA+GT everywhere in **16m10s** against 24m for `op-20260730-040759`.
Forest B fell at +13m05s versus +21m. Cost $6.38 versus $6.54.

**Read the three-op trend, not the two-op diff.** Taking the last pre-merge op as the baseline changes the
conclusion, and the previous review of `op-20260730-040759` did not have it:

| | `op-…231346` (pre-merge) | `op-…040759` | `op-…070442` (knobs on) | `op-…213328` (#364–#370) | `op-…053105` (#371–#374) |
| --- | --- | --- | --- | --- | --- |
| Rendered `EXPLOITED` | 26 | 25 | **24** | 27 | 16-of-27 (`ops runtime`, not re-derived) |
| Failed attempts | 18 | 9 | 14 | 14 | 46 `Task failed` |
| ACL successes / attempts | 7 / 4 | 0 / 1 | **0 / 3** | **0 confirmed** / 7 (§7.7) | **0** / 20 `acl_chain_step` |
| ADCS types attempted | ESC2/6/7/9/15 | none of them | ESC2/6/9/15 | ESC2/6/9/15 | **ESC1/3/7/8/11/13** |
| `Pwn3d!` events | — | 0 | 0 | 0 | **13** |
| Wall clock / cost | — | 24m / $6.54 | 16m10s / $6.38 | 24m50s | **1h35m30s / $12.24** |

**The fifth column is not commensurable with the other four, and is marked so rather than silently
aligned.** Its `EXPLOITED` figure comes from `ops runtime`, not a rendered report, and §6.7 documents
those two disagreeing; its failed-attempt count is raw `Task failed` lines rather than report attempt
rows. Do not diff column 5 against column 4 cell by cell. It is trustworthy for the three rows where the
*kind* of change is unambiguous: the ADCS set moved off the dead ESC2/6/9/15 quartet entirely onto types
that convert plus ESC11 (§3.1), `Pwn3d!` broke a three-op zero (§2.3), and the wall clock quadrupled for
the same 3/3 outcome (§7.6).

So the diversity knobs bought back part of the *attempt* breadth that the ten merges cost — 14 failed
attempts against 9, ACL attempts 3 against 1 — and still land **below** the pre-merge baseline of 18 and
4. **No new technique class converted, and the terminal move is unchanged** (`secretsdump -> krbtgt hash`)
across all four. Every newly reached technique hit a capability or authorization wall, not a queue-ordering
one. §8 records what that settles.

**Every row of this table is a rendered-report count, and §7.7 proves that class of number can be wrong.**
The fourth op's `EXPLOITED` count rises to 27 purely on six phantom ACL credits; its real conversion is no
better than the third. Treat the whole table as a comparison of *reports*, not of behaviour, until the
success columns are re-derived from logs — which is the second half of row 0.

Two claims that a two-op comparison invites and the corpus refutes — do not re-file either. ESC2, ESC6,
ESC9 and ESC15 are **not** first-ever attempts: they carry events in 48, 52, 48 and 49 ops respectively,
and `op-20260730-040759` merely happened to attempt none of them. `pywhisker` is **not** a first in 68
ops: it appears in 51 ops and in four of the last six. ESC11 remains the only ADCS type with zero
attempt events corpus-wide (§3.1).

| Merged row | What the op showed | Verdict |
| --- | --- | --- |
| 11 — diversity knobs (§8) | Knobs live in shipped config; attempt breadth partially recovered, terminal path and converted set unchanged | **the experiment ran — see §8** |
| 17 — SID-sourced edges (§1.2b) | **3** RID-519 dispatches, not fewer; the guard is not on the route that dispatched them | **prediction failed, §1.2b** |
| 1 — `pyOpenSSL<25` venv (§7.2) | `pywhisker` reached the wire and failed `INSUFF_ACCESS_RIGHTS` — an authorization failure, not a Python one | **the venv is not the blocker, §7.2** |
| 0 — ACL dispatch collapse (§7.4) | 0 successes, 3 attempts | **unresolved, second op running** |
| 7 — persist `is_admin` (§2.3) | Zero `Pwn3d!` again; 8 credential rows, all `Admin = No` | untestable a second time, §2.3 |
| 3 — cross-forest PtH probe (§2.4) | `netexec_auth` 0; the twin's forest-B half was again roast ciphertext only | precondition reproduced, §2.4 |
| 16 / §6.7 — orphan credits | 29 claimed against 24 rendered; `ops runtime` now prints a warning naming the 5 | mechanism confirmed, defect open |
| 18 — status heartbeat (§4.4) | `ops runtime` rendered #363's split counts and orphan-credit warning | #363's half observed; the heartbeat half does not render on a completed op |
| 9 — membership first-class (§2.1) | `source_members` 0 in the report **and 0 in every log** | no observable effect, now on log evidence |
| 14 — lateral parser arms | **exercised**: `psexec` 16 tool lines, `smbexec` 6, `wmiexec` 0 — and no lateral success rendered | ran, converted nothing |
| 15 — silver ticket (§5.5) | `T1558.002` absent from the report **and from the log's MITRE histogram** | never attempted |
| 5 — timeout keeps stdout (§4.1) | **partly exercised**: `start_responder` ran once; `ntlmrelayx` / `mitm6` 0 executions (every report mention is LLM prose); relay ran as `relay_and_coerce` ×21 | reachable, unproven |
| 10 — roast attribution (§6.1) | `T1558.004` ×3 in the report, **62 stamps in the log**; `T1558.003` ×6 / 21 | holds — stays closed |

**Four findings this op produced that were not in this document**, in ascending order of how much work
they need: §7.5 — the irreversible-mutation guard has silently killed chain edge 1 in every op since
2026-07-28, and the opt-in env var is set nowhere; §3.9 — ESC15 ships with no template name and dies at
the CA; §3.8 — `krbrelayup` is dispatched against `ldap_signing_*` roughly five times and cannot work from
a Linux box, with a separate unregistered `krbrelay` name ENOENT-ing 8 times; and §7.6 — **blue containment
deleted 59 deferred tasks mid-op, including both `acl_chain_step` tasks, which is the entire fate of the
op's ACL chain work.** §7.6 is the one to read first if you care about §7.4: it is a candidate cause that
no previous review listed, and it makes every red-side verification in this file suspect while blue runs in
the same operation. §1.2b gains a fourth paragraph for the #360 route miss.

**One correction, narrower than the previous revision made it: ESC2 and ESC6 are not ares *cert-request*
defects.** Both requested and *received* a certificate, then failed `certipy_auth` with
`Object SID mismatch` because the CA stamped the requester's RID into the security extension instead of
RID 500. That is KB5014754 strict mapping behaving correctly, and no change to the request path fixes it.
That much stands.

**The previous revision then generalised that into "the lab winning by design — do not file it as coverage
work", and that half is withdrawn.** The uncrackable-password analogy does not hold: that has no fix, and
ares already ships this one. The `sid` parameter that satisfies KB5014754 is passed **deterministically**
by the ESC1 chain (`adcs_exploitation.rs:795`, `:932`) and is only *suggested to the LLM* for ESC6:
`"IMPORTANT: Include 'sid' param (admin_sid) to avoid SID mismatch."` (`:2126`). Deterministic chains
exist for ESC1/3/4/7/13; ESC2, ESC6, ESC9 and ESC15 have none. The converted set in §8
(ESC1/ESC3/ESC8/ESC13) and the failing set (ESC2/ESC6/ESC9/ESC15) split along close to that same line.
`Object SID mismatch` is the exact signature of the `sid` argument not being passed, which makes this a
dispatch-reliability question and not an environmental wall. Filed as **§3.10**.

**One claim from the previous revision is itself withdrawn: ESC9 is not the shipped bypass.** The template
is real and does carry `CT_FLAG_NO_SECURITY_EXTENSION` (live: `ENROLLFLAG=524329`,
`NO_SECURITY_EXTENSION=True` in the forest-B config NC), but a certificate carrying *no* SID extension is a
**weak** mapping, and Full Enforcement denies weak mappings outright. ESC9 dies on the same DC for the same
reason as ESC2 and ESC6, so it rescues nothing. Corrected in §3.10.

### Operation verdict — `op-20260730-213328`, 2026-07-30, 24m50s

**The first op to run against #364–#370, and the one that invalidated this document's trust rule.** Report
at `reports/red/op-20260730-213328.md`. Outcome: 3/3 domains, 2/2 forests, DA+GT everywhere, 250 vulns
discovered. Read the headline numbers with the correction below before quoting any of them.

**Binary gate: green.** `/usr/local/bin/ares` installed 21:32:29Z, **40 s** before the 21:33:09Z start.
Shipped-code literals confirmed present for #365 (`Dropped a secret parsed from an LLM-directed shell`), #367
(`Base64-encoded PKCS#12 certificate`), #368 (`Skipping ADCS finding with no executor`) and #369
(`delete the created machine account`). #366 touches only `ops loot` rendering and #370's code half is a
guard clause, so neither is string-gateable; #370's merge at 21:27:51Z precedes the build by 4m38s.

**The operating box is the EC2 instance, not attacker-1.** attacker-1's `/usr/local/bin/ares` is dated
2026-06-25 and has nothing to do with these ops. Reach the real box with `task ec2:exec`; note its
precondition breaks on any `CMD` containing a double quote, so pipe a base64'd script instead.

**The apparent result — 7 ACL successes, ending a two-op drought — is false.** Six of the seven
`Vulnerability exploited: acl_*` rows carry task ids that the log records as `WARN Task failed`, every one
with the same cause: `pywhisker` planted the shadow credential and generated a PFX, then the agent had no
`certipy_auth`/PKINIT tool to convert it, and gave up with `Assistance needed`. The seventh
(`exploit_26b31e8f435e`, a `privesc`-role task) has no matching failure line and is **unconfirmed in either
direction**. So the honest count is **0 confirmed ACL successes, 1 unresolved** — a third consecutive op at
or near zero, not a recovery. §7.7 has the mechanism, §7.4 the revised table.

| Signal | Reading | Verdict |
| --- | --- | --- |
| ACL conversion | 7 timeline rows, ≥6 backed by failed tasks | **phantom — §7.7** |
| `dacl_abuse` / `auto_dacl_abuse` | **0** log lines, third op running | §7.4 unresolved |
| `acl_chain_step` | 16 lines / 3 from `auto_acl_chain_follow` — the sequencer ran far more than the 3 and 2 of the prior ops | partial gain, converted nothing |
| Blue containment drops | **60** deferred tasks, incl. **2** `acl_chain_step` | **§7.6 third reproduction** |
| `Pwn3d!` / `Admin access confirmed` | 0 / 0; all 8 credential rows `Admin = No` | rows 7 + 21 untestable a third time |
| `netexec_auth` | 0 | row 3 unexercised |
| `psexec` / `wmiexec` / `smbexec` | 0 | row 14 unexercised |
| `T1558.002` | 0 | row 15 unexercised |
| `source_members` | 0 | row 9 still no effect |
| `krbrelayup` | 4 dispatches | row 19 confirmed live |
| ESC15 | 2 dispatches | row 20 confirmed live; #368 exempts `esc5`/`esc14` only |
| ESC2 / ESC6 / ESC9 | 1 failure each | §3.10 holds |
| `T1558.004` / `T1558.003` | 3 / 6 | roast attribution stays closed (§6.1) |

**The exploited-count arithmetic got worse, not better.** Success Metrics claims **32**, exactly **27**
records render `EXPLOITED`, and the timeline carries **23** `Vulnerability exploited` rows. That is three
mutually irreconcilable numbers from one op, where §6.7 documented two — and with §7.7 in hand, the 23 is
itself inflated by at least six. #366 shipped in this binary and changed the supersession accounting
without closing any of the three gaps.

**What this op does establish.** `pywhisker` runs, authenticates, resolves its target and writes
`msDS-KeyCredentialLink` — four ops after §7.2 first suspected the venv and one after that question closed. The
shadow-credential primitive works on the wire. It is stage two that is missing, and that is a smaller and
far more actionable gap than anything §7.4 has been chasing.

### Operation verdict — `op-20260731-053105`, 2026-07-31, 1h35m30s, $12.24

**The first op to run against #371–#374, and the one that closes this document's phantom-credit finding.**
Outcome: 3/3 domains, 2/2 forests, DA everywhere, golden ticket on 2/3. 27 exploitable vulns (16
exploited), 232 findings (7 exploited).

**Binary gate: green.** `/usr/local/bin/ares` installed 05:30:06.7Z, **41 s** before the 05:30:47Z start.
Gated on one shipped literal per PR: `Mutation policy: irreversible tools` (#374),
`ADCS exploit skipped: certipy_request requires a template` (#374), `Password reset confirmed` (#372),
`Discovery: credential published` (#372/#373), and `certipy_auth` at 44 occurrences (#371). #371's removal
half is gated the other way and is the cleanest of the six: `krbrelayup` matches **0** times in the
binary, against a tree that previously carried a dispatch arm, an LLM schema, a MITRE mapping, three
priority weights, a teardown entry and its own driver.

**Read the runtime before anything else: 1h35m30s against 16–25m for the previous four ops, at $12.24
against $6.38.** Same 3/3 outcome, four to six times the wall clock and roughly double the cost. Nothing
below explains it and no row in this document predicts it. It is the most important unattributed signal
this op produced, and it should be the first thing the next op instruments — a fifth column on the trend
table, not a footnote.

| Signal | Reading | Verdict |
| --- | --- | --- |
| `Vulnerability exploited: acl_*` | **0**, against 7 phantom rows last op | **§7.7 defect B closed** |
| `Shadow credential written but never converted` | **7** | the 7 phantoms are now 7 counted failures |
| `certipy_auth` stage two | reached the wire, died `cannot load PFX` ×4 | **§7.7 defect A — new blocker** |
| `pywhisker` / `msDS-KeyCredentialLink` | 45 / 10 | stage one still works |
| `Mutation policy: irreversible tools REFUSED` | **7 workers announce it at startup** | **§7.5 measured, not inferred** |
| `Password reset confirmed` | **0** — the tool is refused, so #372's reset half cannot fire | §7.5 is the cause, not #372 |
| `Discovery: credential published` | **3** | #372/#373 observed working |
| `Pwn3d!` | **13**, 4 admin upgrades, 2 distinct principals | **§2.3 / row 7 closed** |
| `krbrelayup` | **0** in binary, **0** dispatches | **§3.8 closed** |
| ESC11 | **40 lines, real dispatch**, relay chain entered | **§3.1's premise is dead — see below** |
| ESC15 / template-gate skips | 0 / 0 | §3.9 **untested**, not disproven |
| `dacl_abuse` | **0**, fifth consecutive op | §7.4 unresolved |
| `acl_chain_step` / `auto_acl_chain_follow` | 20 / 6 | sequencer up from 16 / 3 |
| Blue containment drops | 238 deferred-task lines | **§7.6 fourth reproduction** |
| `source_members` | 0 | §2.1 still no effect |
| `netexec_auth` / `wmiexec` | 0 / 0 | rows 3, 14 unexercised |

**§3.1's central claim is now false and the section must not be worked from as written.** That section
rests on ESC11 having produced *zero attempt events in 94 operations* — "ESC11 alone has never produced an
attempt", offered as the evidence that ranking cannot explain it and starvation can. This op dispatched
ESC11 for real: `relay chain dispatched`, `esc_type="esc11"`, an `adcs_esc11_*` vuln_id on the forest-B CA
host, and a relay chain that walked **multiple coerce candidates in sequence**, each logging
`candidate produced no PFX — trying next`. So ESC11 is neither gated nor starved. It is dispatched, it
enters the chain it was wired for, and it fails at **coercion** — no candidate yields a PFX. That is a
different defect in a different place from either lead §3.1 carries, and both leads are now spent.

**One reading that looks like a win and is not: `T1558.002` appears 3 times and none of them is red.** All
three are `Forged-ticket correlation re-checked at investigation close … rule="silver_ticket…"` — blue's
detection rule closing an investigation, not a red silver-ticket attempt. Row 15 stays open and unexercised
for the fourth op running. Recorded here because the grep that finds it is the obvious one and the
conclusion it invites is wrong.

### Ground rules for picking up an item

- **Gate clippy on two toolchains.** Run `cargo clippy --workspace --all-targets --keep-going` under
  the default toolchain *and* under 1.97. CI's Clippy job floats to latest stable and runs
  `--workspace`, while the *required* pre-commit hook runs `--all-targets`. Neither is a superset of
  the other, so a lint that only fires inside a test module fails the required check while the Clippy
  job stays green.
- **Add no code comments.** Rationale belongs in the PR body, not the diff. Rustdoc on new public
  items is fine where the surrounding file already documents everything — that is the local
  convention, not an exception to the rule.
- **A fix is not done at `unit`.** Per the legend, only `op` closes an item. Landing `✔ code` +
  `unit` means the item stays open with a Status line, not that it moves to §0.
- **Do not commit or push** unless the operator explicitly asks.
- **Branch from `origin/main`, never from another feature branch.** This repo's workflows gate on
  specific branch names, so a PR stacked on a feature branch runs zero CI — including the required
  Pre-commit and Semgrep checks — while still reading as mergeable.

### Cheap items with no overlap

Safe to work in parallel — nothing is claimed, so the only overlap risk is between these items themselves.

- **WriteOwner primitive (§5.1, priority 8)** — new tool in `ares-tools/src/acl.rs`, schema in
  `ares-llm/src/tool_registry/acl.rs`, a driver, and a parser arm. *Overlap*: none.
- **`is_lsassy_noise` discards the failure reason (§4.2)** — confined to
  `ares-tools/src/parsers/credential_tools.rs`. *Overlap*: none.
- **ESC11 `listener_ip` gate (§3.1)** — confined to
  `ares-cli/src/orchestrator/automation/adcs_exploitation.rs`. *Overlap*: none. **Read §3.1's
  Correction first** — the `listener_ip` gate is almost certainly *not* what blocks ESC11, since ESC8
  clears the identical gate and has successes. Starting from this bullet's framing wastes the work.
- **ESC11 reported as ESC8 (§3.1, second paragraph)** — one hardcoded message at
  `ares-tools/src/parsers/mod.rs:514`. *Overlap*: same file as priority 3's new parser arm, different
  function; a one-line change, so take it early or late rather than concurrently.

---

## 0. Closed since the previous revision

Removed from this document because they now work or are fixed. Listed so the deletions are auditable
and nobody re-files them.

| Former item | Resolution |
| --- | --- |
| `seimpersonate` phantom credit (was priority #1) | Fixed, `f49d303` / #325, 2026-07-28. 61 historical reports carry the old stamp; the four ops after it render `Not Exploited` with the lead still published. |
| "ACL abuse has one success ever, dead since 2026-06-09" | Wrong, but **this correction is now itself in doubt.** The 33 "real ACL successes across 5 ops" were counted from timeline rows, and §7.7 shows a failed task can render one. Re-derive from logs before relying on the number; the evidence gate (#327, 2026-07-29) is unaffected. |
| Missing parser arms: `certipy_esc4_full_chain`, `certipy_esc7_full_chain`, all four `ntlmrelayx_*`, `start_mitm6`, `mssql_ntlm_coerce`, `nopac`, `printnightmare`, `laps_dump` | All have arms as of `1ec9790`, 2026-07-28. The `_ => {}` fallthrough moved to `parsers/mod.rs:724`. `laps_dump`'s arm was always there, at `mod.rs:721`. |
| `is_acl_mutation_vuln()` misses the `gpo_` prefix | Fixed. `result_processing/mod.rs:1165` matches `acl_` and `gpo_`, with a test at `result_processing/tests.rs:1346`. |
| `golden_ticket_` missing from `is_ticket_grant_vuln()` | Fixed, `result_processing/mod.rs:1149`. |
| `lateral_` / `privesc_` task-id prefixes can never reach `mark_exploited` | Fixed. The gate is now `is_exploit_scoped_task_id` (`mod.rs:290`, `:1170`), accepting `exploit_`, `lateral_`, `privesc_`. |
| "Unconstrained delegation is dead, last success 2026-06-18" | A third success landed 2026-07-29. Still weak (3 in 93 ops), not dead. |
| Shadow credentials "attempted 67 ops, 0 successes, unproven post-fix" | Now proven to work on the wire — see §7.2, where a success was lost to a Python dependency. |
| AdminSDHolder "uncategorized, may not be discoverable" | Resolved as a confirmed dead end — see §3.4. |
| "Cap ACL queue depth to fix conversion" | Would fix none of §1.2's five blockers. The ranking already sorts privileged-reaching edges first. |
| `T1558.004` (AS-REP roasting) never emitted; `T1558.003` credit rides the S4U event | **Closed by `op-20260730-040759`** — the first `op` verdict in this document. `T1558.004` fired twice and `T1558.003` attached to 4 roast-hash events. `#350` + `#354`. The subsection's *other* two bullets stay open (§6.1), and the credit half opened a new defect (§6.7). |
| "The GPO driver has never run in a recorded operation" | Wrong as of `op-20260730-040759` — it dispatched three times. Corrected in place at §3.2 rather than closed; the technique still lands zero successes. |
| ESC11 "has no `vulnerability_priorities` weight" | Disproven — it renders `Priority: 4`. Lead retracted in §3.1; the ESC8-contention lead survives and is now the only one. |
| "The `pyOpenSSL<25` venv on the box is unconfirmed" (was priority 1) | Closed `env`. `op-20260730-070442` got `INSUFF_ACCESS_RIGHTS` from the DC rather than a Python error, and `op-20260730-213328` had `pywhisker` write `msDS-KeyCredentialLink` successfully six times (§7.7). The venv works; stage two is what is missing. |
| "Roast MITRE attribution is wrong" (was priority 10) | Closed `op` — `op-20260730-040759` fired the project's first two `T1558.004` events and attached `T1558.003` to the roast hashes; `op-20260730-213328` reproduced at 3 and 6. The subsection's other two bullets stay open (§6.1). |
| §7.7 defect B — a failed shadow-cred task is credited `EXPLOITED` | Closed `op`, #371, `op-20260731-053105`. `Vulnerability exploited: acl_*` went 7 → **0**, and the same 7 events now log `Shadow credential written but never converted`. This is the phantom that forced the trust-rule rewrite; defect A stays open with a **new** blocker (§7.7). |
| §3.8 `krbrelayup` dispatched every op on a Linux box | Closed `op`, #371, `op-20260731-053105`. Technique removed outright — 0 occurrences in the deployed binary, 0 dispatches. The target-selection payoff it predicted is **not** yet verified (§3.8). |
| §2.3 bullet 2 — `is_admin` never persists | Closed `op`, #355, `op-20260731-053105`. First admin-flagged credential in the corpus after 443 rows of `Admin = No`. Bullets 1, 3 and 4 stay open (§2.3). |
| §7.5 "nothing said so" | Closed `op`, #374, `op-20260731-053105` — 7 workers announce the mutation policy at startup. **The refusal it announces is still in force**, so the block itself stays open and is now the confirmed cause of #372's reset half never firing (§7.5). |

**A parser arm existing is not a technique working.** Several rows above closed because an arm was added;
none of them has produced a success in an operation since. `✔ code` on a parser arm means the arm exists,
nothing more — which is the same distinction the legend draws and the reason this section is short.

**Nothing reaches §0 on a code proof alone.** Two items were briefly pruned here on 2026-07-30 —
the §4.1 timeout path (#353) and §6.6's realtime credit (#354) — and both were **restored to open**,
because `✔ code` + `unit` does not close an item however conclusive the grep is. They are the exact
shape the ground rule exists to catch: the defect is provably gone from the tree, and that is not the
same claim as the technique working. Their Status lines carry the code proof; only an op moves them.

---

## 1. The dominant mechanism: escalation needs identities that only arrive as loot

This is one bug class wearing five costumes, and it accounts for more missed lab content than every
missing tool combined. In each case ares eventually holds exactly the identity the lab intends as the
*entry* to an escalation — but only as output from the DCSync that escalation was supposed to enable.

### 1.1 Evidence

**Every ACL success in the corpus postdates Domain Admin in its own operation.**

| Op | First DA | First ACL success | Delta |
| --- | --- | --- | --- |
| 2026-06-09 (late) | 18:34:29 | 18:42:51 | +8m22s |
| 2026-07-29 (055708) | 06:04:00 | 06:04:56 | +56s |
| 2026-07-29 (182329) | 18:27:19 | 18:29:20 | +2m01s |
| 2026-07-29 (201720) | 20:19:07 | 20:20:11 | +64s |
| 2026-07-29 (231346) | 23:16:33 | 23:28:04 | +11m31s |
| 2026-07-30 (040759) | 04:11:42 | **never** | — |
| 2026-07-30 (070442) | 07:08:01 | **never** | — |
| 2026-07-30 (213328) | 21:42:40 (child) / 21:43:35 (root) | 21:43:46 — but **phantom**, §7.7 | +11s |

The last row would have been the strongest evidence in this table — an ACL credit 11 seconds after root-DA,
tightening the pattern further — except that the credit is for a task the log records as failed. It is
listed to make the point that this table's method (read the timeline, diff against DA) cannot tell a real
success from a phantom, and that the five pre-collapse rows above were built with that same method.

The last two rows do not fit the pattern: no ACL success occurred in either, and the whole-operation ACL
attempt count was 1 then 3. That is §7.4, and it is a regression rather than a data point about ordering.
Note what the second row adds — the three attempts all landed at 07:14-07:16, six to eight minutes *after*
the child domain was already dominated, so whatever gated them it was not §1.2 blocker 2's
`dominated_domains` window. They arrived through the LLM route, which that gate does not cover.

Provenance confirms it: in every landed edge the source principal's auth material came from
`secretsdump`. The one exception in 93 ops is the forest-B AS-REP account's GenericWrite, 13 s after
its crack — genuinely pre-compromise, produced no usable credential, fed nothing.

Same shape elsewhere:

- **gMSA-reader machine account**: held in 35 ops; in **35/35** the same report contains the forest-B
  `krbtgt` hash via `secretsdump`. The gMSA's own NTLM is held in 34 ops from the same dump.
- **LAPS-reader**: NTLM held in 34 ops, `Source = secretsdump` in **34/34**, plaintext never cracked.
  Every pre-DA `laps_dump` therefore authenticates as a non-reader and returns an empty result.
- **The gMSA's GenericAll edge** was exploited exactly once, **34 seconds after** forest-B DA, using a
  credential from that DCSync.
- **ACL chain roots** (edges 1, 3, 4, 6, 7 sources) enter `owned_principals()` by no route except a
  DCSync of their own domain.

### 1.2 Why chains never advance — five blockers

Multi-hop dependency *is* modelled (`acl_graph.rs`, #276/#284/#306/#327, 2026-07-26 → 29). The model
is not the problem.

1. **Chains can only be rooted at already-owned principals.** `acl_graph.rs:408-428` seeds
   `walk_chain` exclusively from `owned_principals(state)` (`:255-273`). The chain's entry point is
   only unlocked by the thing the chain was supposed to achieve.
2. **The credential gate and the domination gate are mutually exclusive.** `dominated_domains` is set
   the instant a `krbtgt` hash publishes (`state/publishing/credentials.rs:314`), after which both
   drivers abandon the domain (`automation/acl.rs:213`, `dacl_abuse.rs:236`). But the same
   `secretsdump` is the only source of the chain principals' material. The dispatchable window is the
   few seconds between two hashes out of one dump — exactly the +56 s / +64 s clustering above.
3. **The dispatchers are the wrong shape.**
   - `dacl_abuse.rs:212-224` matches source principals against `state.credentials` only. Hashes are
     never consulted, so hash-only principals never dispatch here.
   - `shadow_credentials.rs:53-56` skips any `target_type` that is not `user`/`computer`/`unknown`, so
     **every group-target edge is invisible to it** — edges 5, 6, 7, the root-domain
     GenericAll-on-a-privileged-group edge, and the cross-forest computer-target edge all have zero
     dispatch events, while a user-target edge from the same source has 59.
   - Group-*sourced* edges need `source_members` to yield a principal (`acl_graph.rs:169-173`), which
     only the BloodHound collector parser populates. No report in the corpus contains that field, so
     these edges reach only the generic `request_exploit` route where the LLM guesses the auth
     principal. Observed guesses for edge 4: five wrong principals plus a service account.
   - `dacl_abuse.rs:283-289` derives `dc_ip` from `cred.domain` rather than the **edge's** domain, so
     it binds the child DC for root-domain objects.
4. **`MAX_HOPS = 4` (`acl_graph.rs:24`) is less than the canonical chain's 8 edges.** The chain cannot
   be materialised even in principle. `walk_chain` is greedy-toward-terminal, so it prefers 1-hop
   shots over the designed path and degrades everything else to a single-edge "unprivileged" chain
   (`:429-456`).
5. **An edge's output re-enters the queue only through LLM goodwill.** No parser arm exists for
   `bloodyad_*`, `pywhisker` or `dacledit` (verified: 0 matches in `parsers/mod.rs`), so a landed
   write becomes a capability only if the LLM voluntarily calls `report_finding`. Also
   `acl_graph.rs:118` drops exploited vuln_ids from the graph, which changes `chain_id` (a hash of
   step vuln_ids) and invalidates the `chain:{id}:step:{n}` dedup key the sequencer needs to advance.

**Status**: two of blocker 3's four bullets are addressed as a side effect of the §7.1 work —
Implemented `✔ code` — merged to `main` as `d9d7dd8` / #350 — Verified `unit`. Those are the first bullet (`dacl_abuse.rs` now falls back to
`find_source_hash`, so hash-only source principals dispatch) and the fourth (dispatch domain now derives
from the resolved auth principal rather than specifically a credential's domain, so root-domain objects
no longer bind the child DC). Blockers 1, 2, 4 and 5, plus the two group-shaped bullets of blocker 3
(the `shadow_credentials.rs` group-target skip and the group-sourced `source_members` dead end), are
`—` / `—`.

**Blocker 2 is now measured, not inferred.** `op-20260730-040759`'s orchestrator log contains exactly
five `acl_chain_step` lines, all within one 700 ms burst at 04:09:42 — `auto_acl_chain_follow` produced
three chain steps and **never fired again for the remaining 21 minutes**. First DA landed at 04:11:42 and
the second domain at 04:12:32, so `dominated_domains` closed the window 2m50s after the sequencer's only
tick. `dacl_abuse` produces no log line at info level anywhere in the op, and `/var/log/ares/acl.log`
never advanced past its 04:07:02 deploy-time mtime while every other role log advanced — the ACL worker
executed nothing.

**A third gate, not previously in this list: the deferred queue.** All three of those chain steps were
admitted (`Soft cap: allowing — role below minimum llm_count=14 max_tasks=12 role="acl" role_count=0`)
and then **deferred** rather than dispatched. The same window carries 223 `Deferred queue full`, 74
`Deferred queue full while gating on cred` and 27 `Deferred queue stale eviction` lines, against 287
deferred `recon` tasks, 107 `coercion` and 99 `credential_access`. Three `acl_chain_step` tasks
competing against that volume, in an op that terminated on objective-achieved 21 minutes later, never
ran. Note what this means for the queue-cap proposal §0 rejected: capping the ACL *publish* volume does
nothing here, because the loser is a task that was already built and admitted.

### 1.2b SID-sourced edges resolve to a non-member — found live, `op-20260730-040759`

`resolve_sid_principal` (`automation/dacl_abuse.rs:393-406`) picks the auth principal for an edge whose
source is a raw SID. It first looks for `c.is_admin && domain matches`, then **falls through to an
unconditional** `find(|c| c.domain.to_lowercase() == resolved_domain)` — any credential in the domain,
with no privilege check at all.

The function's own doc comment justifies SID resolution for well-known RIDs (512/518/519/520/526/527) on
the grounds that "the abuse only requires *a* member of the group". The fallback drops the privilege
requirement, so it can hand the edge to a **non-member**, which voids that justification.

Observed live: an `allextendedrights` edge sourced from RID **519 (Enterprise Admins)** targeting the
`account operators` group was dispatched with an ordinary user's credential, because every credential in
state was `is_admin: false` at that moment. The agent answered exactly as you would expect —
*"Need ACL edge details to exploit: we have credentials for <ordinary user>"* — and the dispatch was
unwinnable from the start. This was the **only** ACL exploit attempt in the run's first 30 minutes.

Note the interaction, which runs the opposite way to intuition: this pathology is *masked* by
`is_admin` never persisting, and priority 7 (#355) fixes that persistence. As admin flags start
sticking, the first branch will fire more often and pick an actual admin — so #355 should reduce this,
not amplify it. The fallback is still wrong on its own terms and should return `None` for a well-known
privileged RID rather than an arbitrary principal: a dispatch that cannot succeed costs a queue slot,
an LLM turn, and a `dacl_abuse` dedup entry that suppresses the edge from being retried later.

**Confirmed as the op's only ACL activity of any kind.** It was not merely the first 30 minutes — it was
the whole operation. The `acl`-role agent burned one turn on it at 04:16:11 and asked for four things the
world model cannot supply: which account the RID resolves to, whether the credential it holds *is* that
principal, the group object's DN and domain, and whether the rights include AddMember. Items 1 and 3 are
§2.1 (no group entity, no SID on `User`); item 4 is the ACE right the edge record already carries and the
prompt does not forward. The agent also flagged that the task named the forest-B DC while the ACL record
named the child domain — the wrong-DC binding of §1.2 blocker 3's fourth bullet, which #350 claims to have
fixed, still reaching the prompt.

The masking interaction described above did **not** resolve: #355 shipped in this binary, but the op
produced zero `Pwn3d!` events, so no credential was ever flagged admin and the fallback ran exactly as
before. #355 cannot reduce this pathology in an op where admin discovery never fires.

**Status**: `✔ code` — **PR #360**, commit `d4e3888` on branch
`fix/sid-principal-membership-and-op-heartbeat` (based on `7f80957`) / Verified `unit`. **Not verified in
a live operation.**

The unconditional in-domain fallback is gone. `is_privileged_well_known_rid` became
`well_known_privileged_group`, which returns the group *name* rather than a boolean, so the resolver now
has something to check membership against. Resolution order: an `is_admin` credential in the domain
(unchanged), else a credential whose principal LDAP `memberOf` places it in the group that RID names,
else `None`. The membership arm reuses `members_from_ldap` from `acl_graph.rs` — the same helper #356
added — which is why this fix only became possible after that landed: before `memberOf` survived the
serde boundary there was no membership evidence to consult, and `None` would have been the only
available answer.

Six tests, the load-bearing ones being `sid_source_never_resolves_to_a_non_member` (the exact live
failure: RID 519, one ordinary credential, no admin flag) and
`sid_source_membership_is_matched_against_the_rids_own_group` (membership in Enterprise Admins must not
satisfy a Key Admins edge — the bug a name-blind membership check would have introduced).

What this does not do is make the edge *winnable*. It stops the doomed dispatch from consuming the
queue slot, the LLM turn and the dedup entry; whether a real member is ever owned is §2.1 and §1.4.
Expect the visible effect in the next op to be **fewer** ACL dispatches, not more — a nil ACL count
after this lands is the fix working, not a regression.

**That prediction failed, and the reason is that the guard is not on the route these dispatches take.**
`op-20260730-070442` ran with #360 merged and produced **three** RID-519 dispatches rather than fewer —
one each against a service account, `krbtgt` and `administrator`, every one bound to an ordinary
unprivileged principal, exactly the pathology this subsection describes. The mechanism:

- `resolve_sid_principal` is reached from **one** call site, `dacl_abuse.rs:232`. The fix guards that
  driver and nothing else.
- The ACL *chain* driver resolves principals through `resolve_step_principal` (`automation/acl.rs:117`),
  which looks up `state.credentials` by `username == source_user` and then `state.hashes` the same way.
  It has **no SID handling at all**, so a raw-SID source matches nothing and the step `break`s — this
  driver never produced these dispatches either.
- All three failures render `Assistance needed:` and ask the agent-facing questions, which is the
  signature of the generic LLM `request_exploit` route — §1.2 blocker 3's third bullet. **No SID guard
  exists on that route.**

So #360 is not disproven; it is bypassed. The work it still needs is a guard at the point where a
raw-SID-sourced edge becomes an LLM task, not only where `dacl_abuse` builds one. Until then row 17 cannot
be evaluated by operation at all, which is the same trap §8 describes for the ACL rows generally.

Two smaller notes from the same three failures. Two of the three died inside the agent turn on the
irreversible-mutation guard rather than on principal resolution (§7.5) — so even a correctly resolved
member would have failed them. And `resolve_sid_principal`'s prefix test is
`source.starts_with("S-1-5-21-")`, case-sensitive; the vuln_ids render the SID lowercased. Whether the
`source` field itself preserves case is unverified, and if it does not, the guard returns `None` at
`:377-379` for every edge and the membership arm is dead code. That is one grep on an ACL edge record and
worth doing before any further work on this row.

### 1.3 Per-edge state of the canonical 8-edge chain

| Edge | Right | Status |
| --- | --- | --- |
| 1 | ForceChangePassword (user→user) | **Dead since 2026-07-28 — hard-blocked, not merely unproductive.** The 9 resets across 7 ops all predate #308's irreversible-mutation guard; since it landed, every single `bloodyad_set_password` invocation in the corpus is a refusal. See §7.5. Zero `acl_forcechangepassword_*` timeline events, before or after. |
| 2 | GenericWrite (user→user) | 2 successes, after 78 failures. |
| 3 | WriteDacl (user→user) | **Regression** — 47 failed dispatches through 2026-07-27, then **zero dispatches at all**. See §7.1; re-route is `✔ code` / `unit`, not yet seen in an op. |
| 4 | Self-Membership / AddSelf (user→group) | 7 failures, 7 ops. Primitive exists; bound as the wrong principal every time, and against the wrong DC. |
| 5 | AddMember (group→group) | 7 failures. One returned `entryAlreadyExists`; the LLM asked for the next edge and nothing answered. |
| 6 | WriteOwner (group→group) | **No primitive exists.** See §5.1. |
| 7 | GenericAll (group→user) | Never dispatched — group-target skip (§1.2.3). |
| 8 | GenericAll (user→computer, RBCD on a DC) | 6 successes, after 123 failures. |

Maximum consecutive run ever achieved: **1**. The forest-B sequence that appears to walk three edges
in order had all three principals' hashes published one second before the first step; a second op
credits the same three edges within 2 seconds of each other, i.e. in parallel.

### 1.4 What to do about it

The cheap probe is to **root chains at crackable identities rather than owned ones**. Two lab
identities are reachable pre-DA — the initial-access account (`description` field) and the forest-B
AS-REP account (cracked in 65 ops) — and the one genuine pre-DA ACL abuse in the corpus came from the
latter. Feeding `walk_chain` from "principals we can plausibly obtain in one hop" instead of
`owned_principals` is a smaller change than raising `MAX_HOPS`, and it is the only change that can
move an ACL success *before* DA.

**Status**: `✔ code` — merged as `a4bfd47` / #352 / Verified `unit`. **The live operation ran and the
result was negative**: `op-20260730-040759` produced zero ACL successes and one ACL attempt. See §7.4 —
the op is evidence of a regression in this area, not of this change working, and the two cannot be
separated without a targeted re-run.

Implemented as a *seeding* change only. `analyze` (`acl_graph.rs`) now walks chains from
`owned_principals ∪ crackable_principals`, where the new `crackable_principals` is every principal
holding **uncracked** Kerberos roast material (`$krb5tgs$` / `$krb5asrep$`, or a roast `hash_type`).
Roast ciphertext is deliberately disjoint from `is_usable_hash`, so such a principal is still not
"owned" — the invariant the pre-existing test `roastable_ciphertext_does_not_own_its_principal` was
written to protect, which is preserved and now asserted directly against `owned_principals` rather than
via the weaker `chains.is_empty()` proxy that this change necessarily invalidates.

Dispatch behaviour is unchanged, which is what makes it safe: `collect_acl_chain_work`
(`automation/acl.rs:208`) resolves each step's principal through `resolve_step_principal`, whose hash
branch filters on `is_usable_hash`, so a speculatively-seeded chain resolves to `None` and `break`s
instead of dispatching a doomed step. Pinned by two tests — one asserting a roast-only source does not
dispatch, one asserting it dispatches as soon as the crack lands.

Speculative chains cannot displace actionable ones: chains now carry a `root_owned` flag and the
privileged/unprivileged sorts key on it first, so owned-rooted chains always take `MAX_CHAINS` capacity
ahead of crackable-rooted ones. Prior behaviour is therefore a strict subset of the new behaviour.

**Correction — the strict-subset claim covers ranking only, and two other paths were not considered.**
Both were found by reading the code after §7.4, and neither is proven to have fired in the op; they are
the leads a re-run should instrument.

- **`find`-first principal selection.** `edge_principals()` (`acl_graph.rs:223-227`) returns
  `[edge.source] ++ edge.source_members`, source first, and the single-edge loop takes
  `find(|p| seeds.contains(p))`. Widening `seeds` from `owned` to `owned ∪ crackable` means an edge whose
  *source* holds only roast ciphertext now matches at position 0, where before the scan fell through to a
  `source_members` entry that was owned. At dispatch, `resolve_step_principal`
  (`automation/acl.rs:117-141`) filters hashes on `is_usable_hash`, roast ciphertext fails it, and the
  caller `break`s (`:207-209`) — so the edge yields no work where it previously yielded a dispatch. This
  is the safety property §1.4 relies on, viewed from the other side: the doomed step does not merely fail
  to dispatch, it *replaced* a step that would have.
- **`seen_chains` steals rather than re-ranks.** `chain_id` hashes the step **vuln_ids**, which name
  edges, not principals. Two roots in the same group traverse the same edges via `by_principal`, so they
  produce an *identical* `chain_id`; `starts` is sorted alphabetically, and the first arrival inserts
  while the second is `continue`d and dropped outright. An alphabetically-earlier crackable root therefore
  deletes the owned-rooted duplicate instead of sorting behind it, and the survivor carries
  `root_owned: false` and an unusable principal.

PR #356 plausibly amplifies both, since populating `source_members` from LDAP `memberOf` is precisely
what enlarges the pool of owned members that the old fall-through used to reach.

What this does **not** fix, and should not be read as fixing: blockers 1, 2, 4 and 5 of §1.2 all stand.
The mechanism it targets is narrow — a chain whose root is a roastable account can now be built and
ranked *before* the DCSync that would otherwise be the only way to learn that principal, so the step
fires when the crack lands rather than after DA. On this lab that is one account. Whether it moves an
ACL success before DA is exactly the thing only an op can answer.

**Priority 6 depends on this and is a trap if taken alone.** Emitting `laps_reader` / `gmsa` vuln types
makes those techniques *queueable*, but §1.1 shows the only LAPS-reader identity ares ever holds arrives
from the forest-B NTDS dump, and the gMSA-reader machine account in 35/35 ops likewise. So a correctly
queued LAPS or gMSA exploit still authenticates as a non-reader on every pre-DA tick and returns
nothing. Whoever picks up 6 should expect zero coverage change until this item lands — the two are one
piece of work in two halves, and 6 is the second half.

---

## 2. Group membership, account flags and per-host rights are not in the world model

`format_state_context()` (`ares-llm/src/prompt/state_context.rs:21-160`) is the complete world model
the LLM ever sees: domains, credentials, cracked hashes, DCs, other hosts, pending vulnerabilities.
**`state.users` is not referenced in that file at all.** Every enumerated user is invisible to the
agent, along with every group, membership, flag and per-host right.

### 2.1 No group entity; membership is collected and discarded

**Partly fixed by `d729e45` / #356, 2026-07-30 — the two claims this subsection used to open with are
now false and have been corrected rather than deleted, because the item as a whole is still open.**
`User` now carries `member_of: Vec<String>` with `memberOf` / `member_of` serde aliases
(`ares-core/src/models/core.rs:80-93`), so `rg -i 'group' ares-core/src/models/` returns 4 matches, not
zero, and `memberOf` is no longer discarded at the serde boundary. `AclEdge.source_members` is seeded
from LDAP instead of BloodHound-only, which closes the group-**sourced** half of §1.2 blocker 3. Still
absent from the model: `sid`, `primary_group_id`, and any group *entity* — `SharedRedTeamState` has no
group collection, so a group is still only ever a string on a principal.

What has **not** changed is the cost described below, because the prompt surface is untouched:
`state.users` still appears **zero times** in `ares-llm/src/prompt/state_context.rs` (re-verified on
`main` 2026-07-30), so memberships now survive into state and remain invisible to the agent. Two of the
three original sinks are also unchanged:

1. `group_enumerated` exists **only** as a string inside a prompt literal
   (`automation/group_enumeration.rs:233`). No consumer. Zero occurrences in 93 reports.
2. `foreign_group_membership` exists only in two prompt literals
   (`automation/foreign_group_enum.rs:130`, `group_enumeration.rs:243`). No consumer, not in
   `is_acl_vuln_type()`, not in any strategy table. Zero occurrences in 93 reports.

**Cost**: the lab's three cross-domain foreign-security-principal memberships are the intended
no-forging path across the trust boundaries. Each of the five relevant groups appears in 74-75 ops —
**every occurrence is an ACL-edge record, never a membership fact**. The legitimate path was
enumerated ~75 times per group and used zero times. All boundary crossings in the corpus are
forge-based (ExtraSid, inter-realm `ticketer`).

This is also a direct cause of §1.2.3: an ACE recorded as `<group> has writeproperty on <computer>`
with no member list names a source principal ares cannot authenticate as.

`AclEdge.source_members` + `expand_members()` (`acl_graph.rs:70-81`,
`ares-tools/src/parsers/bloodhound.rs:278-300`) is the intended fix, landed 2026-07-26/27. It was fed
**only** by BloodHound collector JSON while the ACL volume comes from raw LDAP, which is what #356
addressed by adding the LDAP-side seeding.

**`source_members` still appears 0 times in 93 reports**, including the first op to run with #356 in the
binary. That is not proof the seeding failed — the field may simply not render — but nothing in
`op-20260730-040759` shows a group-sourced edge resolving to a member, and the one ACL attempt it made
failed *because* the source principal could not be resolved (§1.2b). Treat priority 9 as unobserved
rather than working, and note that if the LDAP seeding *is* populating the field, it is a candidate
amplifier for §7.4 — see the correction in §1.4.

### 2.2 `userAccountControl` is requested five times and parsed zero times

Requested at `automation/domain_user_enum.rs:108,193`, `cross_forest_enum.rs:181`, `trust.rs:2206`.
No bit is ever decoded. `NOT_DELEGATED`, `TRUSTED_FOR_DELEGATION`, `0x100000`, `0x1000000`,
`protected_users` — zero genuine hits repo-wide.

Consequences today are latent rather than costly, because the impersonation target is a hardcoded
literal `"Administrator"` in every delegation path (`automation/s4u.rs:505`, `automation/rbcd.rs:208`,
`adcs_exploitation.rs:2353`, `templates/redteam/tasks/exploit_delegation.md.tera:10-14`), confirmed
`impersonate=Administrator` in 45/45 corpus occurrences. So zero attempts were wasted on the lab's
`AccountNotDelegated` account — **by luck, not by design**. Any future work that varies the
impersonated principal has no guard.

The Protected Users member was force-reset in one op and the credential **was never used**, so the
NTLM-refusal failure never occurred. `KDC_ERR_BADOPTION`, `STATUS_ACCOUNT_RESTRICTION`,
`KDC_ERR_POLICY`, `NTLM is disabled` — zero hits in reports and zero classification in code.

The only flag-shaped concept in the system is the opposite polarity: `delegation_accounts` renders
`[DELEGATION ONLY — do NOT use for auth]` in the prompt. There is no negative-flag concept.

### 2.3 Local-admin rights: discovered correctly, scope discarded, boolean not persisted

Ares empirically discovered **all three** of the lab's local-admin grants via netexec's `Pwn3d!`
marker — **32 timeline events across 23 ops**, and the principal-to-host mapping matches ground truth
exactly. Then:

- `detect_and_upgrade_admin_credentials` (`result_processing/admin_checks.rs:263-346`) extracts
  `pwned_ip` at `:284`, uses it transiently, and calls
  `create_admin_upgrade_timeline_event(dispatcher, &username, &domain)` at `:301`. **The host scope is
  discarded in the same function that found it.** `Credential.is_admin` (`core.rs:109`) is a single
  global bool; no `admin_on: Vec<host>` exists anywhere.
- The residual boolean does not persist: **443 credential rows across 93 reports render
  `Admin = No` 443 times and `Yes` zero times**, including ops with a `Pwn3d!` event for that
  principal. `detect_and_upgrade_admin_credentials` mutates the in-memory guard with no Redis
  writeback, and `add_credential` uses `hset_nx` — set-if-not-exists, never update
  (`ares-core/src/state/reader.rs:264-278`). The report reads Redis.
- Every consumer is host-unscoped: `automation/lsassy_dump.rs:76` picks *any* admin credential for
  *any* owned host; same shape at `secretsdump.rs:174,493`, `dacl_abuse.rs:368-372`,
  `credential_expansion.rs:127,148`.
- No local-group enumeration capability exists: `--local-groups`, `local_groups`, `enumalsgroups`,
  `loggedon-users` — zero hits in code, zero in reports.

**Status**: Implemented `✔ code` — **PR #355** (`e9da1e2`, CI 9/9 green), **Verified `op` —
`op-20260731-053105`.** Scope was the first two bullets. The host-unscoped consumers (third bullet) and
local-group enumeration (fourth) are **not** addressed and stay `—` / `—`.

**The persistence half is closed on live evidence, after three ops in which it could not be tested at
all.** #355 shipped in the binaries of `op-20260730-070442` and `op-20260730-213328`, and both produced
**zero** `Pwn3d!` events — so the fix sat in three ops without the input it needed, and this document
recorded it as "untestable a third time" rather than as working. `op-20260731-053105` finally supplied the
input: **13** `Pwn3d!` lines, **4** `Pwn3d! detected -- upgrading credential to admin` upgrades across **2**
distinct principals (the child domain's admin account, recovered from an Autologon registry value, and the
root domain's `Administrator`), and the child-domain credential renders **`(admin)`** in `ops loot`.

That is the first admin-flagged credential in the corpus. The count this section quotes — 443 credential
rows rendering `Admin = No` and `Yes` zero times across 93 reports — is what the `hset_nx` bug produced;
`mark_credentials_admin`'s `hset` writeback survives to the Redis-backed render, which is the exact
property the bullet said was missing.

**Do not read this as the section closing.** Bullet 2 is fixed; bullets 1, 3 and 4 are untouched, and the
host *scope* is still discarded in the same function that discovers it. What has changed is that
`is_admin` is now a value other consumers could key on — which is what makes the third bullet's
host-unscoped credential selection worth fixing rather than academic. §1.2b also predicted that a
persisting `is_admin` would let `resolve_sid_principal`'s first branch fire and pick a real admin; with 2
principals now flagged, that prediction is testable on the next op for the first time.

`SharedState::mark_credentials_admin` replaces the in-memory-only mutation: it flips `is_admin` in
state and rewrites **every** matching Redis field with `hset`, mirroring what `mark_host_owned`
already does for `Host::owned` — whose own comment documents this identical bug class for hosts. All
matching rows are rewritten, not just the first, because the dedup key carries a password digest so
one principal legitimately holds several rows and a stale shadow row would keep reporting it as
non-admin. Redis is reconciled whenever the principal matches, not only on a fresh flip, so an
operation that already mutated memory pre-fix heals on the next `Pwn3d!` line.

The return value is `true` **only** on a genuine `false → true` transition, which preserves two
behaviours worth stating: a repeated `Pwn3d!` line does not re-fire the caller's timeline event and
priority secretsdump, and "no credential for this principal is in state" stays distinguishable from
success. An admin event with no credential behind it is the `seimpersonate` phantom shape from §0, and
a first draft of this fix reintroduced it — the test
`mark_credentials_admin_reports_false_when_no_credential_matches` pins it shut.

**Host scope**: recorded on the admin-upgrade timeline event
(`admin_upgrade_description`), which renders into reports, rather than as a new
`Credential::admin_on` field. Two reasons. `Credential` has 303 struct literals and no `Default`
impl, so a new field is ~300 mechanical edits of pure noise; and more importantly, nothing in scope
would *read* an `admin_on` — adding it would have created a fresh instance of the
capability-with-no-consumer defect this document catalogues in §3.3 and §4.3. The `Admin access
confirmed:` prefix — **trailing space included** — is preserved verbatim, since the Reproduction greps
and 32 historical events key on it.

Verified `unit` — 7 new tests; five assert on **Redis contents** via `MockRedisConnection`, because
the pre-existing sibling test for `update_hash_cracked_password` checks only in-memory state, and an
in-memory assertion passes against the broken code. Suite 4044/1303/421/1621, 0 failed; clippy clean
on 1.94 and CI's 1.97. **Not verified in a live operation** — whether a report now renders
`Admin = Yes` is unproven.

**An op has now run with the fix in the binary and it settled nothing, for an unexpected reason**:
`op-20260730-040759` produced **zero** `Pwn3d!` lines and zero `Admin access confirmed:` events. The
discovery this fix hangs off — the one thing §2.3 opens by praising as demonstrably working, 32 events
across 23 ops — did not happen once. So the 443/0 count above includes an op that ran the fix, and that
is not evidence against the fix. It does raise a separate question worth a grep before the next op: local-admin
discovery is host- and credential-dependent, and an op that reaches DA in under four minutes may never
netexec a member host as a non-admin principal at all. Verifying priority 7 needs an op that produces a
`Pwn3d!`, which is not something the fix controls.

**`op-20260730-070442` fired the discovery once and the report still renders `Admin = No` — and this is
the sharpest illustration in this document of why the trust rule exists.** The report shows zero
`Pwn3d!`, zero `Admin access confirmed:` events and 8 credential rows all `Admin = No`, taking the
corpus to **451 `No` / 0 `Yes`**. The orchestrator log shows the opposite:

```
07:20:10.700574Z INFO Pwn3d! detected -- upgrading credential to admin username=administrator domain=<forest-B domain>
```

One real detection, and `Admin access confirmed` appears **0 times in the log either**. Per §2.3's own
description of the fix, that combination has exactly one meaning: `mark_credentials_admin` returned
`false`, so `create_admin_upgrade_timeline_event` never ran — which is the
`mark_credentials_admin_reports_false_when_no_credential_matches` path, firing because forest B's
administrator was held as a **hash, not a credential row**. #355 behaved exactly as specified and the
discovery was still uncreditable.

So priority 7 is not untestable for the reason previously recorded. The blocker is narrower and now
identified: `detect_and_upgrade_admin_credentials` credits only `state.credentials`, while the principal a
DCSync-driven op actually pwns a host as is hash-only. The same asymmetry that §1.2 blocker 3 fixed for
`dacl_abuse` — falling back to `find_source_hash` — has not been applied here. That is a real, small,
independent piece of work, and it is what row 21 should be about.

Two things this also corrects. Local-admin discovery has **not** stopped — one `Pwn3d!` in this op against
zero in the previous one — so "two consecutive ops with no discovery" would have been wrong; what has
stopped is discovery reaching a report. And the 451/0 corpus count now has a mechanism rather than only a
symptom: hash-only admin principals cannot be credited at all, and a fast DCSync-driven op produces almost
nothing else.

### 2.4 Cross-domain password reuse is visible in ares's own output and never read

The SPN service account has the same password in the child domain and forest B. NTLM is unsalted, so
the hashes are byte-identical, and **in 34 ops both rows appear in the same Hash Material table with
the same NT half**. Never flagged.

- **No reuse *detection* code exists.** Nothing anywhere compares hash values across domains as an
  exploitation signal. The only acknowledgement of shared passwords in the tree is a dedup test
  comment.
- **Reuse *probing* is wired but structurally incapable.** `automation/credential_reuse.rs` matches
  this account twice over (`is_reuse_candidate`, `:30-40`) and correctly declines to skip the
  cross-forest pair (`:43-47`) — but the only thing it ever dispatches is `secretsdump`
  (`:217`, `:274`). That is a DCSync attempt against an account with no replication rights, so a
  genuinely shared password is probed with the one operation guaranteed to fail. There is no plain-auth
  reuse test on this path, and `credential_expansion.rs:62-68` gates lateral auth to the same forest.

The downstream half already works: `build_known_password_wordlist`
(`ares-tools/src/cracker.rs:600-635`) seeds recovered plaintexts first and its own doc comment names
this exact case.

**Correction — the "a few lines" estimate previously carried here was wrong**, and priority 3 in §9 is
corrected to match. The diagnosis above is confirmed at code level: both reuse paths dispatch
secretsdump, at `credential_reuse.rs:217` (`request_secretsdump_hash`) and `:274`
(`request_secretsdump`). The estimate was wrong because it assumed an auth-probe primitive existed to
swap in, and none does:

- The dispatcher exposes exactly eleven `request_*` helpers — `request_recon`,
  `request_low_hanging_fruit`, `request_credential_access`, `request_secretsdump`,
  `request_secretsdump_hash`, `request_lateral`, `request_exploit`, `request_bloodhound`,
  `request_share_enumeration`, `request_share_spider`, `request_coercion`
  (`dispatcher/task_builders.rs:204-726`). **None of them is an auth check.**
- `request_lateral(target_ip, credential, technique)` (`task_builders.rs:431`) takes a `Credential`,
  and `Credential` (`ares-core/src/models/core.rs:97-114`) has **no hash field** — so it cannot carry
  pass-the-hash material even as a workaround.
- No `netexec_auth`-style tool exists. `netexec_auth` appears in the tree only as a *credential source
  string* (`output_extraction/passwords.rs:199`, ranked in `state/publishing/mod.rs:63,98`); there is
  no such tool in `ares-tools/src/lib.rs` and none in the LLM tool registry.

So a pass-the-hash reuse probe is a **capability addition, not an edit**: a new tool in `ares-tools`, a
dispatch arm in `ares-tools/src/lib.rs`, a parser arm (without which the probe is uncreditable — the
exact defect §4 catalogues), an LLM schema, and a dispatcher helper.

The "a few lines" figure remains accurate only for the *other* variant — propagating the plaintext of a
hash twin across domains once either side is cracked. That variant was considered and **not** chosen,
because neither side of the SPN service account was ever cracked (see the last entry under Known
uncertainties), so propagation yields nothing on this lab.

**Status**: `✔ code` — **MERGED to `main` as `080ef4e` / #351** (commit `297e4fa`)
(based on `main`, so it gets real CI) / Verified `unit`. **Not verified in a live operation** — no op has
run a probe, so it is unproven that a real cross-forest bind succeeds and that the parser credits it.

**`op-20260730-040759` ran with the probe in the binary and it never fired — because its precondition
was not reachable, which is a design finding rather than a bug.** `netexec_auth` appears 0 times in the
report. The probe's candidate set requires an NTLM hash **already known byte-identical in two domains
that are not in the same forest**, and this op only ever held one side of the pair: the SPN service
account's NTLM came out of the child-domain NTDS dump, while forest B yielded only its `$krb5tgs$`
ciphertext. There is no second NTLM to compare against, so the gate cannot arm.

That generalises badly. The forest-B DCSync in a fast op is user-scoped — it pulls `krbtgt` and the
domain administrator, not the whole directory — so the forest-B half of any hash twin is systematically
absent. The probe's gate is therefore strictest exactly when the op is most successful. Two ways out,
neither built: accept a **roast-ciphertext-vs-NTLM** pairing as candidate evidence for the same
`sAMAccountName` across forests (weaker signal, but it is the signal that actually exists), or arm the
probe on same-name-different-forest alone and rely on the per-principal attempt caps to bound the
lockout risk that gating on hash equality was chosen to avoid. The second reopens the hazard §2.4
deliberately closed, so prefer the first.

**Reproduced exactly in `op-20260730-070442`, which promotes this from a one-op observation to a
structural property.** `netexec_auth` again appears 0 times. The hash table again holds the SPN service
account's NTLM in the child domain and only its roast ciphertext in forest B — this time with the child
domain carrying *both* an NTLM and a roast row for the account, so the asymmetry is visible inside one
report. Two ops with different runtimes, different foothold randomisation and different technique orders
produced the identical shape, which is what "the probe's gate is strictest exactly when the op is most
successful" predicts. Build the roast-ciphertext-vs-NTLM pairing; waiting for an op to supply the second
NTLM is waiting for a fast op to stop being fast.

Built: `select_proven_reuse_probe_work` (`automation/credential_reuse.rs`), a `netexec_auth_check` tool
(`ares-tools/src/credential_access/misc.rs`, a bare `netexec smb` bind with no `-x`), its dispatch arm
(`ares-tools/src/lib.rs`), `parse_netexec_auth` plus the parser arm, and deterministic wiring through
`dispatch_tool` rather than `throttled_submit` — the LLM-mediated route would have reproduced the §4
"execution without observability" defect while fixing this one. Nine tests. No LLM schema was added:
dispatch is deterministic, so the tool is deliberately not callable by the model, which keeps an
unbounded model-driven auth probe off the table.

Two registrations were required that a new tool does not get for free, and either omission would have
left the feature looking implemented while never working:

- `AUTH_BEARING_TOOLS` (`tool_dispatcher/mod.rs`) — `extract_credential_key` returns `None` for any
  tool absent from that list, so the probe would have **bypassed the dispatcher's existing
  per-credential lockout throttle entirely**.
- `RECON_ROUTED_TOOLS` (same file) — netexec tools must be routed to the recon worker queue by
  `resolve_queue_role`, or the probe runs on a worker without netexec installed.

Checked and found harmless: the `check_cross_realm_auth` guard rejects "native-credential auth aimed
across a forest boundary", which looked like it would veto the whole feature. It is gated on
`kerberos_coercion(tool_name)`, so a new tool is not matched — correct rather than lucky, since that
guard exists because cross-forest *Kerberos* auth is doomed, whereas NTLM pass-the-hash across a forest
is precisely what works when the password is shared.

One hazard found during implementation, excluded and tested: the blank-password NT hash
`31d6cfe0d16ae931b73c59d7e0c089c0` is identical for every blank-password account in every domain. Naive
hash equality would treat the whole estate as proven reuse and fan probes across it — the same lockout
storm the design was chosen to avoid, arriving by another route.

The probe's candidate set is restricted to principals whose NTLM hash is **already known to be
byte-identical across two domains that are not in the same forest**. That makes the hash-equality
detection the *input* to the probe rather than a second, separate feature — cheaper to build, and it
avoids the real hazard of the obvious alternative. `is_reuse_candidate` (`credential_reuse.rs:30-40`)
matches broadly: `administrator`, plus anything containing `svc`, `admin` or `sql`. Fanning that set out
across every foreign DC is an account-lockout generator against the lab, not a reuse probe. Gating on
proven hash equality reduces the candidate set to exactly the one account that matters here. Per-principal
attempt caps plus the existing `credential_reuse` throttle still apply on top.

Files: `automation/credential_reuse.rs`, a new tool module under `ares-tools`, `ares-tools/src/lib.rs`,
`ares-tools/src/parsers/mod.rs`, the LLM tool registry, `dispatcher/task_builders.rs`.

---

## 3. Detection without dispatch

Techniques that are enumerated every operation and never attempted. These are worse than a missing
tool, because the scoreboard shows them as "discovered" coverage.

### 3.1 ADCS ESC11 — best-wired chain in the tree, and it fails at coercion

**Everything below the next two paragraphs was written when ESC11 had never been dispatched, and its two
leads are now spent. Do not start from them.** `op-20260731-053105` dispatched ESC11 for real — 40 log
lines, `relay chain dispatched`, `esc_type="esc11"`, an `adcs_esc11_*` vuln_id on the forest-B CA host —
so the "zero attempt events" premise this section is built on no longer holds, and with it both the
`listener_ip` gate and the ESC8-starvation lead. ESC11 is dispatched and it enters the chain it was wired
for.

**The real defect is one step further in: coercion yields no certificate.** The chain walks multiple
coerce candidates in sequence and each logs `relay chain: candidate produced no PFX — trying next` until
the candidates are exhausted. So the question is no longer "why does ESC11 never run" but "why does no
coerce candidate produce a PFX for it", which is a question about `pick_coerce_targets`
(`adcs_exploitation.rs:2309`) and the relay listener's actual capture, not about gating or ranking. Note
that ESC8 shares that candidate-building branch and *does* convert, so the same-gate argument below now
cuts the other way: it narrows the difference to the coerce target set or the RPC-vs-HTTP relay mode
rather than to anything either lead named. **Capture one full ESC11 relay-chain window from the
orchestrator log before writing code** — the failure is now observable, which it never was before.

The original analysis is retained below for its code-level map of the chain, which is still accurate.

In `EXPLOITABLE_ESC_TYPES` (`automation/adcs_exploitation.rs:310,322`), has a deterministic branch
(`:430-435` → `dispatch_relay_coerce_chain(RelayMode::Esc11Rpc)`, `:1543`), targets `rpc://{ca_host}`
(`:283-288`), and reuses the *working* `relay_and_coerce` parser (`parsers/mod.rs:469-520`).
Discovered in 62 ops (97 instances) and produced **zero timeline events of either polarity** — the
exploit was never attempted. Blocked on a hard gate requiring `listener_ip` (`:1573`) plus a non-CA
coerce candidate (`:1596`, `:2309`).

Separate live risk: on success the shared parser hardcodes the message `"ESC8 relay captured
certificate"` (`parsers/mod.rs:514`), so **an ESC11 win would be reported as ESC8**. Not contaminating
today only because ESC8 successes key on `adcs_esc8_*` vuln_ids.

**Correction — the `listener_ip` diagnosis above is almost certainly wrong; do not start there.**
Re-checked 2026-07-29 at code level: ESC11 and ESC8 share *every* gate named. Both route through the
same `dispatch_relay_coerce_chain`, so they hit the same `listener_ip` early-return
(`adcs_exploitation.rs:1573`); coerce candidates are built for the two together in one branch
(`:2309`, `matches!(esc_type, "esc8" | "esc11")` → `pick_coerce_targets`); `technique_allowed` passes
both (`exclude_techniques` is `[]` and `include_techniques` is commented out in `config/ares.yaml`);
and `listener_ip` itself auto-detects when `ARES_LISTENER_IP` is unset (`config.rs:188`, UDP-probe
fallback). **ESC8 has successes.** A gate ESC8 clears cannot be what stops ESC11.

Two leads were carried here. **`op-20260730-040759` killed the first and confirmed the premise of the
second, so only one remains.**

- ~~**`adcs_esc11` has no `vulnerability_priorities` weight**~~ — **disproven.** Both ESC11 records in
  that report render `Priority: 4`, so an unlisted `vuln_type` is not left unweighted. Do not spend
  time here.
- **ESC8 and ESC11 are discovered on the same CA host**, so they compete for one relay listener and one
  dedup key per tick. If ESC8 always wins that race, ESC11 is starved rather than gated — which
  explains "zero timeline events of either polarity" exactly as well as a hard gate does.

The surviving lead now has direct same-host evidence, and the ranking explanation is excluded with it.
In that op the two forest-B CA hosts carried ESC1 (`Priority: 1`, exploited on both), ESC8
(`Priority: 2`, exploited on both plus a third host), ESC3 (`Priority: 3`, exploited on both) and
**ESC13 (`Priority: 4`, exploited on both)** — while **ESC11, at the same priority 4 on the same two
hosts, stayed `Not Exploited`**. ESC13 is the control: same weight, same targets, same tick ordering,
and it lands. What separates them is that ESC11 needs the relay listener and the coerce candidate that
ESC8 has already consumed, and ESC13 needs neither.

Confirm from `/var/log/ares/orchestrator.log` scoped by op-id: per Known uncertainties a
never-dispatched deterministic probe leaves no artifact in the reports, so the corpus cannot separate
"gated" from "starved". The specific thing to grep for is whether `dispatch_relay_coerce_chain` is
entered with `RelayMode::Esc11Rpc` at all, or whether the ESC8 dedup key short-circuits it first.

~~**One more datum, and it makes ESC11 unique rather than merely unlucky.**~~ **Withdrawn — this was the
load-bearing evidence for the starvation lead and `op-20260731-053105` falsified it.** The corpus count
was accurate as of 94 operations (ESC6 52, ESC15 49, ESC2 48, ESC9 48, ESC11 zero); the inference drawn
from it was not. A technique can carry zero attempt events for 94 ops and still be un-gated — the
dispatch simply had not been reached under the conditions those ops created. Kept visible rather than
deleted because "N ops of silence proves a gate" is an inference this document has now made and had
refuted, and it is available to make again for any of the other zero-count rows.

### 3.2 GPO abuse — 2,322 instances, and the driver dies on a missing binary

`gpo_*` vulnerability instances across 80 ops, every one `Status: Not Exploited`, **zero `gpo_`
timeline events of any kind**, and `pygpoabuse` / `sharpgpoabuse` / `immediate_task` appear in zero
reports. A full deterministic chain exists (`automation/gpo.rs`, parses output itself at `:61-91`,
dispatches at `:385,405`, calls `mark_exploited` directly at `:415-421`).

**Correction, 2026-07-30: "has never run in a recorded operation" was wrong, and the reports could never
have shown otherwise.** `op-20260730-040759`'s orchestrator log carries three
`GPO abuse dispatched (direct tool, no LLM)` lines at 04:09:43 — `writeproperty`, `writeowner` and
`writedacl` on one GPO GUID, sourced from the initial-access account — each followed by
`WARN GPO abuse hit a known failure mode; dedup stays locked … reason="tool_exited_nonzero" attempts=1`.
The driver works: it selects, it dispatches directly, and it correctly refuses to retry a known-bad
outcome. The tool exits non-zero.

That points straight at the last bullet below rather than at any of the routing gaps, and it reorders the
work: **check the ACL container image first.** `ares-llm/src/tool_registry/acl.rs:354-355` states both
binaries are absent from it, and `tool_exited_nonzero` on first attempt with no output is what a missing
binary looks like. Confirm by running the binary in the container before writing any code.

Note also what the `dedup stays locked` behaviour costs while the binary is missing: three GPO edges are
retired per op on the first failure, so the entire GPO surface is exhausted in one tick and the op never
revisits it even if the image is fixed mid-flight.

Residual code gaps, all still real but now second in line: no `gpo` arm in `parse_tool_output` (verified:
0 matches for `pygpoabuse` / `sharpgpoabuse`), and neither tool is in `ACL_MUTATION_TOOLS`
(`result_processing/mod.rs:1312-1322`), so an **LLM-routed** GPO call yields no evidence. These matter
only once the tool can execute.

### 3.3 SID history — a 704-line module that has never produced a finding

`ares-cli/src/orchestrator/automation/sid_history_enum.rs` (added `c68c69e`, 2026-05-12, never
modified) is spawned every operation (`automation_spawner.rs:89`), issues
`ldap_search (sIDHistory=*)` (`:107-108`), emits `vuln_type: "sid_history_abuse"` (`:144`) and
self-credits via `mark_exploited` (`:260-283`). Zero matches for `sidhistory` / `sid_history` in all
93 reports.

Three gaps regardless of whether the probe dispatches:

- The base64 `sIDHistory::` value is **never decoded** — `parse_sid_history_output` (`:321-354`)
  returns only `sAMAccountName`, while its own note at `:137-138` claims the SID is usable as
  `--extra-sid`.
- **Nothing downstream reads `sid_history_abuse`.**
- No **write** capability exists (`sid::patch`, `misc::addsid`, DSInternals — zero hits), so the lab's
  planted SID-history injection cannot be reproduced or abused.

Do not confuse this with ExtraSid: all 231 `T1134.005` stamps across 78 ops attach to child-to-parent
and forest-trust escalation, where the SID is **computed** as `{parent_sid}-519`
(`automation/trust.rs:1657-1661`), never read from an account. There is zero data flow between the two.

### 3.4 AdminSDHolder — tool exists, permanently unreachable

`adminsd_holder_add_ace` (`ares-tools/src/acl.rs:184-218`, schema
`ares-llm/src/tool_registry/acl.rs:192-233`) has **no automation driver**, **no vuln-type routing**,
and the object is **never discoverable** because the LDAP filter excludes `CN=System`. Invoked **0
times** in 93 reports; its six report appearances are the LLM listing its own toolset. Either wire
discovery + a driver or delete the tool — as it stands it inflates the apparent tool surface.

### 3.5 Two ACL edge classes that can never be discovered

- **OU / container DACLs**: **zero** ACL records with an OU, Container or Domain target type exist
  corpus-wide, so the lab's `WriteDacl`-on-an-OU edge is invisible. `dacl_edit` accepts a `target_dn`
  and could exploit it if it were ever produced.
- **`ANONYMOUS LOGON` on the child domain object**: impossible twice over — the enumerator's filter
  excludes the domain object, and `ares-tools/src/parsers/ntsd.rs:169-214` emits only nine right
  tokens, of which `readproperty` and `genericexecute` are not two. Zero occurrences of `S-1-5-7` in
  any report.

### 3.6 Share looting: a general looter, pointed at writable shares, one credential ever

Share *enumeration* is solid (three named shares in 85 / 73 / 67 ops, plus `C$`/`ADMIN$`, all
`READ,WRITE`). Looting is not scheduled as exploitation: none of the 43 vulnerability types in the
corpus is share-, file-, directory- or permissions-related, so nothing ever queues a loot pass.

Note a misleading label while working here: `sysvol_script_search`
(`ares-tools/src/credential_access/misc.rs:195-220`) is **not scoped to SYSVOL** — it runs
`spider_plus` against every readable share, identically to `smbclient_spider`. Both share the parser
arm at `parsers/mod.rs:355`, which hardcodes `"source": "sysvol_script"`
(`ares-tools/src/parsers/spider.rs:114,158,197`). So ares already has a general share looter, has run
it in 67-85 ops, and has recovered **exactly one credential ever** — now 72 rows across 93 ops, still
that single account, `op-20260730-040759` included. The planted file on the child SQL host is provably
unlooted.

### 3.7 Credential Manager

`check_credman_entries` (`ares-tools/src/credential_access/misc.rs:899-913`, `cmdkey /list`) has a
tool body and an LLM description but **no dispatch arm in `ares-tools/src/lib.rs` and no parser arm**.
Zero occurrences of `cmdkey`, `credential manager`, `DefaultPassword`, `AutoAdminLogon` in 93 reports.
Low value — the same account leaks via the autologon registry path, which works — but the tool is
dead weight as wired.

---

### 3.8 `krbrelayup` is dispatched every op and cannot run on a Linux attacker box

Found in `op-20260730-070442`, and it retroactively explains two failures the `op-20260730-040759` review
left unattributed.

`KrbRelayUp` is a Windows .NET assembly that must execute **on** a domain-joined Windows host as an
unprivileged local user — that is the entire premise of the technique. Ares treats it as an ordinary
Linux-side tool: `ares-tools/src/privesc/delegation.rs:471` shells out to `KrbRelayUp relay -d … -dc …`,
it has a dispatch arm (`ares-tools/src/lib.rs:195`), an LLM schema
(`ares-llm/src/tool_registry/privesc/delegation.rs:199`), MITRE mapping (`telemetry/mitre.rs:133`), three
`vulnerability_priorities` weights (`strategy.rs:393,446,550`), a teardown entry
(`cleanup/registry.rs:331`) and its own always-spawned driver (`automation_spawner.rs:81`). The Ansible
attack-box play even asks for it — `privesc_tools_install_krbrelayup: true`
(`ansible/playbooks/ares/goad_attack_box.yml:92`).

What it does with all that wiring is claim `ldap_signing_*` vulnerabilities and fail. In
`op-20260730-070442` the log carries **17 `krbrelayup` tool lines — roughly five invocations — and zero
successes**, and the agent's prose reports *"krbrelayup technique requested but tool unavailable on
worker"* and *"FAILED to execute krbrelayup (tool removed/unavailable)"*. `op-20260730-040759` produced 2
such failures, this op 3.

**Do not take the agent's "unavailable" at face value; the log says something more specific and stranger.**
Alongside those 17 lines sit **8** occurrences of `Tool binary not found (ENOENT from worker)
tool=krbrelay` on `privesc` tasks between 07:08:37 and 07:18:08 — `krbrelay`, not `krbrelayup`. There is
**no `krbrelay` dispatch arm anywhere in the tree**: `ares-tools/src/lib.rs:195` registers only
`krbrelayup`. So an unregistered tool name is reaching the worker and ENOENT-ing, and it is not
distinguishable from the registered one in the agent's summary. Resolve which name the worker is being
asked for before concluding anything about installation state — that is one grep and it changes what the
fix is.

Either way the architectural point stands and is the reason five invocations produced nothing: the
technique requires on-host execution as an unprivileged Windows user, and the dispatcher is Linux.

The cost is not the wasted attempt, it is the target selection. `ldap_signing_disabled` is one of the
higher-count exploitable classes and it converts by other means — in this op one DC's `ldap_signing`
record was exploited four times while two others failed on krbrelayup. So the driver is not merely inert,
it is **routing an exploitable class to an impossible technique**.

**Status**: **closed `op`** — **PR #371**, verified by `op-20260731-053105`. The honest answer was taken:
`krbrelayup` is removed from the technique set entirely rather than gated on a Windows execution
capability, so §5.6's unmade decision stays unmade and this row no longer depends on it. The removal took
the automation, the tool definition, the dispatcher wiring, the MITRE mappings, the cleanup handling and
the tests with it.

Gated both ways in the op: `krbrelayup` matches **0** times in the deployed binary and produces **0**
dispatches in the log, against roughly five invocations per op before. The `krbrelay`/`krbrelayup`
name-confusion question the section raised is closed by construction — neither name can reach a worker
now, so the grep it asked for is moot.

**What this does not establish is the payoff.** The section's actual cost claim was target selection —
`ldap_signing_*` being routed to an impossible technique instead of falling through to ones that convert.
Whether that fall-through now happens is unverified: this op logged no `ldap_signing` conversion either
way. Re-check on the next op before treating the routing half as fixed.

### 3.9 ESC15 is dispatched without the template name it requires

Found in `op-20260730-070442`, present in the last 5 ops that reached ESC15.

`build_adcs_payload` sets the template only when the vulnerability record happens to carry one —
`if let Some(ref tmpl) = item.template_name { payload["template"] = json!(tmpl) }`
(`automation/adcs_exploitation.rs:2359`). There is no requirement check, and `certipy_request` cannot run
without a template. When the record lacks it, the task ships anyway and the CA answers
`0x80094801 CERTSRV_E_NO_CERT_TYPE`. It happened twice in this op, once per CA host, and the agent
correctly reported that it could not proceed and asked for the template name.

ESC15 carries attempt events in 49 ops, so this is a long-standing conversion loss rather than a new
regression; what is new is knowing the reason. Note that the instructions string for `esc15`
(`:2172-2179`) tells the agent to "Use certipy_request with template, ca, target=ca_host" — the
instructions assume a field the payload does not guarantee.

**Status**: `✔ code` (decline half) — **PR #374** / `unit`. **The parser half is blocked on data, not effort.**
`extract_template_for_esc` (`parsers/certipy.rs:220-243`) is a 20-line backward scan for a `Template Name`
header; for ESC15 it finds none. Whether that is because ESC15 is reported CA-wide rather than under a
template stanza, or because its CVE-referencing description pushes the header out of the window, **cannot be
settled from this repo or from the logs** — raw `certipy find` output is never logged, only the parsed
result. Capture one real transcript before touching the parser; guessing at the offset is how a marker set
gets written against output the tool never produces (§0's fabricated-marker row).

The decline half shipped: `esc_type_requires_template` gates `esc1/2/3/4/6/9/10/13/15` and deliberately
excludes `esc7` (hardcodes `SubCA`) and `esc8`/`esc11` (relay defaults to `DomainController`) — gating those
would suppress the only ADCS types that currently convert. Four tests, including one asserting the gated set
is a subset of `EXPLOITABLE_ESC_TYPES`.

**Original framing, retained**: Two halves, and the first is worth doing alone: **decline the dispatch** when a
required field is absent, exactly as §1.2b's #360 fix returns `None`, so the queue slot and LLM turn are
not spent on an unwinnable task. The second half is populating `template_name` for ESC15 records from the
`certipy_find` parse, which is where the value actually is.

### 3.10 ESC2/ESC6 are structurally unwinnable as configured, ESC9 is the live route, and ~100 dispatches go into the dead pair

Split out of the ESC2/ESC6 correction in the op verdict above, after the "lab winning by design" reading
was withdrawn. Neither half below is a defect in ares's certificate-request path — that part of the
correction stands.

**Live evidence, staging, 2026-07-30, via `dreadgoad ssm run`.** Root DC (forest A, also the forest-A CA
host) has `StrongCertificateBindingEnforcement=0`, set by `vulns_adcs_esc10_case1`. Forest-B DC has **no
such value**, so it takes the KDC default (Server 2016 build 14393.8957, hotfix KB5078938 installed
2026-03-11). Two CAs exist, one per forest, on the respective DC and CA hosts. Every lab-created vulnerable
template (ESC1/2/3/3-CRA/4/9, `config.json:189`) is provisioned on the **forest-B** DC; the forest-A forest
carries only stock templates, none of which is a low-privilege enrollee-supplies-subject client-auth path.
So the one forest whose KDC is relaxed has nothing vulnerable to enrol, and everything vulnerable sits in
the forest whose KDC does not relax. The next paragraph infers that split from lab config; this measured it.

**That default is Compatibility (`1`), not Full Enforcement — measured, not inferred.** An earlier revision
of this section reasoned from patch level that a post-February-2025 build defaults to `2`, and used that to
call ESC9 inert. **That was wrong.** The forest-B DC's KDC operational log settles it behaviourally: 14 ×
**Event 39** ("valid but could not be mapped to a user in a secure way"), most recent 2026-07-29 23:30:54,
and **zero Event 40**. Event 39 is the warning logged when a weak mapping is *accepted*; its message
carries no failure clause, unlike the 161 × **Event 41** ("contained a different SID … **the request
involving the certificate failed**") that are the ESC2/ESC6 rejections. A KDC at Full Enforcement would
deny weak mappings and log 40. This one accepts them, so weak, UPN-only mappings still authenticate here.
Read the log rather than the patch level: an absent registry value does not tell you which default applies,
and Event 39-versus-40 does.

**The lab-fidelity half.** ESC6 sets `EDITF_ATTRIBUTESUBJECTALTNAME2` on the CA
(`ansible/roles/vulns_adcs_esc6/tasks/main.yml`), which is a CA-side flag: it lets a requester put an
arbitrary SAN into a cert. Whether that cert is *accepted* is a KDC-side decision, and the only roles that
relax the KDC — `vulns_adcs_esc10_case1` (`StrongCertificateBindingEnforcement=0`) and
`vulns_adcs_esc10_case2` (`CertificateMappingMethods=0x4`) — are applied to the **root DC**
(`ad/GOAD/data/staging-overlay.json:19-20`). ESC6 is applied to the **forest-B CA host** (`:64`), and the
forest-B DC gets only ESC7/ESC13/ESC15 (`:51-53`), leaving it at default enforcement. **The SAN-spoof
primitive and its enabling bypass are in different forests.** A spoofed-SAN cert from the forest-B CA is
presented to a forest-B KDC that was never relaxed, which is exactly the observed `Object SID mismatch`.

`dreadgoad validate` does not catch this. `checkADCSESC6` queries `policy\EditFlags` on the CA host and
prints `EDITF_ATTRIBUTESUBJECTALTNAME2 set on <host> (ESC6 exploitable)` on PASS
(`cli/internal/validate/checks.go:703-732`). It never reads any KDC's binding-enforcement value. **It
asserts the CA-side half and calls the whole thing exploitable**, so the lab advertises an ESC6 that is
inert and validates green while doing it. This is a DreadGOAD bug, not an ares one, and belongs in that
repo; it is recorded here because a lab that validates green on an unwinnable vuln is a standing
measurement hazard for every ADCS row in this file.

**The dispatch half.** ESC6 carries attempt events in 52 ops and ESC2 in 48 (§3.1's count): roughly 100
corpus dispatches into a wall. The wall is not that ares lacks an answer to KB5014754. It has one, and
uses it: `dispatch_esc1_deterministic` computes `admin_rid500_sid(&domain_sid)` and passes it as a literal
tool argument (`adcs_exploitation.rs:795`, `:932`), refusing to dispatch at all when the domain SID is
unresolved (`:892-901`). ESC6 gets no such chain. It is handled by an LLM prompt that *asks* for the same
parameter (`:2126`), so whether `sid` is present depends on the model complying that turn, and
`Object SID mismatch` is precisely what an omitted `sid` produces. Deterministic chains exist for
ESC1/3/4/7/13 and for nothing else.

**That experiment has now been run, and it refutes the `sid`-omission hypothesis.** The ESC2 failure line
in `op-20260730-070442` records the request's own parameters: `SAN URL SID=<domain>-500` **but**
`Security Extension SID=<domain>-1125`. The target SID *was* supplied and the CA overrode it with the
requesting account's own RID. So `sid` was never missing, and neither remedy above — promoting ESC6 to a
deterministic chain, nor asserting `sid` before dispatch — would change the outcome.

**The real discriminator is the template's `msPKI-Certificate-Name-Flag`, not the KDC and not `sid`.**
`ESC1.json` carries `1` = `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`: the enrollee authors the subject, so
certipy's `-upn`/`-sid` reach the issued cert and the security extension agrees with them. `ESC2.json` and
`ESC9.json` both carry `33554432` = `0x02000000` = `CT_FLAG_SUBJECT_ALT_REQUIRE_UPN`: the CA builds the
subject **from the authenticated requester's AD object**, so it stamps that account's RID into the
security extension regardless of what the request asked for. ESC6 is worse still — it ran against the
stock `User` template (`cert_User_*.pfx` in the failure line), which is likewise not enrollee-supplied;
its SAN spoof comes from the CA's `EDITF_ATTRIBUTESUBJECTALTNAME2` flag, which injects a SAN but cannot
touch the security extension. **ESC2 and ESC6 are structurally unwinnable as configured, and no ares-side
change to the request fixes either.**

This restores the original remedy — decline the dispatch — but with a precondition that is precise and
readable from `certipy find` rather than guessed from the KDC: a SAN-spoof ESC is winnable only if the
template sets `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` **or** `CT_FLAG_NO_SECURITY_EXTENSION`. Neither ESC2 nor
the `User` template does. That check is the same shape as §3.9's and should land with it.

**Why this is also what makes ESC9 the lab's intended answer.** ESC9 shares ESC2's name-flag, so it cannot
carry a spoofed SID either — but its `msPKI-Enrollment-Flag` is `524329`, which contains `0x00080000`
`CT_FLAG_NO_SECURITY_EXTENSION`. The CA therefore omits the extension entirely, leaving the KDC nothing to
contradict the UPN. That is precisely the wall ESC2 and ESC6 die on, and the lab ships the template that
removes it.

**The lab ships that template and its own DC defeats it. Measured end-to-end, staging, 2026-07-30.** An
earlier revision of this paragraph read an Event 39 as establishing Compatibility and concluded ESC9 was
live. That is wrong, and the test has now been run rather than inferred. Enrolling in the ESC9 template as
an ordinary forest-B domain user — no UPN spoof, no `-sid`, no ACL primitive — certipy issued the cert and
reported `Certificate has no object SID`, confirming the CA honoured `CT_FLAG_NO_SECURITY_EXTENSION`.
PKINIT with that cert sent the AS-REQ (`Sending AS-REQ to KDC`, `-debug`) and **returned no TGT**. The
forest-B DC's own System log carries the matching record at that moment:

```
Id 39  LevelDisplayName: Error  (Microsoft-Windows-Kerberos-Key-Distribution-Center)
"...a user certificate that was valid but could not be mapped to a user in a secure way
 (such as via explicit mapping, key trust mapping, or a SID)."
  User: <forest-B cracked account>   Certificate Issuer: <forest-B CA>
```

**Event 39's level is the discriminator, not its presence.** At Compatibility the KDC permits the logon and
logs 39 as a *Warning*; at Full Enforcement it refuses and logs *Error*. This is Error, and the client got
no ticket. **The forest-B KDC is at Full Enforcement**, which is what the absent registry value resolves to
at that patch level — now behavioural, not documented-default inference.

**So ESC9 is dead here too, and the whole SAN-spoof family with it.** ESC2 and ESC6 fail because the CA
stamps the requester's SID; ESC9 fails because removing the SID is itself disqualifying under Full
Enforcement. Every route the lab provides in that forest is closed by the same KDC setting, and ESC1
survives only because enrollee-supplied subject plus a matching `-sid` produces a *strong* mapping rather
than a bypassed one.

**A suspicion this clears.** ESC1 converting while ESC2 and ESC6 fail looked like it might be
mis-attribution of the §6.x kind, since ESC1 has no relaxed KDC in forest B either. It is not:
`dispatch_esc1_deterministic` gates crediting on `exec_result_has_hash_discoveries(&result)` (`:975`) and
only then calls `mark_adcs_esc_exploited`, so the ESC1 credit requires real hash output and is sound. That
makes ESC1 positive evidence for the paragraph above rather than a defect. Note the mechanism is the
template's enrollee-supplied subject, not the fact that its chain is deterministic: a deterministic ESC6
chain against the `User` template would fail identically.

**ESC9 is no longer blocked on §1, because it is not blocked on anything ares can do.** The earlier
reading — that reaching ESC9 needs a `GenericWrite`/`ForceChangePassword`-class primitive, that §1 is why
it never converts, and that it should be re-tested once §1 moves — is superseded. The ACL primitive is
genuinely required to *spoof* a UPN, but the measurement above bypassed that requirement entirely by
enrolling as the account itself, and the KDC still refused. **§1 is not what is stopping ESC9 here.** Do
not schedule ESC9 work behind §1, and do not count it as ADCS coverage the ACL fix will unlock.

**A correction to an earlier revision of this section.** The claim that the lab has one CA and that ESC10
is therefore misplaced was wrong. `ad/GOAD/data/inventory:88-90` puts a CA in **both** forests; only
forest B gets the vulnerable templates (`:94-95`). ESC10 needs a relaxed KDC, any enrollable client-auth
template and a UPN write — not a vulnerable template — so it is correctly placed in forest A, whose KDC is
explicitly relaxed. There is no cross-forest placement bug; forest A is the soft forest by design and
forest B is the hard one. Do not file an ESC10 move.

**Status**: `—` / `op` (enforcement measured 2026-07-30, staging). Three actions, none of which depends on
another:

1. **ares** — decline the dispatch for SAN-spoof ESCs whose template sets neither
   `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` nor `CT_FLAG_NO_SECURITY_EXTENSION`, and, given the enforcement
   reading, decline `NO_SECURITY_EXTENSION` templates too when the target KDC is at Full Enforcement. Same
   shape as §3.9's. This is what recovers the ~100 corpus dispatches.
2. **DreadGOAD, lab fidelity** — forest B ships ESC2, ESC6 and ESC9 and its KDC defeats all three. Either
   set `StrongCertificateBindingEnforcement=1` on the forest-B DC or place an ESC10 role there. Until then
   that forest advertises three ADCS routes and provides none. This is the item the "lab winning by design"
   filing would have buried, and it has a one-line fix.
3. **DreadGOAD, validator** — `checkADCSESC6` asserts only the CA-side flag and prints "exploitable";
   `checkADCSESC9` PASSes on `DONT_REQ_PREAUTH` users and never reads the template's enrollment flag or the
   KDC's enforcement. Both report green on routes now measured unwinnable. Also derive
   `checkADCSPublishedTemplates`'s list from `vulns_adcs_templates` instead of hardcoding it — ESC9 is
   shipped and unchecked today.

## 4. Execution without observability

Tools that run correctly and whose results are thrown away before any parser sees them. This class is
why "add a parser arm" was the wrong fix for the relay family.

### 4.1 The timeout path discards stdout

`ares-tools/src/executor.rs:436-441` **discards stdout and returns `Err`** on timeout, and
`parse_tool_output` is only called on the `Ok` path (`ares-cli/src/worker/tool_executor.rs:601-626`).

Every long-lived listener is therefore unparsable no matter how good its parser is:

- `responder` runs with `timeout_secs(30)` (`ares-tools/src/coercion.rs:35-48`) against a daemon that
  never self-exits. Its real parser arm (`parsers/mod.rs:546`) and NetNTLMv2 extractor
  (`parsers/secrets.rs:496-566`) are **unreachable in production**.
- The four `ntlmrelayx_*` tools and `start_mitm6` have arms as of 2026-07-28 and still never land, for
  the same reason (120 s on a non-exiting daemon).

`relay_and_coerce` is the only member of the family that works, and the reason is explicit: it
backgrounds the child with stdout to a file, polls the log, and synthesises deterministic
`CERT_CAPTURED_VIA=` / `PFX_FILE=` / `RELAYED_USER=` markers into its own stdout
(`coercion.rs:556-607`, `:959-963`, `:1042-1061`). **That pattern is the fix for the whole family** —
not more parser arms.

**Status**: Implemented `✔ code` — **PR #353** (`b8d369d`, CI 9/9 green), Verified `unit`.
Fixed at the executor rather than per tool, so no tool definition changed and `coercion.rs` was not
touched. `run_child` now drains both pipes into buffers as the child writes, instead of calling
`wait_with_output()` — which only yields its buffers when the child exits, and is what lost everything.
On timeout it SIGKILLs, drains, and returns `Ok(ToolOutput { exit_code: None, success: false })`
carrying the partial output, so `parse_tool_output` runs. **A timeout that captured nothing still
returns `Err`** with the original wording, so the behaviour change is confined to the case that has
evidence to preserve and a silent hang classifies exactly as before.

The timeout verdict has to survive to the orchestrator and `ToolExecResponse` has no field for it, so
the executor appends a deterministic `ARES_TOOL_TIMED_OUT_AFTER_SECS=` marker to stderr — the same
trick `relay_and_coerce` uses, and it needs no wire-format change. `executor::failure_message` reads it
back and is now the single source of the `error` string for **both** dispatch paths (the NATS worker
and `tool_dispatcher/local.rs`), which each previously built their own copy of the wording. That
matters beyond cosmetics: `cleanup/dispatcher.rs`'s `dispatch_timed_out` gate keys on that string to
leave a timed-out *mutating* tool's journal intent unresolved, and a bare `tool exited with code None`
would have silently downgraded it to `Aborted` — losing the very write-ahead guarantee #348 added.

Verified `unit` — 6 new tests in `ares-tools`, 1 in `ares-cli`; full workspace suite green
(4037/1303/421/1627, 0 failed), clippy clean on 1.94 and CI's 1.97. The load-bearing one is
`timed_out_listener_output_reaches_the_parser`: it runs a real subprocess that prints a NetNTLMv2
capture in Responder's own wrapper format and then hangs past the deadline, then asserts a hash
discovery comes out of `parse_tool_output`. That is the whole §4.1 chain end to end, on a real process.
**Not verified in a live operation** — whether Responder or the relay family capture anything on the
wire is unproven, and this is exactly the `✔ code` + `unit` case the legend warns about.

Note the two NTLMv1-specific blockers below are **not** addressed and are now the only thing standing
between a `force_ntlmv1` capture and a crack: the validator still rejects NetNTLMv1, and mode 5500 is
still absent.

Two further blockers specific to NTLMv1 downgrade: the validator requires a 16-hex challenge
(`parsers/secrets.rs:593`), so a NetNTLMv1 capture is **rejected** despite the `force_ntlmv1` flag
existing; and hashcat mode **5500 appears nowhere in the repo** (`ares-tools/src/cracker.rs:159-177`),
so such a hash could not be cracked if captured.

**Status**: Implemented `✔ code` — `645f635` / #353, merged to `main` 2026-07-30 — Verified `unit`.
`run_child` drains both pipes as the child writes and returns the partial output on timeout rather than
`Err`, so `parse_tool_output` runs on it (`ares-tools/src/executor.rs:463`,
`ExecOutcome::timed_out_with_output`). The four `ntlmrelayx_*` arms, `start_mitm6` and `responder`'s
NetNTLMv2 extractor are reachable in production for the first time. A timeout that captured **nothing**
still returns `Err` with the original wording, so a silent hang classifies exactly as before.

**This item stays open, and the op that ran did not touch it.** `responder`, `ntlmrelayx` and `mitm6`
each appear **0 times** in `op-20260730-040759` — nothing in the listener family was dispatched, so the
timeout path was never entered and the fix is exactly as unproven as before. Note the shape of this
non-result: it is not "the fix failed", it is "the fix guards a path nothing walks". A 24-minute op that
reaches DA in four minutes never needs a coercion listener, so verifying #353 may require an op that is
deliberately denied the fast path rather than a normal run. The one coercion attempt the op did make
(PrinterBug against the unconstrained-delegation host) returned `ERROR_INVALID_HANDLE` and captured
nothing, which is a target-side refusal upstream of anything #353 changed.

The two NTLMv1 blockers below are unaffected and were re-verified on `main` at 2026-07-30: the validator
still rejects a NetNTLMv1 challenge (`parsers/secrets.rs:593`), and hashcat mode 5500 still has zero hits
(`cracker.rs:159-177`). A `force_ntlmv1` capture now reaches the parser and dies there instead of dying
at the timeout.

### 4.2 `is_lsassy_noise()` discards the failure reason

`ares-tools/src/parsers/credential_tools.rs:101-110` drops every `INFO` / `WARNING` / `ERROR` line, so
a RunAsPPL refusal returns exit-0 with zero discoveries — indistinguishable from a clean empty dump.

The lab enables `RunAsPPL` on the forest-B SQL/CA host, and lsassy's record there is 0-for-N: 9
credential rows across 9 ops, none of them that host, whose machine hash arrives only via
`secretsdump`. **The miss is real but currently unprovable from logs**, which is the actual defect.

No PPL handling exists at all: `RunAsPPL`, `PPL`, `ProtectedProcess`, `mimidrv`, `PPLKiller`,
`PPLdump`, "LSA protection" — **zero hits in any `.rs`, `.tera`, `tools.yaml` or `config/ares.yaml`**.
The fact never reaches a prompt. `automation/lsassy_dump.rs:135-145` sets no `method` and has no
fallback branch; the schema advertises one method name whose JSON `default` is never applied
server-side, since `flag_opt` omits `-m` entirely when unset. No alternative dumper is wired:
`pypykatz`, `nanodump`, `procdump`, `dumpert`, `handlekatz`, `mirrordump` have no dispatch and no
parser arms.

### 4.3 `note_kerberos_only` has zero readers

The lab plants both constrained-delegation variants: protocol-transition on a user account, and
Kerberos-only on a machine account. Ares lands the first (59 ops) and has **never independently
exercised the second** — 78 ops, 423 failure events, and 3 nominal successes that all arrive *after*
that op already had DA (so a forwardable TGT could be forged), none since 2026-06-18.

The distinction is detected in exactly one text parser and then thrown away:

```rust
// ares-tools/src/parsers/delegation.rs:57-58
let protocol_transition =
    !(line_lower.contains("w/o protocol") || line_lower.contains("without protocol"));
```

Default is `true` (`:55-56`), so any format drift or BloodHound-sourced row silently classifies
Kerberos-only as protocol-transition. `vuln_type` is always plain `constrained_delegation`
(`:72-76`); the strings `constrained_delegation_use_any` / `_kerb_only` have zero occurrences
repo-wide. The flag *is* echoed into the S4U payload as `note_kerberos_only`
(`automation/s4u.rs:553-568`) — and nothing reads it: the automation gate is
`if vtype != "constrained_delegation" && vtype != "rbcd" { return None }` (`:396-399`), and
`generate_constrained_delegation_prompt` (`ares-llm/src/prompt/exploit/delegation.rs:20-129`)
whitelists fields and never includes it.

Even a compliant model could not act on it: `build_s4u_command`
(`ares-tools/src/privesc/delegation.rs:58-96`) emits only `impacket-getST -spn … -impersonate …` — no
`-self`, `-u2u`, `-altservice`, `-force-forwardable`, no `ticket_path` — and the schema exposes no
such parameter. `templates/.../system_instructions.md.tera:155` has a protocol-transition row and no
Kerberos-only row.

**Ares diagnosed this correctly in free text twice** (`KDC_ERR_BADOPTION` … "not allowed to delegate
to this SPN and/or its TGT is not forwardable") and the system ignored it: `KDC_ERR_BADOPTION` has
zero hits in code, and `s4u.rs:33-37` classifies only four unrelated error strings. The item then
burns `S4U_MAX_FAILURES = 6` at 300 s cooldown (`:24,29`) and is abandoned.
`docs/attack-path-diversity.md:77` claims this gap is closed; it is not.

### 4.4 The op status record carried no liveness signal — found live, `op-20260730-040759`

`set_operation_status` (`ares-core/src/state/operations.rs`) has exactly two callers: `bootstrap.rs`
writes `running` at start, and `finalize_operation` writes the terminal status at the end. Nothing
touched the record in between, so `updated_at` was the start timestamp for the whole run and
`status: running` meant only "an orchestrator once started this operation". A wedged run and a working
one were byte-identical from outside. During this op the question "is it still actually running?" was
not answerable from any ares command; it was settled by SSHing to the box and finding a live
`hashcat -m 13100` at 94% CPU with all four queues empty.

**Status**: `✔ code` — **PR #360**, commit `d4e3888` on branch
`fix/sid-principal-membership-and-op-heartbeat` (based on `7f80957`) / Verified `unit`. **Not verified in
a live operation** — no op has yet produced a moving `updated_at`, and that is the only thing that
closes this.

The heartbeat rides the **lock keeper**, not the agent-heartbeat sweep. That placement is deliberate:
`spawn_lock_keeper` already ticks at `heartbeat_interval` on a dedicated Redis connection created
precisely so its `EXPIRE`s cannot queue behind heavy `BRPOP`/`LPUSH` traffic (`monitoring.rs:117-119`).
A liveness signal that can be blocked by the thing whose liveness it reports is worse than none.

Three pieces:

1. `set_operation_status` now writes `status_changed_at` alongside `updated_at`, so the "when did the
   status last *change*" meaning the field used to carry is preserved rather than overwritten by ticks.
2. `heartbeat_operation_status` refreshes `updated_at` and stamps `heartbeat_interval_secs` into the
   record, which makes staleness self-describing — a reader does not have to guess the producer's
   cadence. It is a read-modify-write that **refuses to write unless the stored status is `running`**,
   so a tick racing past finalization cannot flip a `completed` op back to `running`. Shutdown ordering
   already makes that race near-unreachable (`shutdown_tx` → join → finalize); the guard is there
   because "near-unreachable" is how the frozen timestamp got shipped in the first place.
3. `ares ops status` prints `Status set:` and `Last heartbeat: Ns ago`, with a `*** STALE ***` marker
   past three missed intervals; `ares ops list` degrades `[running]` to
   `[running? STALE — no heartbeat for <age>]`. Only running ops are probed, so the extra `GET` is one
   per list in practice.

Nine tests. The two that matter are `heartbeat_never_resurrects_a_finalized_operation` and
`heartbeat_moves_updated_at_but_not_status_changed_at` — the second is the actual bug, asserted
directly.

Note the limit of what this buys. The heartbeat proves the *lock keeper task* is alive, which is a
weaker claim than "the operation is making progress": an orchestrator whose LLM loop is wedged but
whose Tokio runtime is healthy will still beat. It converts "no information" into "the process is
alive", not into "work is happening". Progress liveness would need a tick counter fed from the
dispatch path, and is worth doing only if a run is ever observed beating while stalled.

---

## 5. Missing primitives — no code exists

### 5.1 WriteOwner / take-ownership

No `owneredit` or set-owner path anywhere: **zero hits in code and zero in all 93 reports**.
`dacl_edit` can *grant* a WriteOwner right but cannot *take* ownership. The prompt template admits the
hole (`templates/.../acl_chain_step.md.tera:61`: *"`writeowner` → `dacl_edit` (with
`rights=WriteDacl`). Note: ownership change needed first; if dacl_edit alone fails, report
insufficient_context"*). 34 dispatches, 0 successes, structurally unwinnable. This is edge 6 — it
sits mid-chain, so it also blocks edges 7 and 8 from ever being reached by an actual walk.

Also blocks: 1,966 `writeowner` and 774 `gpo_writeowner` discovered instances corpus-wide.

### 5.2 gMSA managed-password read

Capability exists and is unreachable at both ends. Tools: `ares-tools/src/privesc/gmsa.rs:17,30`
(netexec `-M gmsa`) and `ares-tools/src/acl.rs:240,255` (bloodyAD `msDS-ManagedPassword`), dispatched
at `lib.rs:199,215`, schemas reachable by the credential-access role, automation driver at
`automation/gmsa.rs:37`. Zero reads in 93 ops. Two independent fatal blockers:

- **No parser arm** for either tool (verified: 0 matches for `gmsa` in `parsers/mod.rs`) — falls
  through to `_ => {}` at `:724`, so a successful read could never be credited.
- **Both work-selection paths are dead.** Path 1 needs a gMSA account in `state.users`; the gMSA never
  appears in a users table (SAMR/LDAP enumeration does not surface it). Path 2 needs
  `vuln_type ∈ {gmsa, gmsa_reader, readgmsapassword}` (`gmsa.rs:30-33`) and **no code anywhere emits
  any of those strings**.

**Status**: `—` / `—` — both blockers above stand, re-verified 2026-07-29. The **prerequisite** is done,
though: §6.2's phantom gate landed, so the parser arm can now be added without shipping a fabricated
success alongside it. Do the arm and the producer in that order, and read §6.2's framing note first.

### 5.3 LAPS: no vuln producer

Better wired than gMSA — the parser arm exists (`parsers/mod.rs:721` → `parse_laps`,
`parsers/credential_tools.rs:464-494`, tested at `mod.rs:2196`), the automation has two credential
sweeps that need no vuln at all (`automation/laps.rs:111-145`, `:162-213`), and `laps_dump` is in
every `request_low_hanging_fruit` payload (`dispatcher/task_builders.rs:316-318`). What is missing is
the same as gMSA's second blocker: `is_laps_candidate` (`laps.rs:25-28`) matches
`laps_abuse|laps_reader|laps` and **nothing emits those**. `config/ares.yaml:258` carries a
`laps_abuse: 13` priority weight for a vuln type no producer creates.

**The shared root cause for 5.2 and 5.3**: `classify_bloodhound_right`
(`ares-tools/src/parsers/bloodhound.rs:39-61`) returns `None` for both `ReadGMSAPassword` and
`ReadLAPSPassword`, commenting that such rights "have their own automation and must not be routed
through the ACL driver". The automations exist; nothing feeds them. Two mappings plus an
LDAP-side equivalent (BloodHound rarely runs — see §6.3) close both.

LAPS is the cheaper of the two: it needs one producer and a reader identity (§1.1). gMSA needs a
producer, a parser arm, and a users-table entry.

### 5.4 MSSQL: the two paths the lab intends and ares cannot take

- **`EXECUTE AS USER`** — the string appears exactly once in the whole codebase, in a doc comment.
  `mssql_enum_impersonation` (`ares-tools/src/lateral/mssql.rs:132-151`) *deliberately* queries
  `master.sys.database_permissions` and `msdb.sys.database_permissions`, and its comment at
  `:127-131` explains why ("database-level `EXECUTE AS USER` grants live in `sys.database_permissions`,
  not the server view"). So the lab's database-scoped grant **is discovered**. But `mssql_impersonate`
  only ever emits `EXECUTE AS LOGIN` (`:161`), and the prompt tells the model to try
  `EXECUTE AS LOGIN = '<target>'` for every registered grant (`automation/mssql_exploitation.rs:221`).
  For a database-scoped grant that is the wrong statement and can only fail. **Enumeration was built
  with the distinction in mind; execution was not.**
- **Linked-server stored credentials** — the lab's two linked servers are reciprocal and each stores
  the other's `sa` password in cleartext, which is the intended cross-forest pivot. `sp_helpserver`
  and `sp_helplinkedsrvlogin` appear **nowhere in the codebase**, and neither `sa` password appears in
  any of 93 reports. Both link directions *are* traversed (139 exploit events), and the failures are
  informative: four `request_assistance` events report `Login failed for user '<domain>\<user>'` and
  for `'sa'`, one of them **explicitly asking for `sp_helpserver` / `sp_helplinkedsrvlogin`**. The LLM
  identified the missing primitive; nobody built it.

### 5.5 Other never-attempted items with no code

| Item | Note |
| --- | --- |
| `rdp_scheduler` (scheduled-task abuse over RDP) | Zero hits repo-wide. No `schtasks` / `atexec` / `dcomexec` executor — those are allowlist strings only (`tool_dispatcher/mod.rs:116-117`). `xfreerdp` is an auth-only probe. The only scheduled-task abuse in the tree is GPO-mediated (§3.2). |
| LLMNR / NBT-NS posture | `enable_llmnr`, `enable_nbt_ns`, `llmnr_enabled` — zero hits in `.rs`/`.yaml`. No probe detects it, no vuln type, no strategy priority. The one `llmnr` string in Rust is a loot-token rename with no producer. |
| ADCS ESC10 case 2 (`CertificateMappingMethods`) | Zero hits repo-wide. |
| Silver ticket | `generate_golden_ticket` always requests `-user-id 500` against `krbtgt`; no `-spn`/service-hash mode. |
| Drop-the-MIC (CVE-2019-1040) | No `--remove-mic` on any relay tool. |
| File-drop coercion (`.lnk`, `.scf`, `.url`) | No `slinky`/`scuffy` equivalent. |
| All Exchange (PrivExchange, ProxyLogon, ProxyShell) | Every "exchange" grep hit is the English word. |
| DPAPI looting / DonPAPI | Zero matches. |
| RID cycling; Kerberos user brute | `enumerate_users` uses SAMR; no kerbrute. |
| Certifried (CVE-2022-26923) | Incidental matches only, no chain. |

Deliberately out of scope, recorded so they are not re-filed: **ZeroLogon** exploitation is omitted as
too destructive (`parsers/mod.rs:391-395`) and the GOAD series never demonstrates it either;
**ADCS ESC12** is not implemented in the lab; **ESC5 / ESC14** are absent from
`EXPLOITABLE_ESC_TYPES` and off by default in the lab build. **ESC16 does not belong in this bucket** —
it is equally absent from the lab build, but unlike the others it is a *precondition* the rest of the
ADCS surface depends on rather than one more technique, so it is filed separately at §5.7.

### 5.6 The on-target execution boundary — still an unmade decision

`ares-llm/src/tool_registry/privesc/escalation.rs:3-6` states the constraint: no executor exists for
printspoofer, godpotato, sweetpotato, seatbelt, sharpup, powerup, winpeas, linpeas, runas_cs,
scm_uac_bypass, powerupsql, because they are Windows binaries that run on-target. Ares is a Linux-side
remote-protocol orchestrator.

This is a deliberate architectural boundary, not a bug, and #325 correctly stopped pretending
otherwise. But it permanently costs the whole local-privilege-escalation category (SeImpersonate to
SYSTEM, the potato family, winPEAS, AMSI bypass, in-memory .NET, IIS webshell upload, Rubeus TGT
harvesting, token impersonation, `tscon` session hijack, SharpGPOAbuse). **Worth an explicit decision
rather than an implicit one** — the current state is that several tools and prompts still gesture at
capabilities that cannot exist.

### 5.7 ADCS ESC16 — the CA-wide enforcement state ares cannot read

`rg 'esc16|DisableExtensionList|1\.3\.6\.1\.4\.1\.311\.25\.2'` over the tree returns **exactly one hit**,
and it is a test asserting the absence: `assert!(!ESC_TYPES.contains(&"esc16"))`
(`ares-tools/src/parsers/certipy.rs:659`). `ESC_TYPES` (`:6-9`) holds 14 entries and the same test pins
`ESC_TYPES.len() == 14` at `:653`, so the exclusion is **load-bearing** — the string cannot be added
without failing two assertions. There is no arm in `EXPLOITABLE_ESC_TYPES`
(`automation/adcs_exploitation.rs:311-324`), no loot category (`ops/loot/format/display.rs:644-660`), no
instructions string, no MITRE mapping.

ESC16 is the CA-global form of the ESC9 bypass: `1.3.6.1.4.1.311.25.2` (`szOID_NTDS_CA_SECURITY_EXT`)
present in the CA policy module's `DisableExtensionList`, which makes the CA omit the SID security
extension from **every** certificate it issues — every template, regardless of that template's own flags.

What makes it more than a fifteenth entry in a list is that it is the switch deciding whether the ADCS
techniques ares *does* run can work at all. The UPN-spoofing machinery is built and wired: the
`bloodyAD set object` UPN swap (`ares-tools/src/acl.rs:535-536`,
`ares-llm/src/tool_registry/acl.rs:138-141`) and the ESC9 / ESC10 primitive
(`ares-tools/src/privesc/adcs.rs:647-650`). The codebase also already reasons about the enforcement in
prose — `tool_registry/privesc/adcs.rs:310` warns that strict certificate mapping rejects a certificate
whose Security-Extension SID does not match, and `automation/golden_cert.rs:55` passes `-sid` explicitly
"to satisfy KB5014754 strong mapping enforcement". So ares knows the rule and compensates for it where it
forges. What it cannot do anywhere is **observe which state the CA is actually in**. `certipy find` is the
one place that fact arrives, and the parser drops it on the floor.

The cost is symmetric, and it is a blind fire in both directions. With the extension stamped, every
UPN/SAN spoof is dead before it is sent and ares rediscovers that one failed attempt at a time. With it
disabled CA-wide, spoofing is live against *every* template — including ones ares currently reads as
non-vulnerable — and nothing raises them.

**Status**: `—` / `—`. The lab does not configure it, so this is coverage rather than a live conversion
loss and should not be prioritised as though an op were failing on it. Step 0 is a box check, not code:
**confirm the installed certipy version**, which is not pinned in-repo — it comes from the arsenal role
(`ansible/playbooks/ares/goad_attack_box.yml:71`). ares already parses `esc13` / `esc14` / `esc15`, so the
installed build is recent; whether that build also emits ESC16 is the single thing to establish, and it
decides whether this is a parser change or an upgrade first. Then get the shape right: ESC16 has no
exploit primitive of its own, so emitting it as a queue item would manufacture exactly the §3 failure this
document catalogues — detection with no dispatch. It belongs as a **fact about the CA that conditions
other records**, gating and re-prioritising ESC9 / ESC10 and template-level UPN spoofing, not as a
vulnerability with a driver behind it.

---

## 6. Credit and attribution defects

### 6.1 Roast credit is fully mis-attributed

**Status**: `✔ code` (#350 + #354, merged) / Verified **`op`** — `op-20260730-040759`, 2026-07-30.
First `T1558.004` event in the project's history:
`{"description":"Hash discovered: <domain>\\<asrep-account> (asrep\u0029", "mitre_techniques":["T1003","T1558.004"], "source":"asrep_roast"}`.
`T1558.003` is also now attached to the roast hashes themselves — three events sourced
`kerberoast` for the two roastable users and the SPN service account — against one legacy
stamp still riding the S4U delegation event. Previously **all** 59 `T1558.003` stamps were the
S4U event and the roast principals got nothing, and `T1558.004` never fired at all. The
remaining S4U stamp is cosmetic: the roast principals now carry their own credit, so the
ID join no longer misses.

- **`T1558.004` (AS-REP roasting) appeared zero times in the first 92 of them** despite 145 AS-REP hashes
  across 83 ops, and **fires in the 93rd** — `op-20260730-040759` is the only report in the corpus
  containing the ID. Mechanism of the original defect: roast hashes arrive on the realtime channel —
  `tool_dispatcher/mod.rs:339` → `result_processing/discovery_polling.rs:131` — which calls
  `publish_hash` and never `create_hash_timeline_event`. The parser path that *does* emit
  (`result_processing/mod.rs:2310`) is then a no-op because `publish_hash` returns `Ok(false)` for an
  already-present hash. Corpus check: of 536 `Hash discovered:` events, exactly 1 is kerberoast and 0
  are AS-REP.
- **`T1558.003` (Kerberoasting) credit is 100% the wrong event.** The technique bullet appears in
  exactly 59 ops, and that set is **byte-identical** to the set with
  `Vulnerability exploited: constrained_delegation_<user>`. It is the S4U event's MITRE stamp. Nineteen
  ops that genuinely harvested Kerberoast tickets receive no `T1558.003` at all.
- **The crack step erases provenance.** `credential_techniques()`
  (`result_processing/timeline.rs:8-25`) stamps from the credential's `source`, but cracked
  credentials carry `source = "cracked:hashcat"`, which matches only `contains("cracked")` → T1552 +
  T1110. All 216 such rows lose the attribution, and no report records which hash a crack came from.

Per the red/blue ATT&CK-ID join contract this makes AS-REP roasting permanently unscoreable as red
coverage and would demote any blue detection of it to `blue_only`.

**Status**: first bullet — Implemented `✔ code`, merged to `main` as `d9d7dd8` / #350 and completed by
`77ffe58` / #354. The realtime discovery channel in `discovery_polling.rs` now emits a hash timeline
event, gated on `publish_hash` returning `Ok(true)` so it fires once, on genuine insert; `hash_techniques`
derives `T1558.003` from a `kerberoast` source and `T1558.004` from an `asrep_roast` source. **Verified
`op`** — `op-20260730-040759`: two `T1558.004` events (the child-domain AS-REP account, and forest B's,
the latter being the account whose crack gates the forest-B chain) and four `T1558.003` events on the
roast hashes themselves. The corpus counts in the bullets above are therefore historical, not current.
**Closed — see §0.**

The second bullet is **substantially improved but not closed**. `T1558.003` now attaches to the four
roast hashes, against **one** legacy stamp still riding the S4U delegation event in the same report. The
ID join no longer misses, which is the part that mattered for the red/blue contract; what remains is a
cosmetic over-stamp on an unrelated event, and it will keep inflating any per-technique event count taken
from the timeline. The third bullet (provenance erased at the crack step, `source = "cracked:hashcat"` →
T1552 + T1110) is untouched and `—` / `—`: this op cracked four hashes and none of the resulting
credential rows records which hash it came from.

That fix closed the *attribution* half of the realtime channel's gap and not the *credit* half — the same
path still emitted no `roast_exploit_token` and no gMSA token. That half was filed separately and has
since closed on its own — `77ffe58` / #354, see §0.

### 6.2 Latent gMSA phantom — same shape as the one just fixed

`emit_gmsa_exploit_token_if_gmsa` (`result_processing/mod.rs:1090-1115`, helpers `:1070`, `:1078`)
marks `gmsa_<name>` EXPLOITED whenever `secretsdump` returns any `$` account whose name contains
"gmsa" — crediting DCSync loot as a gMSA read. It has not surfaced in a report yet only because §5.2
means nothing else in the path works. **Gate it on real read evidence before fixing §5.2**, or the
first working gMSA parser arm will ship a fabricated success.

**Status**: Implemented `✔ code` on branch `fix/acl-hash-source-dispatch-and-roast-attribution`
merged to `main` as `d9d7dd8` / #350, Verified `unit`. The gate now requires **both** a gMSA-looking principal and
a producing tool that actually reads managed passwords, via a new `is_gmsa_read_source` predicate
(`result_processing/mod.rs:1084`) matching sources containing `gmsa` — i.e. `gmsa_dump_passwords` and
`gmsa_read_password_bloodyad`. The condition at `:1108` is now
`!is_gmsa_principal(username) || !is_gmsa_read_source(source)`, so **a `secretsdump` source no longer
credits**. The call site (`:2333`) passes the hash's `source`, which was already in scope, so this cost
no plumbing. The now-false log line ("gMSA hash captured via secretsdump") was corrected to "gMSA
managed password read — emitted exploit token". Six tests in the `emit_gmsa_exploit_token` module
(`result_processing/tests.rs:1702-1770`) cover both read tools, both non-gMSA principal shapes, case
normalisation, and `no_op_for_gmsa_hash_arriving_from_dcsync`.

**Framing — this was priority 6's *prerequisite*, not priority 6.** Nothing about gMSA coverage
improved: §5.2's two blockers stand unchanged (still no `gmsa` parser arm — verified again, 0 matches in
`ares-tools/src/parsers/mod.rs` — and still no producer of the `gmsa` / `gmsa_reader` /
`readgmsapassword` vuln types), so the rest of priority 6 is `—` / `—`. What the gate landing buys is
that the rest of priority 6 is now **safe to do**. Before it, the first working gMSA parser arm would
have shipped a fabricated success on every operation that merely DCSync'd the domain — the phantom would
have arrived in the same commit as the capability, and been indistinguishable from it in the reports.
Ordering was the whole point.

### 6.3 BloodHound is inert and load-bearing

Ten mentions, zero successes across 93 ops. The 29,107 ACL edge descriptions come from raw LDAP
enumeration, not path-finding — which is likely *why* they are a flood rather than a path. This now
matters more than it did: the `ReadLAPSPassword` / `ReadGMSAPassword` mappings (§5.3) are still
BloodHound-only code paths, though `source_members` (§2.1) no longer is since #356. Either make collection
reliable or add LDAP-side equivalents; leaving them BloodHound-gated means shipping fixes that cannot run.

`op-20260730-040759` sharpens the point. A recon agent's own summary says it ran
`BloodHound (All collection)`, and the string `bloodhound` appears **zero times in the resulting report**.
So collection is being attempted and leaving no trace in state — which is the worst of the three
possibilities, because it is indistinguishable from not running unless you read the logs. Before adding
LDAP-side equivalents, establish whether the collector is failing, succeeding and not being parsed, or
succeeding and being parsed into fields nothing renders.

### 6.4 `description_field` mis-attributes the domain

Two genuinely different parsers read the same AD attribute — `user_description_leak`
(`ares-tools/src/parsers/users_shares.rs:143-165`, netexec `--users`) and `description_field`
(`ares-cli/src/orchestrator/output_extraction/passwords.rs:68-118`, rpcclient `queryuser`). Not a
duplicated path, but `description_field` uses the rpcclient task's `default_domain` (`:108`) and files
a child-domain principal under the root domain. Since dedup keys on
`cred:{domain}:{username}:{password_md5_16}` (`state/reader.rs:263`), the same secret can enter state
twice under different domains and defeat dedup. Also: all 39 rows across 93 ops are the same
principal — the sweep has never found a second one — and nothing scans the modelled `User.description`
field for secrets, so the finding only works when a tool happens to print it inline.

### 6.5 One fabricated success is sitting in a report

`op-20260729-182329` claims a captured NTLMv1 hash for a root-domain user "via Responder
(force_ntlmv1) + PetitPotam". It is not real: the claim sits inside an `Exploit attempted but failed:`
row, the hash tail is byte-identical to that user's NT hash already in the same op's table from
`secretsdump`, and the corresponding vulnerability remains `Status: Not Exploited`. A real Responder
capture was impossible on that build — the timeout path discarded its stdout, closed since as
`645f635` / #353 — so the model wrote a plausible narrative around data it already had. Note the
implication for future ops: that impossibility argument no longer applies, so a Responder claim after
2026-07-30 has to be judged on its own evidence.
**Worth a corpus scrub for other claims of this shape, and an evidence gate on
`report_finding` for capture-type claims.**

### 6.6 The realtime channel is missing roast *primitive* credit, not just the timeline event

Found while fixing §6.1, and distinct from it: §6.1 is about **MITRE attribution**, this is about
**exploit-scoreboard credit**. The two hash-publish paths do different amounts of work, and the §6.1 fix
only closed part of the gap.

On a successful `publish_hash` the **parser** path (`result_processing/mod.rs:2320-2360`) does three
things:

1. emits the hash timeline event (`create_hash_timeline_event`),
2. calls `emit_gmsa_exploit_token_if_gmsa` (§6.2),
3. emits a `roast_exploit_token` (`mod.rs:1583`, called at `:2349`) crediting the AS-REP / Kerberoast
   primitive **at capture time** — deliberately, so credit does not depend on the crack succeeding. A
   capture proves the primitive whether or not the wordlist covers the password.

The **realtime** path (`result_processing/discovery_polling.rs:137-150`) now emits the timeline event —
that is the §6.1 fix — but still emits **neither** `roast_exploit_token` **nor** the gMSA token
(verified: `roast_exploit_token` has exactly two non-test references, both in
`result_processing/mod.rs`).

**Cost**: roast primitive credit is missing for every hash that arrives via the realtime channel — and
per §6.1 that is the channel roast hashes actually use. So the scoreboard undercounts the AS-REP and
Kerberoast primitives on the 83 ops that captured 145 AS-REP hashes, independently of whether the MITRE
stamp is now right.

The primary session **deliberately did not bundle this** with the §6.1 fix. Emitting exploit-scoreboard
tokens on a newly-widened path is precisely the class of change that produced the phantoms this document
catalogues (§6.2, and the `seimpersonate` row in §0). It wants an explicit decision, not a silent
widening that arrives as a side effect of an attribution fix.

**Status**: Implemented `✔ code` — **PR #354** (`c956d7e`, CI 9/9 green), Verified `unit`. The
file-collision caveat is retired (#350 merged), and the operator approved the widening explicitly on
2026-07-29 — that was the decision this item was waiting on.

Fixed by **removing the second path rather than duplicating the block into it**. All three steps —
`create_hash_timeline_event`, `emit_gmsa_exploit_token_if_gmsa`, and the `roast_exploit_token` /
`mark_exploited` pair — now live in one `credit_published_hash` helper
(`result_processing/mod.rs`), and both publish paths call it. The realtime channel previously did
one of the three, then two of three after #350; it now does all three by construction, because there
is no longer a separate copy that can fall behind. `discovery_polling.rs` no longer imports
`create_hash_timeline_event` at all.

Verified `unit` — 3 new tests, suite 4040/1303/421/1621, 0 failed, clippy clean on 1.94 and 1.97.
The tests are **source-level parity guards**, not behaviour tests: they assert the realtime channel
routes through the helper and calls none of the three steps directly. That shape is deliberate —
`result_processing` has no `Dispatcher` test harness, so a behaviour test is not available at this
level, and the failure mode being guarded is precisely "one path silently stops doing part of the
work". The repo already uses this `include_str!` pattern in two places. **Not verified in a live
operation**: no op has emitted a `roast_exploit_token` from the realtime channel yet, so the
scoreboard undercount described above still stands as written.

**Status**: Implemented `✔ code` — `77ffe58` / #354, merged 2026-07-30 — Verified `unit`.

Both publish paths now call one `credit_published_hash` helper (`result_processing/mod.rs`), so neither
can emit part of the credit: `roast_exploit_token` has exactly two references in that file (its definition
and its single call site inside the helper), and `discovery_polling.rs:140` calls
`super::credit_published_hash`. The three tests are **source-level parity guards**, not behaviour tests —
`result_processing` has no `Dispatcher` harness — which is a weaker class of evidence than the other
`unit` rows in this document.

**`op-20260730-040759` shows the tokens landing, and shows that landing is not enough.** The mechanism
works: five roast tokens were credited into the exploited set. It is provable only by arithmetic, because
**not one of them renders anywhere in the report** — which is the new defect, filed as §6.7. The
undercount this subsection was written about is fixed; it has been replaced by an unauditable overcount.

### 6.7 `mark_exploited` credits vuln_ids that have no vulnerability record

Found in `op-20260730-040759`. The report's Success Metrics claims **30** vulnerabilities exploited.
Exactly **25** of its 257 vulnerability records render `- **Status**: EXPLOITED` (plus 1 `SUPERSEDED`,
231 `Not Exploited` — 257 total, so nothing is missing from the section). Five credits are counted and
not shown.

The five are identifiable, and they are §6.6's roast tokens. `roast_exploit_token`
(`result_processing/mod.rs:1594-1617`) mints `kerberoast_{user}` or `asrep_roast_{domain}`, and this op
captured four Kerberoast tickets and two AS-REP tickets, which reduce to exactly five distinct tokens.
`mark_exploited` (`state/dedup.rs:32`) then `sadd`s the id into `ares:op:{id}:exploited` **without
requiring a matching entry in `discovered_vulnerabilities`** — it only reads that map to compute
supersedes. So the id is a scoreboard member with no record behind it: it increments the metric, it
renders in no table, and no timeline row names it.

Three consequences, in increasing order of seriousness:

1. **The headline exploited count cannot be reconciled against the report body.** Any reader diffing the
   metric against the rendered rows finds a five-item gap with no way to attribute it. This is the same
   class of defect as the metrics traps in §0 — a number that is right for a reason the report does not
   contain.
2. **The credit is unauditable, so it cannot be distinguished from a phantom.** Every phantom in this
   document (`seimpersonate`, the §6.2 gMSA gate) was caught *because* it rendered somewhere and the
   evidence behind it could be checked. A credit that only exists as a Redis set member is structurally
   immune to that check. The fix is to emit a vulnerability record alongside the token, not to remove
   the token.
3. **`kerberoast_{user}` carries no domain, so the same SPN account in two forests collapses to one
   credit.** In this op the SPN service account was roasted in *both* the child domain and forest B, and
   both hashes minted `kerberoast_{same-user}` — one scoreboard entry for two distinct primitives on two
   distinct DCs. The comment at `:1598-1599` says "token-per-account so multiple SPN hashes don't collapse
   on a single entry", which is exactly what happens across a domain boundary. Note which case this
   silently undercounts: the cross-forest shared-password account that §2.4 exists to exploit. The AS-REP
   token is keyed per-domain and is fine.

**Reproduced in `op-20260730-070442` with the same five-record gap** — Success Metrics claims 29, exactly
24 records render `EXPLOITED`, 1 `SUPERSEDED`, 233 `Not Exploited` against 258 total. And the
domain-collapse case in consequence 3 is visible in that report's own hash table: the SPN service account
was roasted in the child domain *and* in forest B, two rows, one token.

**There are three different numbers, not two.** Redis `ares:op:op-20260730-070442:exploited` has
`scard = 31`, `ops runtime` reports 29 (21 exploitable + 5 findings + …), and the report renders 24. So the
authoritative set is larger than the metric that is itself larger than the body, and neither intermediate
number is derivable from the one below it. Whatever fix lands here should reconcile all three or state
plainly which is authoritative; adding a record for the roast tokens closes the 24↔29 gap but not
necessarily the 29↔31 one.

**#363 improved the symptom's visibility without touching the defect.** `ares ops runtime` now prints
`Warning: N exploit credits have no vulnerability record (not itemised by 'ops loot')`
(`ares-cli/src/ops/runtime.rs:78`) alongside a split of exploitable versus informational findings. That is
a real gain — the gap is now announced instead of having to be derived by diffing a metric against a
table — but the credit is still a bare Redis set member, so consequence 2 stands unchanged: it remains
structurally immune to the phantom check that caught every other phantom in this document. Do not read the
warning as the fix.

**`op-20260730-213328` reproduces all three numbers and widens the spread**: Success Metrics 32, rendered
`EXPLOITED` 27, timeline `Vulnerability exploited` rows 23. #366 shipped in that binary and changed how
supersession is counted without closing any gap. Note the interaction with §7.7 — at least six of those 23
timeline rows are themselves phantoms, so the *lowest* of the three numbers is still an overcount, and no
number in this report is a valid measure of conversion.

**Status**: `—` / `—`. Fixing 3 is a one-line key change (`kerberoast_{domain}_{user}`) and needs a
migration thought for the dedup key; fixing 1 and 2 means publishing a record, which is the same shape of
work as §5.3's missing vuln producer. The warning #363 added is the cheapest possible witness for whether
the record half ever lands: when it does, the warning goes to zero on its own.

---

## 7. Regressions

### 7.1 Chain edge 3 (WriteDacl) went from 47 dispatches to zero

Through 2026-07-27 it routed to `certipy_shadow` in the privesc agent, which replied *"I do not have
bloodyAD/dacledit tools in this agent toolset"* every time — 47 failures across 47 ops. The #283
re-route pulled it out of shadow-credentials and **nothing picked it up**: a hash-only source
principal (§1.2.3) plus a dominated domain (§1.2.2) means neither remaining driver can reach it. Still
discovered every operation, never dispatched again.

**Status**: Implemented `✔ code` — **merged to `main` as `d9d7dd8` / #350**, 2026-07-29.
`dacl_abuse.rs` falls back to `find_source_hash` when no plaintext
credential exists for an edge's source principal, mirroring the pattern `shadow_credentials.rs` already
used; `collect_dacl_work`'s early return no longer bails when only hashes are present; `DaclWork.credential`
became an `Option` alongside a new `hash` field; and the dispatch payload emits the hash under the same
key shape shadow-creds uses. Verified `unit` — 3 new tests, full workspace suite green
(4035/1303/421/1621, 0 failed), clippy clean on both 1.94 and CI's 1.97.

**The op ran and edge 3 still did not dispatch** — `op-20260730-040759` contains zero `writedacl`
timeline events of either polarity, against 12 discovered `writedacl` instances. The re-route cannot be
evaluated on its own terms, because §7.4 shows the whole ACL dispatch path went quiet in the same op:
`dacl_abuse` produced no log line at all. Edge 3 is now blocked behind §7.4 rather than behind #283.

`op-20260730-070442` repeats it exactly: zero `writedacl` timeline events of either polarity, and all
three of that op's ACL attempts were `allextendedrights` edges. Two ops, zero edge-3 dispatches, on a
binary containing the re-route both times.

### 7.2 A real shadow-credential win was lost to a Python dependency

`op-20260729-003520` at 00:42:09 shows `pywhisker` **succeeding** — `msDS-KeyCredentialLink` written —
then dying on `OpenSSL.crypto has no attribute PKCS12`, and the op reports it as a failure. This is
the `pyOpenSSL<25` breakage. **Confirm the pinned venv is live on the current box**; this single fix
plausibly converts the shadow-credential family, which has 67 ops of attempts behind it.

**Status**: Implemented `✔ env`, Verified `env` (box check, 2026-07-29). `/usr/local/bin/pywhisker` is a
shell wrapper that execs `/opt/pywhisker/venv/bin/pywhisker`, and that venv carries pyOpenSSL 24.0.0
reporting `PKCS12-OK`. The system `/usr/bin/python3` still has 26.1.0 / `NO-PKCS12`, but venv
site-packages take precedence, so it does not apply. The venv is dated Jul 29 03:28 — roughly three
hours after the 00:42 failure recorded above, consistent with the fix landing after that operation.

`pywhisker`, `shadow_cred` and `certipy_shadow` each appear **0 times** in `op-20260730-040759`, so that
op left the environment fix unverified.

**`op-20260730-070442` settles it, and the answer is that the venv is no longer the blocker.** `pywhisker`
ran against a user-target edge, reached the wire, and failed with `INSUFF_ACCESS_RIGHTS` while modifying
`msDS-KeyCredentialLink` — an **authorization** failure returned by the DC, not `OpenSSL.crypto has no
attribute PKCS12`. The pinned venv is doing its job: the tool got far enough to be told no. That closes
the venv question, and the row that tracked it has been deleted from §9.

What it fails on instead is §1.2b's problem, one layer up: the edge was sourced from a well-known
privileged RID and dispatched as an ordinary unprivileged principal, so the write was never going to be
permitted whatever Python was installed. Note also that the one-op silence in `op-20260730-040759` was a
blip rather than a trend — `pywhisker` appears in 51 ops and in four of the last six, so the "the family
has stopped being tried" reading of that op was wrong.

**Status**: the environment half is `✔ env` / `env` and can be considered done. The family's conversion
now depends on source-principal resolution (§1.2b) and on the irreversible-mutation guard for the
fallback path (§7.5), neither of which is an env question.

### 7.3 NTLMv1 downgrade is still dead

Three real successes ever, last **2026-07-05**, against 42 ops carrying failures with the latest on
2026-07-29. The apparent 2026-07-29 revival is the fabricated claim in §6.5. New tooling has landed
since (`force_ntlmv1`). One of its two blockers is gone — the timeout no longer discards Responder's
stdout (`645f635` / #353) — leaving the two parse/crack blockers in §4.1: the validator rejects
NetNTLMv1, and hashcat mode 5500 is absent. `op-20260730-040759` discovered one `ntlmv1_downgrade`
instance and never dispatched Responder at all, so the count of real successes is unchanged.

### 7.4 ACL abuse collapsed to a single attempt in the first post-merge op

**The most important open item in this document.** Found in `op-20260730-040759`, on a binary gated green
against all ten of #350–#359.

| Op | ACL successes | ACL failures | Time to first DA | Timeline span |
| --- | --- | --- | --- | --- |
| 2026-07-29 (055708) | 8 | 5 | +6m52s | 23m34s |
| 2026-07-29 (151601) | 0 | 2 | — | — |
| 2026-07-29 (182329) | 5 | 6 | +3m50s | 16m15s |
| 2026-07-29 (201720) | **12** | 0 | **+1m47s** | 13m22s |
| 2026-07-29 (231346) | 7 | 4 | +2m47s | 16m38s |
| **2026-07-30 (040759)** | **0** | **1** | +3m43s | 22m22s |
| **2026-07-30 (070442)** | **0** | **3** | +3m36s | 15m03s |
| **2026-07-30 (213328)** | **0 confirmed** (7 rendered, ≥6 phantom — §7.7) | 0 | +9m31s | 24m50s |

**Every "successes" figure above the last row is a rendered-timeline count and none has been log-checked.**
§7.7 shows that a failed task can render an `acl_*` exploited row, so the 8 / 5 / 12 / 7 in this column are
upper bounds, not measurements. Re-deriving them from the orchestrator logs is a prerequisite for treating
this table as evidence of a collapse at all — the change on 2026-07-30 might be in what gets credited
rather than in what runs.

**Two obvious explanations are excluded by that table.** It is not runtime: the new op's timeline spans
longer than three of the four comparison ops. It is not speed-to-DA shrinking the pre-domination window:
the op that hit DA fastest of all, at 1m47s, landed twelve ACL successes. Something else changed between
23:13Z on 2026-07-29 and 04:07Z on 2026-07-30, and what changed in that gap is #350–#359.

What the logs establish, none of which the reports can show:

- `auto_acl_chain_follow` fired **once**, at 04:09:42, produced **three** `acl_chain_step` tasks, and never
  fired again in the remaining 21 minutes.
- All three were admitted by the soft cap and then **deferred**, in a window carrying 223
  `Deferred queue full` lines. They never executed.
- `dacl_abuse` appears **zero** times in the log at info level.
- `/var/log/ares/acl.log` never advanced past its 04:07:02 deploy-time mtime, while `orchestrator`,
  `recon`, `credential_access`, `cracker`, `privesc`, `lateral` and `coercion` all did. The ACL worker ran
  nothing.
- The one ACL attempt in the report came from the LLM `request_exploit` route, not from either driver, and
  it is §1.2b's RID-519 edge.

So the failure is upstream of exploitation: ACL work is barely being *built*, and what is built is not
being *run*. Three candidate causes, in the order worth testing:

1. **#352 / #356 changed which principal an edge binds to.** The `find`-first and `seen_chains` mechanisms
   in §1.4's Correction are real in the code and both convert a would-be dispatch into a `break`. Neither
   is proven to have fired here. Testing it is cheap: re-run with `crackable_principals` returning an empty
   set and compare the `acl_chain_step` count.
2. **The deferred queue starves the `acl` role.** Three tasks against 287 deferred `recon` tasks, in an op
   that terminates on objective-achieved. This one is not new code, so it does not explain the *change*,
   but it explains why the little work that existed produced nothing.
3. **Something in #355 / #357 altered ownership or admin state in a way the ACL drivers gate on.** #357
   touches `state/publishing/hosts.rs` and host ownership; #355 rewrites credential rows in Redis. Both
   are plausible and neither has a mechanism identified.

**Do not attribute this to a single PR without a re-run.** Ten changes shipped in one deploy, which is the
cost this document warned about in the branch sweep and is now paying. The cheapest disambiguation is one
op per suspect with the others reverted, or — better — instrument `collect_acl_chain_work` and
`collect_dacl_work` to log a per-tick reason for every edge they decline, and re-run once. The absence of
any such logging is why three candidate causes remain indistinguishable after a full-log review.

**Status**: `—` / `—`. Nothing has been changed in response to this yet.

**A second op has run and the collapse persists, with one candidate cause newly excluded and one newly
added.** `op-20260730-070442` scored 0 successes against 3 attempts. Runtime is excluded again — its
timeline spans 15m03s and it hit first DA at +3m36s, both mid-range for the table. Two things the second
op establishes that the first could not:

- **Turning the diversity knobs on is not the fix.** Softmax selection, novelty memory and a randomised
  entry foothold moved ACL attempts from 1 to 3, still short of the pre-merge 4 and still converting
  nothing. Whatever suppresses this path is downstream of queue ordering, which removes the most
  attractive cheap explanation.
- **The §7.5 mutation guard is *not* the cause of the collapse, and should not be chased as one.** It
  landed 2026-07-28, before the 2026-07-29 ops that scored 8, 5, 12 and 7 successes, so it cannot explain
  a change that happened on 2026-07-30. It is a separate, additive blocker that removes one specific edge
  (§1.3 edge 1) and accounted for two of this op's three failures — worth fixing on its own terms, not as
  a row-0 hypothesis.

**The second op's logs settle two of the three original candidates and add a fourth nobody listed.**

- **Candidate 2 — "the deferred queue starves the `acl` role" — is excluded.** All 245 `Deferred queue
  full` drops in this op (120 plain, 125 while gating on cred) carry `task_type="recon"`; the span field
  is 100 % recon across 489 occurrences, with no other type appearing. ACL tasks are not being dropped by
  queue pressure. They were deferred — 2 `Task deferred task_type=acl_chain_step role=acl` lines, both
  admitted by the soft cap — and then died another way, below.
- **Candidate 1 remains open but is now cheap to test, because the instrumentation priority 0 asks for
  partly exists and is merely invisible.** `dacl_abuse.rs` already logs its declines: `DACL abuse skipped:
  domain dominated` (`:263`), `DACL abuse deferred: credential capture in flight` (`:271`), `Destructive
  ACL skipped: target material already in state` (`:283`), plus deferred/dropped at `:90,94` — **all at
  `debug!`**, while the box runs `RUST_LOG=info`. Only `DACL abuse dispatched` is `info!`. So the observed
  "`dacl_abuse` appears zero times in the log" means *never dispatched*, **not** never ticked, and the
  distinction the whole row turns on is one log level away. Run one op with debug scoped to the ACL
  modules before writing any code.
- **`acl.log` did advance this time**, to 07:16:32Z, carrying 12 in-window lines — 3 tool invocations
  total: two `bloodyad_set_password` and one `pywhisker`. The ACL worker ran, and everything it ran was
  one of the three LLM-routed RID-519 edges. Neither deterministic driver contributed a single execution.
- **Candidate 4, new: blue containment killed the only ACL chain work that existed.** See §7.6.

**A third op has run and it splits this row in two.** `op-20260730-213328`, gated green against #364–#370:

- **`dacl_abuse` produced 0 log lines for the third consecutive op.** Whatever silenced the deterministic
  DACL driver on 2026-07-30 is still silencing it, and no change in #360–#370 touched it. This half of the
  row is unmoved and remains the open question.
- **The chain sequencer, by contrast, is no longer quiet**: `acl_chain_step` appears 16 times against 3 and
  2 in the prior ops, from 3 `auto_acl_chain_follow` dispatches. Work is being built and routed. One step
  executed and failed on `pywhisker could not resolve target in LDAP`; two more were deleted by blue
  containment (§7.6) before running.
- **The ACL activity that did convert was not from either driver** — it came through the LLM
  `request_exploit` route, and §7.7 shows it did not convert at all.

**Candidate 1 is now the last one standing for the `dacl_abuse` half**, and the debug-log run this row has
asked for twice is still the way to test it. Nothing about the third op makes that cheaper or more
expensive; it just removes the temptation to read a recovery into the timeline rows.

### 7.5 ForceChangePassword has been hard-blocked since 2026-07-28 and nothing said so

Found in `op-20260730-070442`. `bloodyad_set_password` is the sole member of `IRREVERSIBLE_TOOLS`
(`ares-tools/src/mutation.rs:39`), gated behind `ARES_ALLOW_IRREVERSIBLE_MUTATION` by #308 (`1eb61ba`,
2026-07-28). **That variable is set nowhere** — not in `config/ares.yaml`, not in any Taskfile, not in the
deployment. Its only occurrence in the tree is the constant that names it (`mutation.rs:35`).

The corpus boundary is exact, and it is the cleanest before/after in this document:

| Window | `bloodyad_set_password` mentions | Refusals |
| --- | --- | --- |
| through `op-20260728-064041` | freely dispatched, up to 8 per op | **0** |
| `op-20260728-150151` onward, 11 consecutive ops | 1, 1, 1, 1, 1, 1, 1, 2, 3, 2 | **every one** |

So the primitive behind chain edge 1 — the one edge §1.3 credits as landing on the wire — has had a 100 %
refusal rate for eleven operations, and the failure surfaces only as an agent's prose complaint inside an
`Exploit attempted but failed` row. Nothing counts it, no vuln record carries it, and §1.3 still described
edge 1 as working.

The guard itself is correct and should stay: its doc comment says it exists so that "a fresh or
misconfigured deployment cannot destroy target accounts by default", and password overwrite genuinely has
no teardown. What is missing is the deliberate opt-in for a lab where irreversible mutation is the point.

**Status**: **observability half closed `op`** (PR #374, `op-20260731-053105`); **the block itself is
open and now measured rather than inferred.**

The startup log line this section asked for shipped, and all **7** workers in `op-20260731-053105`
announced:

```
Mutation policy: irreversible tools REFUSED — every call to them will fail until the env var is set
```

So the "nothing said so" half of this section's title is fixed: the policy is now auditable at startup
instead of being reconstructed from downstream task failures. **The refusal is still in force** —
`ARES_ALLOW_IRREVERSIBLE_MUTATION` remains set nowhere, which is now a measured fact about the deployed
box rather than an inference from the tree.

**One consequence, which is a genuine finding rather than bookkeeping: this row is now the confirmed cause
of a *different* row's zero.** #372 added a timeline event on reset-credential publish; `op-20260731-053105`
logs `Password reset confirmed` **0** times while `Discovery: credential published` fires 3 times from the
same PR. #372 works. The reset path cannot fire because the tool that produces a reset is refused before
it runs. Any future verification of a reset-dependent change against this box will read as a silent
no-op for the same reason, which makes the env var a prerequisite for testing, not just for converting.

The remaining work is unchanged and still needs no code: set `ARES_ALLOW_IRREVERSIBLE_MUTATION=1` on the
operating box. The dispatch-time *counted* decline is also still unbuilt — the announcement says what the
policy is, not how many dispatches it killed. This stays the cheapest available change that can move an
ACL success, and it is independent of §7.4.

### 7.6 Blue containment is deleting red's deferred queue mid-operation

Found in `op-20260730-070442`'s orchestrator log, and it is not mentioned anywhere else in this document.
The op ran with `ARES_BLUE_ENABLED=1`, and blue's containment actions revoked credentials that red had
deferred work against. The orchestrator then discarded that work:

```
07:19:15 INFO Dropping deferred task — invalidated by blue containment task_type=acl_chain_step target_role=acl reason=credential revoked (<forest-B account>)
07:19:15 INFO Dropping deferred task — invalidated by blue containment task_type=acl_chain_step target_role=acl reason=credential revoked (<forest-B account>)
```

**Those two lines are the entire fate of the op's ACL chain work.** `auto_acl_chain_follow` fired 3 times
and produced 2 deferred `acl_chain_step` tasks; both were admitted by the soft cap
(`Soft cap: allowing — role below minimum llm_count=12 max_tasks=12 role="acl" role_count=0`), both sat in
the deferred queue, and both were deleted by blue containment before executing. **Zero `acl_chain_step`
tasks ever ran.** `Task completed via LLM` with `role="acl"` appears 0 times.

The effect is not confined to ACL. 59 deferred tasks were dropped this way — 24 `recon`, 12 `lateral`, 11
`coercion`, 8 `credential_access`, 2 `exploit`, 2 `acl_chain_step` — attributed to three revoked
principals: 34 to a forest-B account, 16 and 9 to two child-domain accounts.

Three reasons this matters more than its line count suggests:

1. **It is a measurement hazard for every red row in this file.** A red-team change whose verification
   depends on a deferred task executing can be silently voided by blue, and the resulting report is
   indistinguishable from "the driver never built the work". §7.4 spent two ops and a full-log review on
   exactly that ambiguity for the ACL rows.
2. **It is invisible from reports**, like §7.5 and §2.3. Nothing in the report body or the `ops runtime`
   headline says work was discarded.
3. **The 2/2 hit rate on ACL work is suspicious and should be checked before it is accepted as chance.**
   ACL chain steps depend on freshly cracked or freshly dumped principals, which are precisely the
   credentials blue detects and revokes first. If that correlation is real, ACL work is structurally the
   most likely category to be contained, and no amount of red-side fixing will show up while blue runs in
   the same operation.

**Reproduced a third time, larger, in `op-20260730-213328`** — so this is systematic, not a one-op
coincidence. 60 deferred tasks dropped: 14 `recon`, 13 `lateral`, 11 `coercion`, 8 `credential_access`, 8
`privesc`, 4 `exploit`, **2 `acl_chain_step`**. The ACL number is 2 for the second op running, and both
drops name the same revoked child-domain account. Point 3's suspicion is now the working assumption rather
than a hypothesis: across two ops, blue has deleted 4 of the 5 `acl_chain_step` tasks that reached the
deferred queue.

**Reproduced a fourth time in `op-20260731-053105`**, and larger again: **238** deferred-task drop lines
against 60 and 59 in the two ops above, alongside 258 containment mentions. Four ops, four reproductions,
monotonically increasing — this is now the best-established open row in the document and the only one that
has never once failed to reproduce.

**Status**: `—` / `—`. This is a design question, not a bug: the drop is arguably correct behaviour for a
revoked credential. What is missing is that it is uncounted and unattributed. Minimum fix is a per-op
counter of blue-invalidated tasks by role, surfaced in `ops runtime` next to the orphan-credit warning, so
a red verification run can tell whether its subject was contained. For verifying red rows specifically,
consider one op with blue disabled — the cheapest way to remove this variable entirely, and something no
op in the recent corpus has done.

**That blue-disabled op is now the highest-value single experiment available**, and the reason is the
runtime anomaly rather than the queue drops. `op-20260731-053105` took **1h35m** against 16–25m for the
four ops before it, at double the cost, for the same 3/3 result — while dropping four times as many
deferred tasks as any previous op. Whether those two facts are the same fact is unknown and cheap to
settle: one op with `ARES_BLUE_ENABLED=0` answers it, and until it is answered every wall-clock and cost
comparison in this document is confounded by an uncontrolled variable.

### 7.7 Shadow credentials stop at stage one, and the half-attack is credited as an ACL success

Found in `op-20260730-213328`, and it is two defects that happen to share a symptom. Both are cheap.

**Defect A — the `acl` agent has no stage-two tool.** The shadow-credential attack is two moves: write
`msDS-KeyCredentialLink` on the target (`pywhisker`), then authenticate with the resulting PFX via PKINIT
to recover the target's NT hash (`certipy_auth` / `gettgtpkinit`). The op ran stage one **six times and it
worked every time** — the agent's own words, six variations on *"Shadow credentials injection succeeded
(PFX generated), but I don't have a `certipy_auth`/PKINIT tool"*. The `acl` role starts its loop with
`tools=15` and stage two is not among them. Six planted key credentials, six PFX files, zero hashes.

That is the whole conversion gap for this technique family. It is not a wire problem, not a Python problem
(§7.2 closed that), not a principal-resolution problem — the writes landed. One tool in one role's
registry closes it.

**Defect B — the failed task is credited anyway.** Each of those six tasks ends `WARN Task failed …
err="Assistance needed: …"`, and each still produces a `Vulnerability exploited: acl_*` timeline row and an
`EXPLOITED` status. The credit fires on the ACL write, not on the escalation the vuln record claims:

| Timeline row (21:43–21:54) | Task id | Log outcome |
| --- | --- | --- |
| `acl_genericall_*_administrator` | `exploit_1b9f9a18a7df` | `Task failed` |
| `acl_genericall_*` (root-domain user target) | `exploit_bf4c0673e383` | `Task failed` |
| `acl_genericall_*` (root-domain group target) | `exploit_26b31e8f435e` | no outcome line — unconfirmed |
| `acl_genericwrite_*` (child-domain user target) | `exploit_8cc41971da28` | `Task failed` |
| `acl_genericall_*` (local account target) | `exploit_1654dcb3dd41` | `Task failed` |
| `acl_genericall_*` (root-domain user target) | `exploit_cb5897927e5f` | `Task failed` |
| `acl_genericall_*_krbtgt` | `exploit_f3ddeaef340c` | `Task failed` |

This is the fourth phantom in this document's history and the first to survive the check that caught the
other three. `seimpersonate`, the §6.2 gMSA credit and the §6.7 roast tokens were all caught by diffing a
metric against a rendered row; this one **renders correctly in both places** and is only visible in the
orchestrator log. That is why the trust rule at the top of this file had to be rewritten rather than
re-applied.

Two things follow that are worth more than the fix itself:

1. **Five of this document's seven pre-collapse ACL "successes" have never been log-checked.** §1.1's
   ordering table, §1.3's per-edge counts and §7.4's success column are all built from timeline rows. If
   this crediting path predates the collapse, some of those 8/5/12/7 counts are phantoms too, and the
   "collapse" of §7.4 may be partly a *reporting* change rather than a behavioural one. Re-deriving §1.3
   from logs is the single highest-value audit left in this file.
2. **A phantom that renders correctly defeats every check this document relies on.** The only remaining
   discriminator is the task-id join, which nothing automates. A `Task failed` that still credits its vuln
   should be impossible by construction, not caught by a human reading two artifacts side by side.

**Status**: **Defect B closed `op`** — **PR #371**, verified by `op-20260731-053105`. **Defect A is `✔ code`
/ `op`-refuted**: the tool shipped, ran, and fails on a cause this section did not anticipate.

**Defect B is closed, and the arithmetic is exact.** `op-20260731-053105` renders
`Vulnerability exploited: acl_*` **0** times — against 7 phantom rows in the op above — and in their place
logs `Shadow credential written but never converted` **7** times, each followed by
`Exploit failure recorded as timeline event` naming the vuln_id. The same 7 events that were credited as
successes are now counted as failures. The marker split does exactly what it was built to do, and the
trust-rule violation that forced this document's rewrite is gone.

**Defect A shipped and is refuted, which is the more useful result.** `certipy_auth` is in the `acl` role's
registry, the agent calls it, and it reaches the wire — so "one tool in one role's registry closes it" was
right about the wiring and wrong about the outcome. Stage two now fails 4 times on:

```
certipy_auth failed: cannot load PFX (Invalid password or PKCS12 data)
                     after successful pywhisker add on <target>
```

`pywhisker` exports a **password-protected** PFX and `certipy_auth` is invoked without one. This is a
smaller gap than any this section has described — an argument, not a capability — and it is the entire
remaining distance on the shadow-credential chain. It is also the third consecutive relocation of this
technique's blocker (venv → missing tool → PFX password), so the next fix should be verified by an op that
recovers an NT hash, not by the absence of the current error string.

**The audit this section called for in point 1 is now cheaper and more urgent.** With defect B closed, any
`acl_*` credit appearing in a *future* op is trustworthy; the five pre-collapse successes in §1.3 and
§1.1 remain unaudited and were produced by the crediting path this PR removed. Re-deriving them from logs
is still the highest-value audit left in this file, and it is now a clean before/after rather than an
open-ended re-check.

Both defects shipped together, as this section argued they must. Defect A: `certipy_auth` added to
`acl::tool_definitions()` (15→16 tools) — no `ares-tools` change was needed, because `dispatch()` and
`parse_tool_output()` key on tool name with no role parameter, so the tool already executed and already had a
parser arm; the `acl` LLM simply never saw it. Verified on the box that `certipy` v5.0.4 is installed and the
role reports `missing_count=0`, so the dispatch can actually run. Defect B: `ACL_MUTATION_MARKERS` split, with
the three shadow-cred stage-one markers moved to `SHADOW_CRED_STAGE_ONE_MARKERS`, which never satisfy the
gate alone; a completed chain credits through ordinary parser evidence instead. A `warn!` fires when stage one
lands unconverted, so the gap is countable rather than silent.

One hole closed that this section did not name: `ACL_MUTATION_MARKERS_NEEDING_ATTRIBUTION` contains `"done!"`
and `"added to "`, and `pywhisker` is in `ACL_MUTATION_TOOLS` — so a bare `[+] Done!` would have credited
regardless of the split. Stage-one tools now skip the attribution path entirely.

**Four existing tests asserted the defect as correct behaviour** and were inverted rather than worked around,
including one named `acl_shadow_cred_success_now_clears_the_whole_exploit_gate`. A fifth,
`assisted_terminal_acl_write_still_credits`, was added to pin that the split does not undo #327's legitimate
case — an ACL write that *is* the objective still credits on assistance.

**Original framing, retained**: Defect A is one entry in the `acl` role's tool registry plus a parser arm for the
PKINIT output — and note §1.2 blocker 5 already records that no `pywhisker` arm exists, so the two are the
same piece of work. Defect B is a gate in the exploit-completion path: do not `mark_exploited` on a task
that ended in `Assistance needed` or any non-success terminal state. Do A and B together — A alone starts
converting real hashes while B alone stops the inflation, but shipping A without B means the new real
successes are indistinguishable from the phantoms already in the corpus.

---

## 8. Attack-path diversity: still one path, now tested

Across 93 reports there is exactly **one** real attack-path signature — `secretsdump → krbtgt NTLM
hash` — run by every successful operation, rendered two ways (`→` in 20, `->` in 64). Real variation
exists one layer down (which primitive opened the door differs: ESC1 / ESC3 / ESC8 / ESC13 / MSSQL
linked-server / S4U), and per-op technique count has grown roughly 5×. But every opening converges on the
same terminal move, and DA is achieved for the child domain in 83 ops versus the root domain in 10 and
forest B in 8.

**Two updates from `op-20260730-040759`, pulling in opposite directions.**

The ceiling moved: it reached DA and a golden ticket in **all three domains inside 24 minutes** — the
child domain at +3m43s, the root at +4m50s, forest B at +21m. All-three-domain ops are now 8 in the
corpus, and 6 of those 8 are consecutive recent runs, so this has become the normal outcome rather than
the exceptional one.

The variation did not. All the "one layer down" diversity that paragraph credits is now concentrated in a
single subsystem: 10 of the op's 25 exploited records are ADCS (ESC8 ×4, ESC1 ×2, ESC3 ×2, ESC13 ×2), and
ACL, GPO, LAPS, gMSA, shadow-credential and relay-capture contributed **nothing at all**. Faster
convergence on one path is not the same as more paths, and this op is the clearest instance yet of the two
being confused: every headline number improved while the number of distinct routes fell.

**The feature built to fix this has now been run, and the answer is a capability ceiling rather than a
queue-ordering artifact.** #361 turned all four knobs on in the shipped config — `selection_temperature:
0.7`, `novelty.enabled: true` scoped per-campaign, `randomize_entry_foothold: true`, `emit_path_records:
true` (`config/ares.yaml:96-116`) — and #362 moved path recording onto the dedup path. The defaults in
`strategy.rs:91-95` are still off, so the config is doing the work; `Strategy::resolve` reads the YAML at
`:227-241`. `op-20260730-070442` is the first operation to run with them live.

It changed nothing about the shape of the result:

- **Terminal move identical.** `secretsdump -> krbtgt hash`, the 94th consecutive op with that signature.
- **Converted set identical.** 24 exploited records against the previous op's 25, the same eleven
  technique types, differing by one fewer `ldap_signing_disabled`. ADCS is 10 of the 24 in exactly the
  same mix.
- **Attempt breadth recovered partially and remains below the pre-merge baseline** — 14 failed attempts
  against 9 in the previous op and 18 in the last pre-merge op; ACL attempts 3 against 1 and 4.
- Zero ACL, zero GPO, zero LAPS, zero gMSA, zero shadow-credential, zero relay-capture successes, for the
  second op running.

The knobs demonstrably reach selection — more distinct techniques were tried — and every technique they
newly reached failed on something selection cannot influence: a tool the box cannot run (§3.8), a payload
missing a required field (§3.9), an env guard (§7.5), an unresolvable source principal (§1.2b), or a CA
that stamps the requester's SID (the KB5014754 note in the second verdict section). **That is the
finding.** Single-path convergence was never mainly a sampling problem, and the four knobs cannot be
expected to fix it; what they can do is stop masking which walls the alternate paths hit, which is exactly
what this op did.

Two consequences for how the rest of this file should be read. The §8 argument for prioritising diversity
work above ACL/lateral/reuse work is **withdrawn** — the precondition it claimed (that those rows are
unfalsifiable until the knobs are on) has been satisfied, and they are still unfalsifiable, for the
reasons in §7.4. And the fleet sweep in the `attack-path-diversity-sweep` skill is now worth running for
*measurement* rather than as a test of the hypothesis: with `emit_path_records` live, it can quantify how
many distinct paths exist at all, which no single op can.

**What the path records actually contain, and two gaps in the plumbing.** The op wrote 57 records to
`ares:op:<id>:path_record`, with `ares:op:<id>:coverage` holding 24 distinct steps and
`ares:novelty:per-campaign:steps` the same 24 — so novelty memory is accumulating across runs as designed.
The 24 are ADCS ESC1/ESC3/ESC8/ESC13 on both CA hosts, `dc_secretsdump` and `golden_ticket` on all three
DCs, `child_to_parent` on two, plus `constrained_delegation`, `ldap_signing_disabled`, `mssql_access` and
`mssql_linked_server`. Two problems with using this as coverage measurement as it stands:

- **33 of the 57 records are `mssql_linked_server` repeats**, and one step key is `adcs_esc8:` with an
  empty target. Deduplication is happening at the coverage set but the record list is dominated by one
  technique re-firing, so any per-record statistic is skewed unless it reads `coverage` instead.
- **The records exist only in Redis.** There is no `reports/diversity/` directory and no filesystem output
  anywhere on the box, so the records vanish with the Redis instance. The sweep procedure in the skill
  assumes a persisted artifact; whoever runs it needs to export from Redis first, or `emit_path_records`
  needs a writer.

Observability of the knobs themselves is one line for the whole op:
`Strategy resolved preset=Comprehensive … selection_temperature=0.699999988079071 novelty_enabled=true
randomize_entry_foothold=true emit_path_records=true`. There are **no per-selection softmax, novelty or
temperature decision lines**, so which candidate the sampler passed over — the thing that would show
diversity working or not working at the tick level — is not recorded anywhere. That is the gap to close
before the fleet sweep is worth its cost.

---

## 9. Priorities

Ordered by expected coverage gain per unit of work. Markers per the legend at the top of this file: an
`Implemented` marker with `Verified: unit` or `env` does **not** mean the gap is closed.

**Three rows have been deleted from this table as done** and are recorded in §0: the old row 1 (the
`pyOpenSSL<25` venv, closed `env` — `pywhisker` now demonstrably writes to LDAP, §7.7), the old row 10
(roast MITRE attribution, closed `op`) and **the old row 19** (drop `krbrelayup` from the Linux technique
set — closed `op` by #371 and `op-20260731-053105`, 0 occurrences in the deployed binary and 0 dispatches).
Row 11 keeps its number and its `op` marker but stays listed,
because the fleet sweep it asks for has not run. Numbers are never reused — the gaps at 1, 10 and 19 are
deliberate, since a dozen places in this file say "priority 3" or "priority 13" by name and renumbering
would break them silently. The same reason keeps **24**, **-2**, **-1**, **0**, **16** and **20**–**23**
out of numeric order.

**Before starting any row, read Parallel work coordination at the top of this file**, especially the binary
gate. Rows 2, 3, 4, 6a, 7, 9, 13, 14, 15, 17 and 18 have merged to `main` and are **not** closed: per the
legend only `op` closes an item, and three ops have now failed to exercise most of them. Row 6a is
numbered as a prerequisite rather than a priority because it adds no coverage — it only prevents a phantom.
§0 is reserved for items an operation has confirmed, or for corrections and rejected proposals — not for
code fixes awaiting their first op, however conclusive the grep.

**Row 24 is now the first thing to do, and it displaced row -2 by shipping it.** #371 landed row -2's tool
and credit gate; `op-20260731-053105` proved the credit gate works and moved the blocker one step down the
chain, to a PFX password that is never passed. Row 24 is what is left of that chain — an argument, not a
capability, and the smallest remaining unit of work in this table that can convert a technique.

**Rows 24 and -1 are the first two things to do**, in that order. Both unblock an attack primitive
outright rather than diagnosing why others are quiet: 24 is one argument on one tool call, standing
between seven already-successful shadow-credential writes and seven NT hashes; -1 is a single environment
variable with no code at all. Neither depends on row 0.

| Priority | Item | Implemented | Verified | Evidence |
| --- | --- | --- | --- | --- |
| **24** | **Pass the PFX password to `certipy_auth` (§7.7 defect A)** | `—` | `—` | **New, and the cheapest conversion on the board — it is an argument, not a capability.** Row -2 shipped the tool and it reaches the wire; `op-20260731-053105` then failed stage two **4 times** on `certipy_auth failed: cannot load PFX (Invalid password or PKCS12 data) after successful pywhisker add`. `pywhisker` exports a **password-protected** PFX and the `certipy_auth` call site passes none. Seven `msDS-KeyCredentialLink` writes landed in that op and produced zero hashes for want of one argument. **Verify by an op that recovers an NT hash, not by the error string disappearing** — this is the third relocation of this technique's blocker (venv → missing tool → PFX password), and the first two both looked closed at the point the error text changed. |
| **-2** | **Give the `acl` role a PKINIT tool, and stop crediting failed tasks (§7.7)** | `✔ code` — **PR #371** | **`op`** (credit gate) / `op`-refuted (tool) | **Shipped, and it split in two.** The credit gate is **closed** — `op-20260731-053105` renders `Vulnerability exploited: acl_*` **0** times against 7 phantoms the op before, logging `Shadow credential written but never converted` in their place. The tool half shipped and is **refuted rather than closed**: `certipy_auth` is in the registry, the agent calls it, it reaches the wire, and it dies on a PFX password. The premise "one registry entry closes it" was right about the wiring and wrong about the outcome. Remaining work is row 24. |
| **-1** | **Set `ARES_ALLOW_IRREVERSIBLE_MUTATION=1` on the box (§7.5)** | `—` (env), `✔ code` for the startup line — **PR #374** | **`op`** (startup line) / `—` (env) | **Still an env change with no code and no dependency on row 0 — now with the block confirmed live.** #374's startup line shipped and all **7** workers in `op-20260731-053105` announced `Mutation policy: irreversible tools REFUSED`, so the refusal is measured on the deployed box rather than inferred from the tree. `bloodyad_set_password` remains 100 % refused across 12 consecutive ops since #308, and it is the sole primitive behind chain edge 1. **New argument for doing this now:** the same op logged `Password reset confirmed` 0 times while its sibling `Discovery: credential published` fired 3 times — so the refusal is now the confirmed cause of a *different* PR's path never executing, which makes the env var a prerequisite for **testing** reset-dependent changes, not only for converting them. The *counted* dispatch-time decline is still unbuilt. |
| **0** | **Diagnose the `dacl_abuse` silence, and re-derive the ACL success history from logs (§7.4, §7.7)** | `—` | `—` | **Narrowed and split after three ops.** The `dacl_abuse` driver has produced **0 log lines in all three**, and that is now the whole of this row — the chain sequencer recovered on its own (16 `acl_chain_step` lines vs 3 and 2). Candidate 2 (queue starvation) **excluded**; candidate 4 (blue containment, §7.6) **confirmed** and split off as row 22. Candidate 1 is the last standing and the test is unchanged: one op with `debug!` scoped to the ACL modules, since every decline reason already logs there (`dacl_abuse.rs:90,94,263,271,283`) while the box runs `RUST_LOG=info`. **New second half, and do it first:** §7.7 shows failed tasks render as ACL successes, so the 8/5/12/7 history this row calls a collapse has never been log-checked. Re-derive it before diagnosing a change that may not have happened. Blocks rows 2, 4 and 9. |
| 2 | Re-route chain edge 3 (§7.1) | `✔ code` — merged to `main`, `d9d7dd8` / #350 | `unit` | 3 new tests; suite 4035/1303/421/1621, 0 failed; clippy clean on 1.94 and 1.97. **Op ran, edge 3 still did not dispatch** — 12 `writedacl` instances discovered, zero timeline events. Not attributable to this change: §7.4 shows `dacl_abuse` produced no log line at all. |
| 3 | Cross-domain pass-the-hash reuse probe (§2.4) | `✔ code` — merged, `080ef4e` / #351 | `unit` | 9 tests; clippy clean on both toolchains. **Op ran, probe never fired — precondition unreachable.** It needs the same NTLM in two forests; the op held the SPN account's NTLM in the child domain and only its `$krb5tgs$` ciphertext in forest B, because a fast forest-B DCSync is user-scoped. See §2.4 for the two ways out. |
| 4 | Root ACL chains at crackable identities, not owned ones (§1.4) | `✔ code` — merged, `a4bfd47` / #352 | `unit` | 8 tests; 7407 workspace tests. **Op ran and the result was negative** (0 ACL successes). Also a **suspect** for row 0: §1.4's Correction shows `find`-first principal selection and `seen_chains` theft can each turn a would-be dispatch into a `break`, which falsifies the change's strict-subset claim. |
| 5 | Fix the timeout-discards-stdout path (§4.1) | `✔ code` — merged, `645f635` / #353 | `unit` | Executor-level fix; 7 tests incl. a real-subprocess end-to-end. **Op ran and never entered the path** — `responder` / `ntlmrelayx` / `mitm6` all 0 occurrences. Verifying it may need an op denied the fast path, since a 24-minute DA needs no listener. NTLMv1 sub-blockers untouched (`parsers/secrets.rs:593`; mode 5500 absent). |
| 6 | Emit `laps_reader` / `gmsa` vuln types + the gMSA parser arm (§5.3, §5.2) | `—` | `—` | Unchanged. Its **prerequisite** — the §6.2 phantom gate — is now `✔ code` / `unit`, which is what makes this item safe to start. The item itself has not begun. |
| 6a | Gate the §6.2 gMSA phantom — **prerequisite of 6, not 6 itself** | `✔ code` — merged to `main`, #350 | `unit` | `is_gmsa_read_source` (`result_processing/mod.rs:1084`) now required alongside `is_gmsa_principal`; a `secretsdump` source no longer credits; false log line corrected. Six tests incl. `no_op_for_gmsa_hash_arriving_from_dcsync`. No coverage gain — it prevents one. |
| 7 | Persist `is_admin` and keep the host scope (§2.3) | `✔ code` — merged, `eed9cb5` / #355 | **`op`** (persistence) / `—` (host scope) | **Closed on the persistence half after three ops that could not test it.** `op-20260731-053105` produced **13** `Pwn3d!` lines and **4** admin upgrades across 2 principals, and the credential renders **`(admin)`** in `ops loot` — the first admin-flagged credential against a corpus of 443 `Admin = No` / 0 `Yes`. `mark_credentials_admin`'s `hset` writeback reaches the Redis-backed render, which is exactly what the bullet said was missing. The **host scope** half is untouched and stays `—`: §2.3's third-bullet consumers still pick any admin credential for any owned host. |
| 8 | Build the WriteOwner primitive (§5.1) | `—` | `—` | Unchanged, and now cheap relative to its payoff: `op-20260730-040759` discovered 12 `writeowner` + 8 `gpo_writeowner` instances and can act on none of them. |
| 9 | Make membership first-class (§2.1) | `✔ code` — merged, `d729e45` / #356, partial | `unit` | Fixes the group-**sourced** half of §1.2 blocker 3: `memberOf` now survives deserialization and seeds `AclEdge.source_members` from LDAP instead of BloodHound-only. 8 tests. **Op ran with no observable effect** — `source_members` still 0 occurrences in 93 reports; also a **suspect** for row 0. Group-**target** skip and the prompt surface still unfixed. |
| 11 | Turn the diversity knobs on and run the sweep (§8) | `✔ code` — #361 + #362 | **`op`** | **The knobs are on and the experiment has run.** All four live in `config/ares.yaml:96-116`; `op-20260730-070442` is the first op with them. Result: terminal path unchanged, converted set unchanged, attempt breadth partially recovered but still below the pre-merge baseline. **Single-path convergence is a capability ceiling, not a queue-ordering artifact** — see §8, which withdraws its own argument for prioritising this above the ACL/lateral/reuse rows. What remains is the fleet sweep as *measurement* rather than as a test. |
| 12 | Decide the on-target execution question explicitly (§5.6) | `—` | `—` | Still an unmade decision. |
| 13 | Emit roast / gMSA exploit-credit tokens on the realtime channel (§6.6) | `✔ code` — merged, `77ffe58` / #354 | `unit` | Both publish paths collapsed into one `credit_published_hash` helper, so a path can no longer do part of the work. 3 tests, all **source-level parity guards** — a weaker evidence class than the other rows here. **The op shows the tokens landing and rendering nowhere**; the undercount is fixed and replaced by an unauditable overcount — row 16. |
| 14 | Lateral / GPO parser arms | `✔ code` — merged, `a427762` / #357 | `—` | Swept up: complete work that had no PR. **Op ran and exercised none of it** — `psexec` / `wmiexec` / `smbexec` all 0 occurrences. The GPO half is now upstaged by §3.2's finding that the driver dispatches and the binary is missing from the container. |
| 15 | Silver ticket, red + blue (§5.5) | `✔ code` — merged, `7f80957` + `678b871` / #358 + #359 | `—` | Must land together; ID join verified on `T1558.002`. **Op ran and never attempted it** — `T1558.002` 0 occurrences. Since both halves shipped, the ID join is at least not making the scorecard worse while it waits. |
| **16** | **Give roast credit a vulnerability record, and put the domain in the token (§6.7)** | `—` | `—` | **New.** `op-20260730-040759` counts 30 exploited and renders 25; the 5-item gap is §6.6's roast tokens, credited into a Redis set with no vulnerability record. Also `kerberoast_{user}` omits the domain, so one SPN account roasted in two forests collapses to a single credit — undercounting exactly the cross-forest case row 3 exists to exploit. |
| 17 | Stop SID-sourced ACL edges resolving to a non-member (§1.2b) | `✔ code` — merged #360 | `unit` | The unconditional in-domain fallback is gone and membership is checked against the group the RID names. 6 tests. **The op ran and the prediction failed: 3 RID-519 dispatches, not fewer.** The guard has one call site (`dacl_abuse.rs:232`); `acl.rs`'s `resolve_step_principal` has no SID handling and the three dispatches came through the unguarded LLM `request_exploit` route. Remaining work is a guard where a raw-SID edge becomes an LLM task. Check the `starts_with("S-1-5-21-")` case-sensitivity first — one grep, and if `source` is lowercased the membership arm is dead code. |
| 18 | Heartbeat the op status record (§4.4) | `✔ code` — merged #360 | `unit` | `updated_at` now moves on every lock-keeper tick; `status_changed_at` preserves the old meaning; `ares ops status` / `ops list` report heartbeat age and mark stale past three intervals. 9 tests. Proves the lock keeper is alive, **not** that work is progressing — see the §4.4 caveat. Not observed on `op-20260730-070442`: heartbeat age does not render for a `completed` op, so this still needs a mid-flight check. |
| **20** | **Decline ADCS dispatches missing a required field (§3.9)** | `✔ code` (decline half) — **PR #374** | `unit` | **New.** ESC15 ships without `template` because `build_adcs_payload` sets it only when present (`adcs_exploitation.rs:2359`), and `certipy_request` cannot run without it — `CERTSRV_E_NO_CERT_TYPE` in the last 5 ops that reached ESC15, twice in the op before last. **`op-20260731-053105` neither confirms nor refutes the decline half**: it logged 0 template-gate skips because it dispatched ESC15 0 times, so the gate had nothing to decline. Still `unit`. Populating `template_name` from the `certipy_find` parse is the second half and is blocked on capturing one raw `certipy find` transcript (§3.9). |
| **21** | **Credit local-admin discovery for hash-only principals (§2.3)** | `—` | `—` | **Still open, and now bounded rather than total.** `op-20260730-070442` fired one `Pwn3d!` that credited nothing because the principal was held as a hash, not a credential row. `op-20260731-053105` fired **13** and credited **4**, across 2 principals that *did* have credential rows — so row 7 is unblocked for the credential-backed case and this row is now specifically about the hash-only remainder. The gap between 13 discoveries and 4 upgrades is the size of that remainder and is worth deriving exactly before writing code: some of the 13 are repeat detections of the same principal. Fix is unchanged — the `find_source_hash` fallback #350 gave `dacl_abuse`. |
| **22** | **Count blue-invalidated tasks, and run one op with blue off (§7.6)** | `—` | `—` | **Promote this — four reproductions, monotonically increasing, and it now has a second symptom.** Deferred-task drops went 59 → 60 → **238** in `op-20260731-053105`; nothing counts or surfaces any of them, so a voided red verification is indistinguishable from a driver that built nothing. The new symptom is wall clock: that op took **1h35m at $12.24** against 16–25m and ~$6.40 for the four before it, for the same 3/3 result, while dropping four times as many tasks. Whether those are one fact is unknown and one `ARES_BLUE_ENABLED=0` op settles it. Until it is settled, **every wall-clock and cost comparison in this document is confounded**, which makes this the cheapest way to make rows 0, 2, 4 and 9 measurable at all. |
| **23** | **Parse ESC16 and use it to condition the UPN-spoof family (§5.7)** | `—` | `—` | **New, and correctly placed below every live-conversion row.** `esc16` occurs exactly once in the tree — a test asserting its absence (`parsers/certipy.rs:659`), backed by a `len() == 14` pin at `:653`. The lab does not configure it, so nothing is failing on it today; what it costs is the ability to tell "the CA stamps the SID, so UPN spoofing is dead" from "the CA omits it CA-wide, so spoofing is live on every template". ares carries the spoof primitives and the KB5014754 reasoning already (`privesc/adcs.rs:647-650`, `golden_cert.rs:55`) and fires them unconditioned on the one fact that decides them. Check the installed certipy version before writing anything. Land it as a CA-level precondition, **not** as a vulnerability record — a record with no driver is §3's failure mode by construction. |

Detail, in the same order:

24. **Pass the PFX password to `certipy_auth`** (§7.7 defect A). The smallest unit of work in this table
   that can convert a technique, and the last step of a chain whose other three steps all now work:
   `pywhisker` authenticates, resolves its target, and writes `msDS-KeyCredentialLink`; `certipy_auth` is
   in the role's registry and gets called. Only the handoff between them fails, because the PFX
   `pywhisker` produces is password-protected and the `certipy_auth` call site passes no password. Seven
   writes, zero hashes, one argument. **Verify it with an op that recovers an NT hash.** This technique's
   blocker has now moved three times — venv, then missing tool, then PFX password — and on the first two
   occasions the change in error text was mistaken for progress toward closure; it was progress, but each
   time the next wall was one call deeper, and only a recovered hash proves there is no fourth.
-2. **Give the `acl` role a PKINIT tool, and gate the credit** (§7.7). **Shipped as #371, and it split.**
   The credit gate is closed on `op` — the seven writes that would have rendered `EXPLOITED` now render as
   counted failures, which is the finding that forced this document's trust rule to be rewritten and is now
   reversed. The tool half is refuted rather than closed: it was true that the `acl` agent had no PKINIT
   tool and false that adding one would convert anything, because the next failure was waiting one call
   later. What remains is row 24.
-1. **Set `ARES_ALLOW_IRREVERSIBLE_MUTATION=1`** (§7.5). One env change, no code, no dependency on any
   other row, and it restores the primitive behind chain edge 1 after eleven ops of 100 % refusal. Add the
   startup line and the counted decline in the same pass so the class of defect — a guard visible only as
   agent prose — cannot recur.
0. **Diagnose the ACL dispatch collapse** (§7.4). Still ahead of the rows it blocks, but **the ask has
   changed and shrunk.** Do not start by writing instrumentation: `dacl_abuse.rs` already logs every
   decline reason at `debug!` (`:90,94,263,271,283`) and the box runs `RUST_LOG=info`, so the first move is
   one op with debug scoped to the ACL modules. That alone separates "gated", "never ticked" and "bound to
   an unusable principal", which a full-log review at info could not. Two candidates are already settled —
   queue starvation is excluded, blue containment (§7.6) is confirmed to have deleted both chain steps — so
   pair the debug run with row 22's blue-off op and the remaining ambiguity is one variable, not three.
   Reverting `crackable_principals` to an empty set remains the cheapest single-variable test of candidate 1.
2. **Re-route chain edge 3** (§7.1). A live regression with a known cause; restores 47 ops' worth of
   dispatch. Shipped, and the op that followed did not dispatch edge 3 either — but §7.4 shows the whole
   path went quiet, so this is now downstream of row 0.
3. **Add a cross-domain pass-the-hash reuse probe** (§2.4). Merged as #351. Built as a capability
   addition, not the "few lines" an earlier revision of this document claimed — there was no auth-probe
   primitive to swap in. **The op showed the design's weak point rather than its wire behaviour**: the
   probe requires the same NTLM in two forests, and a fast forest-B DCSync is user-scoped, so the
   forest-B half of the twin is systematically absent and the gate cannot arm. Fixing that means
   accepting a roast-ciphertext-vs-NTLM pairing as candidate evidence — see §2.4.
4. **Root ACL chains at crackable identities, not owned ones** (§1.4). The only change that can move
   an ACL success before DA, which is the single largest structural finding in this document. It shipped,
   and it is now also a **suspect** in row 0: the strict-subset safety claim holds for ranking but not for
   `find`-first principal selection or `seen_chains` dedup.
5. **Fix the timeout-discards-stdout path** (§4.1). `✔ code` / `unit`, merged as #353 — **not closed**.
   Done at the executor rather than per tool: pipes are drained as the child writes, and a timeout
   holding output returns it for parsing. Responder, all four `ntlmrelayx_*` and `mitm6` are reachable
   for the first time; none is proven to capture. What remains inside the item is the NetNTLMv1 pair —
   a validator that accepts a v1 challenge and a hashcat 5500 entry — neither worth doing without the
   other, since either alone still yields nothing crackable.
6. **Emit `laps_reader` / `gmsa` vuln types** (§5.3, §5.2) — plus a gMSA parser arm. Prefer an LDAP-side
   producer over a BloodHound mapping (§6.3). **The "gate the gMSA phantom first" precondition is now
   satisfied** (row 6a, §6.2): the gate landed as `✔ code` / `unit`, so the arm can be added without the
   phantom arriving in the same commit as the capability. The item itself is untouched — both of §5.2's
   blockers and §5.3's missing producer are exactly as described.
7. **Persist `is_admin` and keep the host scope** (§2.3). `✔ code` / `unit`. Ares already discovers
   all three lab grants correctly and threw both the scope and the flag away. The flag now reaches
   Redis and the host now reaches the timeline event. This does **not** by itself make lateral
   targeting host-scoped — the consumers in §2.3's third bullet are still host-unscoped, and that
   remains `—`.
8. **Build the WriteOwner primitive** (§5.1). Unblocks mid-chain edge 6 and ~2,700 discovered
   instances.
9. **Make membership first-class** (§2.1) — at minimum, stop dropping `memberOf` at the serde boundary
   and put groups in `format_state_context`. This is the root cause of the group-sourced-edge dead end
   and of the cross-domain-membership path never being taken.
11. **Turn the diversity knobs on and run the sweep** (§8).
12. **Decide the on-target execution question explicitly** (§5.6).

13. **Emit roast / gMSA exploit-credit tokens on the realtime channel** (§6.6). Merged as #354. Fixed by
    collapsing both publish paths into one helper rather than duplicating the block, so drift is
    structurally prevented. The op shows the tokens landing; what it also shows is that landing in a Redis
    set is not the same as reaching a report, which is row 16.
16. **Give roast credit a vulnerability record, and put the domain in the token** (§6.7). Two independent
    defects behind one symptom. The domain half is a one-line key change and should be done first, because
    it is currently collapsing two forests' worth of one primitive into a single credit. The record half is
    the same shape of work as §5.3's missing vuln producer, and it is what makes the credit auditable —
    every phantom this document has caught was caught because it rendered somewhere.

Deferred deliberately: replacing prefix-string technique identity with an enum. It is the right
long-term fix for the whole Class-2/Class-3 family, but the specific prefix bugs it would have caught
are now fixed individually, so it no longer blocks coverage.

---

## Reproduction

```bash
cd reports/red

# One attack-path signature, two renderings
rg --no-filename '^\*\*Attack Path\*\*: ' *.md | sort | uniq -c

# DA per domain — real timeline events, not Status flags
rg --no-filename -o 'Domain Admin achieved for [a-z.]*' *.md | sort | uniq -c | sort -rn

# ACL successes, and their ordering against DA (expect every one to come after)
rg -o '\| 2026[^|]*\| (CRITICAL: Domain Admin achieved|Vulnerability exploited: acl_)[^|]*' *.md

# is_admin never persists: expect 443 "No", 0 "Yes"
rg --no-filename -o '^\| [a-z.]+ \| [^|]+ \| `[^`]*` \| [a-z_:]+ \| (Yes|No) \|$' *.md \
  | grep -oE '(Yes|No) \|$' | sort | uniq -c

# ...while local-admin discovery demonstrably worked
rg --no-filename -o 'Admin access confirmed: [^|]*' *.md | sort | uniq -c

# Cross-domain password reuse, visible as an identical NT half in one table
rg --no-filename -o '^\| [a-z.]+ \| [a-z_]*svc[a-z_]* \| ntlm \| `[^`]*`' *.md | sort | uniq -c

# T1558.004: 0 for the first 92 of them, then exactly 1 — op-20260730-040759 and no other
rg -l 'T1558\.004' *.md
rg -l 'T1558\.003' *.md | wc -l
rg -l 'Vulnerability exploited: constrained_delegation_' *.md | wc -l

# The §6.7 arithmetic: metric says 30, records render 25
rg -o '^\| Vulnerabilities (Exploited|Superseded|Found) \| [0-9]+' op-20260730-040759.md
rg -o '^- \*\*Status\*\*: .*' op-20260730-040759.md | sort | uniq -c

# §7.4: ACL success/failure per op, newest last — expect 8/12/7 then 0
for f in op-202607{29,30}*.md; do printf '%s ok=%s fail=%s\n' "$f" \
  "$(rg -c 'Vulnerability exploited: acl_' $f || echo 0)" \
  "$(rg -c 'Exploit attempted but failed: acl_' $f || echo 0)"; done

# Detection-without-dispatch: discovered but zero events of either polarity
rg -l '^#### adcs_esc11 on' *.md | wc -l
rg -l 'adcs_esc11[^|]*(exploited|failed)' *.md | wc -l

# Every timeline task-id is exploit_ — no lateral_/privesc_/gpo_ task has ever reached a report
rg --no-filename -o '\(task [a-z]+_' *.md | sort | uniq -c

# §7.5: the mutation guard's boundary. Expect 0 refusals through op-20260728-064041,
# then every bloodyad_set_password mention to be a refusal from op-20260728-150151 on.
for f in op-202607*.md; do
  r=$(rg -c 'ARES_ALLOW_IRREVERSIBLE_MUTATION' "$f" || echo 0)
  b=$(rg -c 'bloodyad_set_password' "$f" || echo 0)
  [ "$r$b" != "00" ] && printf '%-28s refusal=%-3s mentions=%s\n' "$f" "$r" "$b"
done

# §3.1: ESC11 is the only ADCS type with zero attempt events corpus-wide
for e in esc1 esc2 esc3 esc6 esc9 esc11 esc15; do
  printf '%-6s %s\n' "$e" "$(rg -l "adcs_${e}_[0-9]" *.md | wc -l)"
done
```

Three greps that will **not** work, and the log commands that replace them. Each corresponds to a finding a
report cannot carry, and each was got wrong at least once by grepping reports alone:

```bash
# WRONG: "zero Pwn3d! means local-admin discovery stopped" (§2.3) — the report renders 0 either way.
#   The event fires and is then dropped for want of a credential row.
grep -a 'Pwn3d! detected' /var/log/ares/orchestrator.log

# WRONG: "psexec/smbexec/responder 0 occurrences means not exercised" (rows 14, 5) — the report
#   renders LLM prose, not executions. Count tool.name= instead, and divide by ~3 lines per invocation.
grep -ao 'tool\.name="[a-z_]*"' /var/log/ares/orchestrator.log | sort | uniq -c | sort -rn

# WRONG: "the ACL drivers built no work" (§7.4) — they built it and blue deleted it (§7.6).
grep -a 'invalidated by blue containment' /var/log/ares/orchestrator.log
```

Two traps for anyone grepping this corpus:

- `mimikatz` and `impacket` appear in every report as boilerplate from a fixed Recommendations line.
  Both `rg -l -i mimikatz *.md` and `rg -l 'Deploy endpoint detection for common attack tools' *.md`
  return the same count.
- Grepping a feature name matches the ACL graph's *object* names. `LAPS` hits ~1,336 times as a GPO
  name; `Protected Users` hits ~604 times as a group object in ACE records. Neither is evidence the
  feature was reasoned about.

## Known uncertainties

- ~~Whether `laps_dump` actually reaches dispatch cannot be established from reports.~~ **Resolved for
  `laps_dump` by the `op-20260730-070442` log review: it executed 21 times** and produced nothing, which
  is §1.1's prediction (every pre-DA read authenticates as a non-reader) confirmed on execution evidence
  rather than inferred. `sid_history_enum`'s probe is still unestablished. Confirm from
  `/var/log/ares/orchestrator.log`, scoped by op-id and timestamp window.
- The same review resolved several other report-invisible questions and is worth reading before re-deriving
  any of them: `psexec` executed 16 times and `smbexec` 6 (`wmiexec` 0); `start_responder` ran once while
  every `ntlmrelayx` and `mitm6` mention in the report is LLM prose with **zero** executions behind it;
  relay work runs as `relay_and_coerce` ×21; `gmsa` and `netexec_auth_check` have zero executions; and the
  whole `auto_gpo_abuse` subsystem emitted nothing at all in that op, against three dispatches in the
  previous one. Note what the 2026-07-30 review established about that log:
  `orchestrator.log` holds only the **current** op — it is reset at deploy — so a before/after comparison
  across two ops is not available from it, while `ingest.log` (17 GB) and the per-role logs are cumulative
  and must be timestamp-scoped. The per-role logs are also the cheapest liveness signal there is: a role
  whose log mtime never advances past deploy time executed nothing, which is how §7.4 was established.
- **Which of #350–#359 caused §7.4 is unresolved and may stay that way.** Ten changes shipped in one
  deploy, and the op is a clean before/after boundary across all ten at once. Three candidate mechanisms
  are named in §7.4 and none is excluded. Any future attribution needs one-suspect-per-op or per-tick
  decline logging; do not let a plausible story about a single PR harden into a recorded cause.
- The RunAsPPL attribution in §4.2 is inferred from lsassy's target distribution, not from an observed
  error string, precisely because `is_lsassy_noise` discards it.
- AES-etype Kerberoast starvation is **suggestive, not proven**: one roastable cracked in 0 of 25
  etype-18 ops versus 42 of 53 etype-23 ops, but the other cracked in 9 of the 25, and the corpus
  cannot attribute a crack to a specific hash. `ares-tools/src/cracker.rs:61-69` records the team's own
  measurement of the effect.
- Which driver dispatched each credited ACL success is not determinable from reports — all task-ids
  render as `exploit_<uuid>`.
- Two ACL successes credited against `krbtgt` may be a `msDS-KeyCredentialLink` write or a saved-PFX
  marker rather than anything strategically meaningful; the reports do not carry the raw tool line.
- The SPN service account's password is not in either wordlist and is not reachable from any base word
  by `best64`/`d3ad0ne`. It was provably attempted — `batch_same_mode_roastable`
  (`automation/crack.rs:296-299`) put it in the same hashcat invocation that cracked the two roastable
  users. Recorded here as **the lab winning by design**, not an ares gap; do not re-file it.
