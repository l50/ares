<!-- markdownlint-disable MD013 -->

# Blue response actuators — design and implementation plan

Design doc for making blue's decisions physically effective against a live
multi-forest AD lab. Complements `docs/blue.md` (existing blue investigation
architecture), `docs/DEMO-PLAN.md` (operational plan), and
`docs/exercise-replay.md` (artifact plan).

## Scope

The CFP language commits us to blue that **takes autonomous response actions
without human intervention**: revoking credentials, isolating hosts, disrupting
attacker footholds. Today's blue triages, correlates, investigates, and emits
escalation *recommendations* — but no downstream code enforces those
recommendations against the lab.

This doc is the plan to close that gap by Aug 6.

### Non-goals

- Enterprise-grade EDR replacement. This is autonomous-response research.
- Response against real customer environments. Actions target DreadGOAD only.
- Full ATT&CK Mitigations coverage. MVP is 5 actuators; expansion is post-talk.
- Anti-tamper / anti-uninstall. Not a security-hardened blue box.

## Architecture

### Blue responder — a new deployable

Blue currently lives in K8s (orchestrator pods + Redis + Loki). It has read
paths (Loki, Prometheus, Grafana) but no write path to AD. We add a **blue
responder box** — a dedicated VM in the same range as DreadGOAD, with
authenticated access to both forests, that executes actuator tools on the
blue orchestrator's behalf.

```text
┌──────────────────────────┐         ┌──────────────────────────┐
│ Blue orchestrator (K8s)  │         │ DreadGOAD lab            │
│                          │         │  ┌──────────┐            │
│  investigation.rs        │         │  │ dc01     │  ┌────┐    │
│  callbacks.rs            │  action │  │ (sk)     │  │ca01│    │
│  ▲ ▼                     │  ──────▶│  └──────────┘  └────┘    │
│  response dispatcher     │         │  ┌──────────┐            │
│  ▲ ▼                     │         │  │ dc02     │  ┌────┐    │
└─────────┬────────────────┘         │  │ (essos)  │  │sql │    │
          │                          │  └──────────┘  └────┘    │
          │ mTLS + gRPC              │  ┌──────────┐  ┌────┐    │
          ▼                          │  │ web01    │  │ws01│    │
┌──────────────────────────┐         │  └──────────┘  └────┘    │
│ Blue responder (VM)      │         └──────────────────────────┘
│                          │                    ▲
│  responder-agent (Rust)  │  WinRM/LDAP/CA API │
│  ├─ ldap_client          │ ───────────────────┘
│  ├─ winrm_client         │
│  ├─ ca_client            │
│  ├─ audit log            │
│  └─ rate limiter         │
└──────────────────────────┘
```

**Why a separate box** (not inline in the K8s orchestrator):

- Credential isolation — the responder holds DA-equivalent credentials
  for both forests. Keeping that outside the LLM-in-loop pod reduces the
  blast radius if the orchestrator container is ever compromised.
- Network path — the K8s cluster is in AWS; DreadGOAD is in Ludus/Proxmox.
  A responder box in the DreadGOAD range removes the WAN hop from the
  hot path.
- Mirrors red — red dispatches from K8s to `kali-ares`; the responder
  is blue's `kali-ares`. Symmetric ops story.

### Provisioning

New Ansible playbook: `ansible/playbooks/blue/responder.yml`, alongside the
existing `linux/attacker_setup.yml`. Roles:

- `blue_responder_base` — Ubuntu 22.04, uv, workspace `/blue`, systemd unit
  for the responder-agent binary.
- `blue_responder_ad_client` — installs bloodyAD, impacket, certipy,
  pywinrm, ldap3, PowerShell Core (for cross-forest AD operations).
- `blue_responder_credentials` — writes `/etc/blue-responder/creds.json`
  (mode 0400, root-only), populated from 1Password at provisioning time.
  Contains: one DA-equivalent principal per forest, CA-admin cert,
  local-admin fallback for WinRM to workstations.
- `blue_responder_telemetry` — Fluent Bit shipping the audit log to Loki;
  OTel exporter for action spans to Tempo.

Deploy target for Black Hat: one blue responder per forest (2 total in
DreadGOAD), plus a smoke-test lab profile. In the demo path we run one
per forest so cross-forest containment (e.g. revoke krbtgt in both) is
parallelizable.

### Communication

Blue orchestrator ↔ responder over **mTLS gRPC**, one long-lived
connection per orchestrator pod. Protobuf:

```proto
service Responder {
  rpc Execute(ActionRequest) returns (ActionResult);
  rpc DryRun(ActionRequest) returns (DryRunResult);
  rpc Rollback(RollbackRequest) returns (ActionResult);
  rpc Status(google.protobuf.Empty) returns (ResponderStatus);
}

message ActionRequest {
  string action_id = 1;     // client-generated UUID
  string action_type = 2;   // "disable_ad_account" etc.
  map<string,string> params = 3;
  string investigation_id = 4;
  string reasoning = 5;     // LLM's justification, for audit
  bool dry_run = 6;
}

message ActionResult {
  string action_id = 1;
  enum Status { SUCCESS = 0; FAILED = 1; RATE_LIMITED = 2; BLOCKED = 3; }
  Status status = 2;
  string message = 3;
  map<string,string> observed_state = 4;   // what the action produced
  string rollback_token = 5;               // opaque handle for Rollback()
  google.protobuf.Timestamp executed_at = 6;
}
```

Orchestrator-side new module: `ares-cli/src/blue/response/` with a
`Dispatcher` that owns the gRPC channel, applies pre-flight safety
checks, and awaits the result. Callbacks in `orchestrator/blue/callbacks.rs`
call into `Dispatcher::execute` from `confirm_escalation`.

## MVP actuator set (5 tools for Aug 6)

Deliberately narrow. Each covers a distinct CFP category and each is
demoable in one dashboard row.

| # | Tool | Category | Mechanism | Rollback | Demo purpose |
|---|---|---|---|---|---|
| 1 | `disable_ad_account` | Credential revoke | LDAP `userAccountControl` flip via bloodyAD | Re-enable via LDAP | Blocks red's next tool call using that principal |
| 2 | `revoke_krbtgt` | Credential revoke | PowerShell `Reset-ADServiceAccountPassword` for krbtgt via WinRM to DC (twice, with a 10s gap) | Restore from pre-action ntds.dit snapshot | The "big red button" — invalidates all TGTs domain-wide |
| 3 | `revoke_certificate` | Foothold disruption | `certutil -revoke <serial> 4` on CA host via WinRM (reason 4 = superseded) | Un-revoke via CA console (offline restore) | Kills ADCS-based footholds (ESC1/4/8) |
| 4 | `isolate_host_firewall` | Host isolation | WinRM: `New-NetFirewallRule` — block inbound from attacker subnet, block outbound to LDAP/SMB except DCs | `Remove-NetFirewallRule -Name ares-isolate-*` | Visible on the attack graph — attacker's lateral to this node fails |
| 5 | `kill_smb_sessions` | Foothold disruption | WinRM: `Get-SmbSession \| Where-Object ClientUserName -like "*<user>*" \| Close-SmbSession` | N/A (transient state) | Immediate lateral-movement disruption |

Each tool is implemented as one Rust module under
`ares-tools/src/blue/response/` and one Python helper under
`/blue/tools/` on the responder box (invoked over the gRPC call). Python
helpers use the same red-agent stack (bloodyAD, certipy, impacket) — no
new dependency surface.

### Deliberately deferred

- Account deletion — irreversible, out of scope.
- GPO modification — high blast radius, out of scope.
- Trust modification — talk demonstrates *inside* the trust, not against it.
- Machine account manipulation beyond krbtgt — no MVP story.
- Certificate authority revocation lists distribution — the demo doesn't
  need the CRL to be widely published in real-time.

## Safety model

Every actuator runs through **five gates** before it touches the lab:

1. **Schema validation.** Params match the tool's protobuf schema; unknown
   fields rejected. Cheap, catches LLM hallucinations.
2. **Blocklist.** Hardcoded principals and targets that no autonomous action
   may touch — DC computer accounts (except krbtgt), the CA computer
   account, the responder's own principals, the DA account used by the
   red-run harness (else blue disables the red-run's own kickoff creds and
   the op ends anticlimactically). List lives in
   `config/blue-responder-blocklist.yaml` and is loaded at responder start.
3. **Rate limit.** Per-action-type token bucket. MVP limits:
   - `disable_ad_account`: 5 per 60s per forest
   - `revoke_krbtgt`: 1 per 5 min (this is the nuclear option)
   - `revoke_certificate`: 3 per 60s per CA
   - `isolate_host_firewall`: 5 per 60s
   - `kill_smb_sessions`: 10 per 60s
4. **Dry-run pre-flight.** Every action first runs as `dry_run=true`,
   which returns *what the action would do* (params validated, target
   resolvable, credentials accepted) without committing. On success,
   the orchestrator commits.
5. **Post-condition assertion.** After execution, the responder
   validates the intended state (account is disabled, session is gone,
   firewall rule exists). If the assertion fails, mark
   `Status = FAILED` and skip audit as "committed".

Rollback: every SUCCESS result includes a `rollback_token` the responder
persists (Postgres `blue_action_rollback` table). At the end of the
engagement, `ares blue rollback --investigation <id>` iterates the
rollback tokens in reverse action order and calls
`Responder::Rollback(token)` for each. Between engagements, the range
gets a full snapshot restore anyway — rollback is a defense-in-depth
convenience, not the primary reset path.

Audit: every action, SUCCESS or FAILED, writes a row to Postgres
`blue_actions` (FK: `investigation_id`) with `(action_type, target,
params, reasoning, executed_at, status, message, dry_run,
rollback_token, forest)`. This is the ground-truth log for eval and
for the scoring dashboard.

## Blue orchestrator updates

### Tool exposure

Extend the blue tool schema in `ares-cli/src/orchestrator/blue/` to
expose the 5 actuator tools as callable functions. LLM sees them
alongside the existing investigation tools (Loki queries, evidence
recording, etc.). Each tool description includes:

- What the tool does
- When to use it (the "signal" — e.g. "high-confidence credential
  compromise")
- What it *doesn't* do (e.g. "does not delete the account, only
  disables — reversible")
- Rate-limit hint
- Required parameters + validation constraints

Tool call flow: LLM decides → `callbacks.rs` receives call →
`Dispatcher::execute` → 5-gate check → gRPC to responder → result
returned to LLM → LLM sees success/failure and adapts next step.

### Prompt updates

Investigation Orchestrator system prompt gets a new section: **Response
Actions.** Load-bearing sentences:

- "You may take autonomous response actions when confidence ≥ 0.8 and
  the observed evidence supports it. State your reasoning in the
  `reasoning` field."
- "Prefer least-disruptive containment first. Disable an account before
  resetting the whole krbtgt."
- "Response actions are logged and scored. Actions that fail rate limits
  or schema validation count against you."
- "You cannot undo an action in this investigation. Rollbacks happen at
  engagement end."

Two new investigation stages after Synthesis: **Containment** (pick the
minimal set of actions that disrupt the confirmed foothold) and
**Verification** (poll for expected state; retry escalate if the
attacker adapts). Both are LLM-driven; state lives in Redis alongside
the existing stage keys.

### Confidence + threshold

Actions require the LLM to attach a `confidence` numeric field (0.0–1.0).
Threshold configurable in `config/ares.yaml` under `blue.response.confidence_threshold`,
defaulting to 0.8 for MVP. Below threshold → the tool returns
`BLOCKED` with a hint to gather more evidence first. This is a soft
guardrail — the primary safety comes from the 5 gates above.

## Adversarial-loop mechanics

The point of live actuators is that **red observes containment and adapts**.
For the demo to sell "adversarial loop, not scripted", the red side needs to
route around blue's disruptions.

### Red side — required changes

Small but important. Where red tool calls fail today, they typically log
generic errors. To adapt, red workers must classify a failure well enough
for the orchestrator to reroute.

Concretely:

- **Auth errors** (`STATUS_LOGON_FAILURE`, `KRB_AP_ERR_MODIFIED`, LDAP
  `INVALID_CREDENTIALS`) → emit a `credential_revoked` observation for
  the affected principal. Orchestrator drops queued exploits that
  depend on it and prioritizes an alternate credential in the queue.
- **Kerberos-domain-wide failures** (all TGTs failing across the forest
  in a short window) → emit a `krbtgt_rotated` observation. Trigger
  re-recon from scratch (this is expensive; blue winning here is a real
  win).
- **Network unreachable** (SMB, WinRM, LDAP all fail to a specific
  host) → emit a `host_isolated` observation for the target.
  Orchestrator marks the host as unreachable for the remainder of the
  op and reprioritizes lateral targets.
- **Certificate rejected during PKINIT** (`KDC_ERR_CLIENT_REVOKED`) →
  emit a `certificate_revoked` observation. Orchestrator drops queued
  ADCS-based exploits using that cert and considers re-enrollment via
  an alternate template.

New observation types map to existing patterns in `ares-core/src/red/state/observations.rs`
(structure exists; add variants). The queue-selection code
(`ares-cli/src/orchestrator/exploitation.rs`,
`ares-cli/src/orchestrator/deferred.rs`) already handles removing
queue entries when a precondition observation appears — we're
adding new precondition-invalidating observations, not new queue
logic.

### Emergent behavior — worth demoing

- Blue disables `svc_mssql` → red's next MSSQL impersonation call fails
  → red switches to an ACL-based path from the same host.
- Blue isolates `web01` → red drops web01 from lateral targets → picks
  `sql01` next.
- Blue revokes krbtgt after red has DA → red's cached TGTs die → red
  has to re-authenticate from a foothold that may itself have been
  disabled → **race condition** where fastest-to-persist wins. This
  is the arc's climax; instrument it well.

The talk's "attackers adapt after detections" line is only true if the
new observation types are wired. Without them, red keeps retrying the
same failed call. This is 2–3 days of focused work in the red side; it
is on the critical path.

## Scoring — bidirectional

Existing blue scoring stays. Add:

**Red-side outcome tracking** (already partially in `red-state.json`):

- Techniques attempted, successful, failed.
- DA achieved (per domain), time-to-first-DA.
- Actions blocked by blue (new — counts red-side observations of
  containment).
- Adaptation events (new — count of queue reprioritizations triggered
  by blue-caused failures).

**Adversarial composite score:**

- `blue_prevention_rate` = actions_blocked / (actions_attempted_post_first_alert)
- `blue_time_to_contain` = median duration from first successful red
  exploit to blue containment of that foothold
- `red_persistence_score` = # of foothold changes red made after
  containment / total containments (higher = red adapted well)
- `winner_signal` — the demo dashboard's Winner panel already has
  IN PROGRESS / RED LEAD / BLUE DEFENDING states. Compute from:
  - RED LEAD when red has active DA + last blue containment > 30s ago
  - BLUE DEFENDING when blue containment count > red foothold count
    AND blue containment fresher than red DA
  - IN PROGRESS otherwise

Prometheus counters exported by the blue orchestrator (and matching
recording rules for the composites):
`blue_actions_dispatched_total{action_type,status}`,
`blue_actions_dispatched_duration_seconds{action_type}`,
`blue_containment_time_seconds{investigation_id}`,
`red_adaptations_total{trigger}`,
`red_footholds_active`,
`winner_state{value="in_progress|red_lead|blue_defending"}`.

## Implementation timeline (Aug 6 target — 26 days)

Aggressive but reachable if scope stays at the MVP.

| Week of | Milestone |
|---|---|
| Jul 14 | Responder VM provisioning (Ansible role + role tests). LDAP + WinRM clients working end-to-end against a smoke-test DreadGOAD range. |
| Jul 14 | Red observation types wired (`credential_revoked`, `host_isolated`, `krbtgt_rotated`, `certificate_revoked`) + queue-invalidation logic. |
| Jul 21 | Actuators 1–3 implemented (`disable_ad_account`, `revoke_krbtgt`, `revoke_certificate`) with dry-run and rollback. Integration tests hitting the smoke-test range. |
| Jul 21 | gRPC dispatcher in ares-cli. Orchestrator → responder path proven end-to-end with actuator #1. |
| Jul 28 | Actuators 4–5 (`isolate_host_firewall`, `kill_smb_sessions`). All 5 actuator prompt descriptions written and A/B'd for LLM decision quality. |
| Jul 28 | Prometheus counters + recording rules exported. Demo dashboard's Simulated Response Actions panel reads real data. |
| Aug 3 | First full arc rehearsal on the DreadGOAD range with live blue actuators. Time every beat. |
| Aug 4–5 | Rehearsal iteration. Freeze responder image, dashboard, prompts. |
| Aug 6 | Ship. |

Risks that would force a scope cut:

- WinRM auth flake on cross-forest calls — mitigation: pin the
  responder to same-forest DA principals, cross-forest actions go
  through the responder in the target forest.
- Red observation-type wiring takes longer than 3 days — mitigation:
  ship with only `credential_revoked` and `host_isolated`; drop
  `revoke_krbtgt` and `revoke_certificate` from the demo arc if their
  observation types aren't done.
- Rehearsal reveals the LLM is over- or under-confident in
  containment — mitigation: adjust the confidence threshold in
  `config/ares.yaml`. Left as an operator knob, not a code change.

Reject on principle: shipping any actuator without dry-run + rollback +
audit + blocklist all in place. Better to demo four actuators well than
five sloppily.

## What this replaces in the demo plan

`DEMO-PLAN.md` currently frames blue as Option C (simulated response
actions, `dry_run=true` spans). This plan moves us to **Option A**
(real actuators). The demo-plan arc, "Simulated Response Actions"
panel narration, and open-work list all need updates — tracked in
DEMO-PLAN.md commit that lands with this doc.

## Open decisions

1. **Confidence threshold.** 0.8 is a defensible starting number; expect
   to tune to 0.7 or 0.85 after the first rehearsal. Ask: are we
   comfortable if the demo shows blue *declining* to act on a real
   alert because confidence was 0.79?
2. **Cross-forest containment.** MVP is one responder per forest;
   cross-forest actions happen twice. Alternative: one responder with
   trust-crossing DA. Simpler infra, higher blast radius on
   compromise. Recommend MVP (per-forest) for the demo.
3. **Should blue see red's live actions?** Today blue only sees
   telemetry (Loki, Prom, Grafana). Giving blue access to
   `red-state.json` breaks the "bottom-up ground truth" thesis —
   blue would be reading the answer key. Recommend explicitly: no,
   blue only sees telemetry. Preserve the thesis.
4. **What if blue disables the red-run kickoff account by mistake?**
   Blocklist protects this, but only if the kickoff account is in
   the list. Draft a `demo/blocklist.yaml` per-lab template.
5. **Post-talk open-source path.** These actuators are useful
   research artifacts. Ship in the same ares repo, or in a new
   `blue-responder` repo? Recommend same repo — the value is the
   integration with the eval framework, not the tools in isolation.
