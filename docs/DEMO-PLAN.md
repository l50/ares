<!-- markdownlint-disable MD013 -->

# Demo Plan — Catch Me If You Can (Black Hat USA 2026)

Operational plan for the live demo section of the "Catch Me If You Can: AI
Investigators Hunting Autonomous Attackers as a Benchmark" briefing —
Thursday, August 6, 12:00–12:40 pm, Jasmine A. Owner: Jayson Grace.

This is the operational playbook — not the deck outline. It covers **what runs,
what the audience sees, what breaks, and how we recover.**

---

## TL;DR — Recommendation

**Warm-replay primary, live standby, video ultimate fallback.**

- **Primary path: `ares benchmark run --clock-mode wallclock` against a pre-captured hero snapshot.** Same Grafana + Tempo + Loki stack as production, same trace spans, same alert firings — anchored to a captured op so timing, outcome, and kill-chain shape are deterministic. Looks and feels live because the observability path *is* the live path; only the log stream is canned.
- **Standby: live Ares stack against a warmed DreadGOAD range**, ready to run in Q&A or as a "prove it's real" moment after the scored replay finishes.
- **Fallback: pre-recorded 4K screen capture with speaker VO track**, cued to auto-play if the replay stack fails a pre-flight probe.

Rationale: the recent hero run (`op-20260705-101128`) hit first Domain Admin at 6:40 — inside the 8-minute demo budget, but with meaningful run-to-run variance and a real (~5%) failure tail. On show-floor Wi-Fi, a live-only demo is a coin flip against 40 minutes of speaker credibility. The replay path uses production-parity code — it *is* the system, just with a known-good input tape — so we do not sacrifice authenticity for reliability.

**Live standby is not decorative here.** The blue actuators (see below) require a live lab to actually revoke credentials and isolate hosts. The primary path is replay, but the standby path — a warmed DreadGOAD with the responder VMs live — is where we go for Q&A moments where someone asks "does this really work?" or if the replay path fails preflight. Both paths are first-class and must be rehearsed.

The `benchmark-replay-timeline-spec.md` clock state machine has `wallclock` mode explicitly earmarked "for real-time demos, not scoring." This plan is what that mode was built for.

### Blue: we are building real actuators (Option A)

The CFP language commits us to blue that **takes autonomous response actions**
against the live AD lab — revoking credentials, isolating hosts, disrupting
attacker footholds. Today's blue emits escalation *recommendations* only; no
downstream code enforces them. We're closing that gap.

Design + implementation plan: `docs/blue-response-actuators.md`.

Summary of what that plan commits us to:

- **Blue responder VM** — one per forest inside DreadGOAD, holds DA-equivalent
  credentials, exposes a mTLS gRPC service that the K8s orchestrator dispatches
  actions to. Provisioned via new `ansible/playbooks/blue/responder.yml`.
- **5-actuator MVP:** `disable_ad_account`, `revoke_krbtgt`, `revoke_certificate`,
  `isolate_host_firewall`, `kill_smb_sessions`. One per CFP category, minimum
  breadth for the arc to breathe.
- **5-gate safety pipeline:** schema validation → blocklist → rate limits →
  dry-run pre-flight → post-condition assertion. Every action audited in
  Postgres with rollback tokens.
- **Red-side observation types** so red *sees* containment happen and
  reroutes: `credential_revoked`, `host_isolated`, `krbtgt_rotated`,
  `certificate_revoked`. Without these, the "attackers adapt after
  detections" claim in the CFP is false and the demo becomes a scripted
  playback.
- **Bidirectional scoring** — the demo dashboard's existing Winner panel
  (IN PROGRESS / RED LEAD / BLUE DEFENDING) is driven by real
  `blue_prevention_rate`, `blue_time_to_contain`, `red_persistence_score`,
  etc.

**Timeline is tight but reachable.** 26 days to Aug 6 with focused scope.
`blue-response-actuators.md` breaks it down week by week. The primary risks
are the red-side observation-type wiring (2–3 days, on the critical path)
and cross-forest WinRM auth stability (rehearsal will surface).

Options B and C are still on the table if execution slips:

- **B. Reframe blue** as "autonomous triage + escalation". Cut the
  containment beats from the arc entirely. Truthful but a smaller demo.
- **C. Ship 2 actuators well, simulate the other 3.** Hybrid — the arc
  runs with two real containment events (e.g. account disable + host
  isolate) plus simulated spans for krbtgt/cert/session actions. Honest
  narration required ("this action is on-lab; this one is a simulated
  decision").

Order of preference: A → C → B. Decide by T-1 week (Jul 30). Anything
below A after that date locks us into the smaller-demo story.

---

## What the audience sees

**One 4K display. One browser window. One Grafana dashboard.** No terminals, no k9s, no `kubectl logs` tail. If a viewer glances at the screen for 3 seconds, they should understand the frame.

### Dashboard layout (single pane)

```text
┌────────────────────────────────────────────────────────────────────────┐
│  CATCH ME IF YOU CAN — LIVE                          T+03:12  RUN #4   │
├───────────────────────────────────┬────────────────────────────────────┤
│                                   │                                    │
│      ATTACK GRAPH (Tempo)         │      DEFENDER TIMELINE (Loki)      │
│                                   │                                    │
│    [initial access]               │   12:03:47  ALERT  T1078.002       │
│         │                         │             │                      │
│         ▼                         │             ▼ TRIAGE               │
│    [cred access]                  │   12:03:59  Blue: correlate 4624   │
│         │                         │                                    │
│         ▼                         │   12:04:14  CAUSATION  T1550       │
│    [lateral: forest A]  ●NEW      │             │                      │
│         │                         │             ▼ LATERAL              │
│         ▼                         │   12:04:31  Blue: revoke session   │
│    [priv esc: ESC1]  ●NEW         │                                    │
│         │                         │   12:04:52  Blue: isolate host     │
│         ▼                         │                                    │
│    [cross-forest: ESC5]           │                                    │
│                                   │                                    │
├───────────────────────────────────┴────────────────────────────────────┤
│  SCORE (running)                                                       │
│   Detection:      6 / 9 IOCs        MITRE Coverage:    18 / 24 TTPs    │
│   Time-to-Alert:  11.4 s (median)   Time-to-Contain:   47.1 s (med)    │
│   Investigation:  0.71 (35% det + 30% qual + 35% completeness)         │
└────────────────────────────────────────────────────────────────────────┘
```

Nothing else. No log wall, no code, no JSON. If a panel isn't landing an idea the audience can hold onto in one glance, cut it before rehearsal, not during.

### The three visual moves that have to land

1. **Attack graph grows in real time as red succeeds.** New nodes flash on the LEFT with a technique tag. This is the "adversary is deciding, right now" moment.
2. **Defender timeline scrolls in real time on the RIGHT.** Each row is an ATT&CK-tagged span. When a blue action fires (revoke, isolate, disrupt), it renders as a bold row.
3. **The scoreboard at the bottom updates continuously.** Detection rate ticks up when blue catches something; time-to-contain updates on each response. The audience internalizes that both sides are *being measured* — this is the whole thesis in one strip.

### Naming for the stage

DreadGOAD keeps GOAD's `essos.local` / `sevenkingdoms.local` naming. **Do not** rename for the demo. Two reasons: the Windows AD community reads these as "we ran against a real, known-hard lab, not a toy," and re-labeling breaks reproducibility for the audience members who go download the tools after. Call it out in the framing slide ("If you've built lab AD before, this is GOAD's DreadGOAD fork — same names you already know").

---

## Demo arc — 8 minutes, beat by beat

Assume section 3 of the deck (Demo, 8 min). Timing is generous — leaves 60s slack for a live audience laugh line at "first DA in six minutes."

| T+ | Beat | On screen | Speaker |
|---|---|---|---|
| 0:00 | **Frame** | Static: two boxes labelled "Attacker (Ares Red)" and "Defender (Ares Blue)". Dashboard blank. | "Here's the setup. Same lab as the paper. Nothing pre-planned — the attacker decides what to do next. The defender doesn't know what's coming." |
| 0:20 | **Kick off** | Click "Start" in Grafana annotation (this actually flips `replay_now` off "paused" and starts wallclock advance). | "Attacker is dropped in with one low-priv credential. Blue starts watching Loki. Clock's on them both." |
| 0:35 | **First recon spans** | Attack graph shows Recon node. Defender timeline scrolls Sysmon events. No alert yet. | "Recon's happening. Blue can see the noise but no rule's fired yet — this is the false-negative window every SOC lives in." |
| 1:10 | **First alert** | Red row appears on defender side: `T1078.002 - Valid Accounts`. Blue triage span starts. | "There's the first alert. Blue's Triage agent picks it up — you'll see it correlate the 4624 to the recon window." |
| 2:00 | **Attacker succeeds cred access** | New node on attack graph: Cred Access. Simultaneously, Blue's Causation stage lights up. | "Red got a hash. Blue's now in Causation — trying to figure out *why* the alert fired, not just *that* it fired." |
| 3:00 | **Blue disables the compromised account** | Bold row: `Blue: disable_ad_account svc_mssql (SUCCESS)`. Attack graph: red's queued MSSQL impersonation greys out — precondition `credential_revoked` fired. | "Blue just disabled svc_mssql on the lab. Watch — the attacker's next impersonation attempt fails on `STATUS_LOGON_FAILURE`, and the orchestrator drops every queued path that depended on that account." |
| 3:30 | **Attacker adapts** | Attack graph: new branch off Cred Access, alternate path selected. `red_adaptations_total` ticks up on the scoreboard. | "This is where scripted red-team demos die. Red's orchestrator saw the credential revocation as a new observation, reprioritized, and picked a different path from the queue. No human in the loop." |
| 4:30 | **Cross-forest pivot** | New node: `ESC5 - Golden Certificate`. Attack graph now visibly spans two forest columns. | "Now we're crossing forests. Same attacker, no human. The blue side sees a certificate-issuance event — new alert coming." |
| 5:15 | **DA hit** | Big node flashes: `Domain Admin — child.essos.local`. Scoreboard updates: "First DA T+5:15". | "First Domain Admin. Blue caught 6 of 9 IOCs on the way. Watch what it does next." |
| 5:45 | **Blue containment burst** | Sequence of real action spans: `isolate_host_firewall dc02.essos.local`, `revoke_krbtgt essos.local`, `revoke_certificate <serial>`. Attack graph shows red's next 3–4 queue entries invalidate as the observations propagate. Scoreboard's Winner panel flips to **BLUE DEFENDING**. | "Isolate, revoke, invalidate. The lab is actually rejecting the attacker now. Blue's tickets are dead, its certs are revoked, its target is unreachable. Watch what red does with 15 seconds left on the clock." |
| 6:30 | **Freeze frame + score** | Pause replay, foreground the scoreboard. | "Final scoreboard. This is what the paper's benchmark actually produces. Every run generates a number like this — comparable, reproducible, adversary-authored." |
| 7:30 | **Bridge back** | Return to slide. | Transition to Results section. |

Rehearse to hit 7:30 with no rushing. If any beat slips 15+ seconds in rehearsal, cut it — do not compress narration.

---

## Why replay (not live)

The talk's honesty depends on the replay being **operationally equivalent** to a live run, not a shortcut. Concretely:

| Concern | Live | Replay (`wallclock` mode) |
|---|---|---|
| Grafana dashboards | Real | Real (same instance) |
| Tempo trace spans | Real, emitted by orchestrator | Real, emitted by orchestrator during original capture |
| Loki logs | Real Windows/Sysmon | Real Windows/Sysmon, replayed from snapshot |
| Alert firings | Real Grafana alert rules | Real (rules fire on the replayed streams) |
| Blue investigation | Real | Real — investigation orchestrator runs live against the replay stack |
| Blue autonomous actions | Real (blue responder VM dispatches over gRPC; effects hit AD) | Real (captured actions replay from the audit log; captured Loki telemetry shows their downstream effects) |
| Timing | Variable, subject to LLM latency | Deterministic wall-clock re-anchoring |
| Outcome | ~95% DA success, first-DA time varies 4–15 min | Fixed to captured op |

With Option A (real actuators — see below), the primary asymmetry between replay and live is **not** the response layer — it's the *observability path* of the response. When we replay, blue's decision spans and Postgres audit rows are captured; the actuator gRPC calls were real *during the captured op* and their effects show up in the Loki telemetry we replay. The audience sees the same containment beats they would see live, because those beats *actually happened once* against the real lab.

If a Q&A asks "did that actually revoke a session, or is this replay?" — the answer is "the captured op was live against DreadGOAD; blue actuators fired on the lab and this is a faithful replay of that run. If you want, I can run it live during Q&A — it takes about 8 minutes." That's a strong answer, not a hedge.

---

## Infrastructure

### On-stage laptop

- Two USB-C displays: HDMI to venue projector for Grafana; laptop screen for speaker view (slides + a quiet terminal).
- **Everything runs locally.** No dependency on venue Wi-Fi for the demo path.
- Local K8s (kind/k3d) with the ephemeral replay stack: Grafana, Tempo, Loki, mock alert receivers, `ares blue orchestrator` pod.
- `ares benchmark run --stack-ip 127.0.0.1 --clock-mode wallclock --snapshot-id op-<hero>` as the driver command, pre-typed in a tmux pane hidden behind slides.
- Snapshot bundle copied to `~/demo/snapshots/` — no S3 dependency during show.
- Anthropic API key pre-loaded (fallback: warm the LLM cache with a dry-run 24h prior so most tool-plan prompt prefixes are already cached and blue-side latency drops).

### Hero snapshot selection

Criteria for the primary demo snapshot:

1. First DA between 5:00 and 6:30 (fits the arc, sells the sub-6 number).
2. Blue investigation hit ≥ 5 of the 9 canonical IOCs (score narrative works).
3. Both forests touched (needed for the cross-forest visual).
4. At least one *failed* attacker move followed by a successful adapt (sells "not scripted").
5. Golden Ticket persistence at the tail (locks the ATT&CK progression story).

Candidate: `op-20260705-101128` (6:40 to first DA, child domain). Verify criteria 2–5 with `ares benchmark inspect op-20260705-101128` before locking. Capture a **second** snapshot as backup with a different chain shape (e.g. essos DA via ESC5 per `playbook-essos-da-esc5.md`) so the standby run doesn't tell the same story.

### Range (for standby + rehearsal)

DreadGOAD in the Ludus DG range — canonical 2-forest, 3-domain topology. Warm the range 24h before travel; verify with `task red:multi TARGET=dreadgoad` smoke and `docs/goad-checklist.md` clock-skew fix (attacker-as-NTP) applied. If any DC drifts >2 min from attacker, cross-realm Kerberos silently degrades and the demo timing will slip.

---

## Instrumentation — what makes it look right

**Correction to an earlier version of this doc:** the dashboards and the custom panel already exist. They live in the dreadops repo, not in ares. Concretely:

- **Dashboards (as ConfigMaps):** `~/dreadnode/dreadops/apps/argonaut/environments/dev/infrastructure/observability/grafana/dashboards/`
  - `attack-demo-live-dashboard.yaml` — **"Live Demo - Red vs Blue"** (702 lines, uid `attack-demo-live`). Templated on `$environment` (dev/staging) and `$operation_id` (auto-populated from `traces_spanmetrics_calls_total`). This is the demo dashboard. Do not build a new one.
  - `attack-graph-dashboard.yaml`, `attack-simulation-overview-dashboard.yaml`, `attack-target-network-dashboard.yaml`, `attack-operation-summary-dashboard.yaml`, `blue-team-detection-dashboard.yaml`, `red-team-agent-logs-dashboard.yaml` — supporting drill-downs linked from the demo dashboard header.
- **Custom Grafana panel plugin:** `~/dreadnode/dreadops/apps/argonaut/plugins/dreadnode-attackgraph-panel/` — TypeScript + Cytoscape.js. Reads Tempo TraceQL directly. Node shapes/colors by target type (DC diamond/red, server rectangle/yellow, workstation ellipse/green, agent hexagon/blue, user triangle/purple); edge colors by MITRE tactic. Filters by tactic + technique. Includes `ReplayControls.tsx` + `useReplayState.ts` (playback), `TimelineView.tsx`, `TacticProgressBar.tsx`, `ipHostnameResolver.ts`. This is a substantial existing artifact — treat as ready and iterate on rough edges only.

What the "Live Demo - Red vs Blue" dashboard already renders (from the on-disk panel list):

1. **Header row:** Operation ID, Duration, Current Phase, Red Operations count, Blue Investigations count, **Winner** (mapped: IN PROGRESS / RED LEAD / BLUE DEFENDING).
2. **Attack Visualization row:** the custom `dreadnode-attackgraph-panel` reading Tempo, filtered by `attack_operation_id`.
3. **RED vs BLUE Activity row:** Kill Chain Progress bargauge, Milestones Achieved stat, Techniques Used piechart.
4. **Detection Timeline** (timeseries).
5. **Simulated Response Actions** (table) — the dashboard *already* frames blue actions as "simulated" (regex-mapped to Threat Hunting, Network Isolation Check, Alert Acknowledged, Credential Scan). This aligns with Option C exactly — the dashboard side of that decision is done.

### ATT&CK-tagged spans on the ares side (already emitted — good)

`ares-core/src/telemetry/mitre.rs` maps 100+ tools → technique IDs and role → tactic. `ares-core/src/telemetry/spans/builder.rs` emits them as `attack.technique`, `attack.tactic`, `attack.phase` attributes on every worker action. Blue-team spans are tagged too.

**The panel plugin expects some specific attribute names** (per its README):

- Required: `destination.address`, `traceID`
- Recommended: `mitre.tactic`, `mitre.technique.id`, `attack_target_type`, `attack_target_domain`, `tool.name`

**Verify before rehearsal:** run the panel's example TraceQL on the hero snapshot:

```traceql
{ resource.service.namespace = "attack-simulation"
  && span.mitre_tactic = "lateral-movement"
  && span.destination_address != "" }
```

If ares emits `attack.technique` but the panel reads `mitre.technique.id`, align them at the ares source (`mitre.rs` / `spans/builder.rs`) so both this demo dashboard and the panel's TraceQL queries render immediately. Do not paper over in the dashboard.

### What still needs building on the ares side

1. **Blue decision spans that populate the Simulated Response Actions table.** The dashboard already has the table; the source spans must exist for it to fill. Extending `escalate_investigation` / `confirm_escalation` / `downgrade_escalation` in `ares-cli/src/orchestrator/blue/callbacks.rs` to emit spans with a `simulated_response.action_type` attribute (or whatever attribute the table's query expects — check the dashboard JSON before implementing).
2. **Prometheus counters** the header/timeline panels read. The dashboard's stat panels query metrics like `attack_operation_active`, `attack_kill_chain_progress`, `attack_milestones_reached`, and similar. Verify each metric name against the dashboard JSON before assuming it's exported. Anything missing → wire from the existing scorer (`ares-core/src/eval/scorers/scoring.rs`) as a counter.

The dashboard is the source of truth for what attributes and metrics ares must emit. Read `attack-demo-live-dashboard.yaml` panel by panel, list every attribute/metric it references, then grep the ares codebase for each. Gaps are the work list.

---

## Failure modes and mitigations

Rank ordered by "how likely is this to bite on stage":

| Failure | Signal | Mitigation |
|---|---|---|
| Venue Wi-Fi flaky | Grafana can't reach S3 for panel plugins | Everything served from local disk; snapshot bundle local; no plugin fetch at runtime. Pre-flight check: `curl -s localhost:3000/api/health && cat /var/log/grafana/plugin.log \| tail`. |
| Laptop LLM API key rate-limited (Anthropic) | Blue investigation stalls on 429 | Pre-warm cache 24h prior. Fallback key on a different org. Set `ARES_LLM_PREFLIGHT_SKIP=1` for the demo path (per memory). |
| Blue investigation takes longer than the arc allows | Scoreboard freezes mid-demo | `wallclock` mode advances regardless; investigation is best-effort. Rehearse with the *median* investigation timing, not the p50 — cap step budget at the tighter end. |
| Snapshot doesn't render the "adapt after failure" node | Missing narrative beat | Pre-verify the hero snapshot has ≥1 failed → succeeded transition (criterion 4 above). If missing, pick a different snapshot. |
| Speaker laptop crashes | Total demo failure | Backup laptop (Martin's) running the same stack, mirrored via display switch. Rehearsal at least once from the backup. |
| Everything above fails | Nothing on screen | Auto-fall-through to pre-recorded 4K MP4 + speaker VO. Cued from slide 3 of demo section. Tell the audience — "the video is the same run you would have seen, we lost the stack" beats trying to fake it. |

### Pre-flight probe

A single script — `demo/preflight.sh` — that runs 15 minutes before the session and blocks green-light unless all pass:

1. K8s cluster healthy (`kubectl -n replay get pods`).
2. Grafana serves 200 on `/api/health`.
3. Loki has snapshot streams ingested (`logcli query 'count_over_time({op="op-<hero>"}[1h])'` returns > 0).
4. Tempo has spans for the same op.
5. Blue orchestrator pod ready + connected to LLM (`kubectl logs` shows a successful test completion).
6. Alert rule count matches expected (all rules loaded from ConfigMap, not stale).
7. Timeline clock is at `paused` (not mid-advance from a rehearsal).

If any step fails, `preflight.sh` exits non-zero and prints the exact fix. Rehearsal cadence catches any that flake.

---

## Rehearsal timeline

| Date | Task | Owner |
|---|---|---|
| **T-4 weeks (July 9)** | Lock hero snapshot. Freeze dashboard JSON. | Jayson |
| **T-3 weeks (July 16)** | First full-arc rehearsal on production hardware. Video capture. | Jayson + Martin |
| **T-2 weeks (July 23)** | Second full rehearsal. Time every beat. Iterate script. | Jayson + Martin + Shane |
| **T-1 week (July 30)** | Full rehearsal on the exact travel laptop. Backup laptop rehearsal. | Jayson + Martin |
| **T-3 days (Aug 3)** | Freeze the demo image (dashboard JSON + snapshot bundle + preflight script + video). | Jayson |
| **T-2 days (Aug 4)** | Travel. Verify laptops boot demo cold at hotel. Screen-cap fallback video final render. | Jayson + Martin |
| **T-1 day (Aug 5)** | Speaker room dry run. On projector. In room dimensions. | Jayson + Martin |
| **T-0 (Aug 6, 11:00)** | Preflight probe. Green-light or fall back to video. | Jayson |
| **T-0 (Aug 6, 12:00)** | Ship it. | — |

Everything after T-3 days is **frozen**. No dashboard edits, no snapshot swaps, no script tweaks. The demo is a released artifact from that point.

---

## Beyond the demo — exercises as first-class artifacts

The demo is one instance of a broader idea: **serialize any completed op into a
versioned, replayable "exercise"** that anyone can pull and re-run to reproduce
the same engagement. Six replay modes (visual/blue-eval/red-eval/head-to-head/
checkpoint-fork/counterfactual), OCI-style distribution, signed artifacts, a
public catalog.

Design lives in `docs/exercise-replay.md`. Only two of its phases are on the
critical path for Aug 6:

- **Phase 1 (Tempo trace capture + replay)** — blocking. The current
  snapshot manifest (`ares-cli/src/benchmark/manifest.rs`) captures Loki,
  metrics, alerts, dashboards, annotations, red state — but not Tempo
  traces. The demo dashboard's Cytoscape attack-graph panel is
  Tempo-driven, so pure-visual replay needs the traces in the bundle.
- **Phase 3 (`--mode visual`)** — becomes the demo primary path. `ares
  exercise run <id> --mode visual` — no agents, no LLM calls, no lab; just
  stream captured telemetry into ephemeral Loki + Tempo at wall-clock
  timings. This is what "the demo runs" means, formalized.

Phase 2 (manifest v2 + `ares exercise` CLI) and Phase 4 (public catalog) are
nice-to-haves for Aug 6 — if they land, the hero snapshot ships as a signed
public exercise the day of the talk. If not, the exercise concept goes in the
deck as "here's what we're releasing next" and the pieces land in the following
month.

## Post-talk artifacts

The audience wants to download this the moment it ends. Ready at go-time:

- **The hero snapshot bundle** on `github.com/dreadnode/ares-demos` — `snapshot-blackhat-2026.tar.gz` with instructions to `ares benchmark run` locally.
- **A pointer to the live demo dashboard** — the actual JSON lives in `dreadops/apps/argonaut/environments/dev/infrastructure/observability/grafana/dashboards/attack-demo-live-dashboard.yaml`. Publish a rendered PNG plus the source path, or export the dashboard from Grafana as a `.json` and drop it in `ares-demos/dashboards/` for offline import.
- **The preflight script** so anyone can validate their own replay stack.
- A short (2-min) screen-cap of the demo on the talk landing page so people who missed the room see it.
- A `demo/README.md` that documents the arc, the snapshot criteria, and how to run the same replay against a fresh Ares checkout.

QR code on the takeaways slide points at the repo.

---

## Open work / gaps to close

Grouped by workstream. Everything below is on the critical path unless
marked otherwise. Timeline detail lives in each linked design doc.

### A. Blue actuators (`docs/blue-response-actuators.md`)

The biggest workstream. Ordered:

1. **Responder VM provisioning.** `ansible/playbooks/blue/responder.yml`,
   4 roles, credentials from 1Password. Verified with molecule against a
   smoke-test range. Owner: Jayson. ETA: week of Jul 14.
2. **gRPC responder-agent binary.** New Rust binary in `ares-tools/src/blue/response/`.
   mTLS, 5 gates (schema/blocklist/rate limit/dry-run/post-condition),
   Postgres audit + rollback. Owner: Jayson. ETA: week of Jul 14.
3. **Actuators 1–3** (`disable_ad_account`, `revoke_krbtgt`, `revoke_certificate`).
   Rust module per action, Python helper on responder. Integration tests
   on smoke-test range. Owner: Jayson. ETA: week of Jul 21.
4. **Dispatcher + orchestrator wiring.** `ares-cli/src/blue/response/`
   Dispatcher; `callbacks.rs` calls into it from `confirm_escalation`.
   Owner: Jayson. ETA: week of Jul 21.
5. **Actuators 4–5** (`isolate_host_firewall`, `kill_smb_sessions`).
   Owner: Jayson. ETA: week of Jul 28.
6. **Blue prompt updates** — new Containment + Verification stages;
   confidence threshold; response-tool descriptions. A/B tuned against
   rehearsal ops. Owner: Jayson + Martin. ETA: week of Jul 28.

### B. Red-side observation types (`docs/blue-response-actuators.md#red-side—required-changes`)

Without this, red does not adapt to containment and the CFP language is
false.

1. **New observation variants** — `credential_revoked`, `host_isolated`,
   `krbtgt_rotated`, `certificate_revoked` in
   `ares-core/src/red/state/observations.rs`. Owner: Jayson. ETA: week of Jul 14.
2. **Failure-classification wiring** — auth errors, network errors,
   Kerberos errors, PKINIT rejections map to the new observations.
   Sites: relevant red workers under `ares-tools/src/red/`. Owner:
   Jayson. ETA: week of Jul 14.
3. **Queue-invalidation on observation.** Verify
   `ares-cli/src/orchestrator/{exploitation,deferred}.rs` already
   drops queue entries whose preconditions are invalidated; extend if
   not. Owner: Jayson. ETA: week of Jul 21.

### C. Dashboard alignment (`docs/DEMO-PLAN.md#instrumentation`)

Existing dashboards are the source of truth for what ares must emit.

1. ~~**Attribute + metric audit** of `attack-demo-live-dashboard.yaml`.
   Every span attribute + Prometheus metric it queries; cross-ref
   ares source.~~ **Landed in #195.**
2. ~~**Attribute alignment** — rename `attack.technique` etc. in
   `ares-core/src/telemetry/mitre.rs` + `spans/builder.rs` to match
   what the Cytoscape panel expects (`mitre.technique.id`,
   `destination.address`, `attack_target_type`, etc.).~~ **Landed in #195** (`otel.status_code` sentinel on span builder — pipeline verification still pending).
3. **Prometheus counter exports** — from blue orchestrator, wire
   scorer output + new actuator counters
   (`blue_actions_dispatched_total`, `blue_containment_time_seconds`,
   `red_adaptations_total`, `winner_state`). Recording rules for
   composites. Owner: Martin. ETA: week of Jul 28.

### D. Exercise replay (`docs/exercise-replay.md`)

Blocking for the demo primary path.

1. ~~**Tempo trace capture + replay** (Phase 1 of exercise-replay).
   Extend `SnapshotManifest`; pull traces during `ares benchmark
   capture`; push into ephemeral Tempo during replay.~~ **Landed in #196** (end-to-end smoke pending).
2. **`--mode visual`** (Phase 3 of exercise-replay). Streams captured
   telemetry into ephemeral stack with no blue orchestrator running.
   Owner: Jayson. ETA: 2 days, week of Jul 21.

### E. Demo-day glue

1. ~~**`demo/preflight.sh`** — ~100 lines, checks pods + panels + snapshot
   + attribute presence.~~ **Landed in #197.**
2. **Fallback video** — 8-min rehearsal capture, edited, VO. Owner:
   Jayson. ETA: T-1 week.
3. **Hero snapshot re-capture** — after A + B + C land, capture a
   fresh op with actuators firing and observations populated. Owner:
   Jayson. ETA: week of Aug 3.
4. **Blocklist for the demo range** — `demo/blocklist.yaml` per
   `blue-response-actuators.md#4`. Owner: Jayson. ETA: with actuator #1.

### Explicitly out of scope

- **Enterprise-grade EDR replacement.** Actuators run against DreadGOAD
  only. Not a security-hardened product.
- **Live red+blue-together streaming CLI.** The Grafana "Live Demo - Red
  vs Blue" dashboard *is* the streaming view.
- **Building a new demo dashboard.** Iterate on the existing
  `attack-demo-live-dashboard.yaml`; do not fork.
- **Trust modification, GPO changes, account deletion.** Excluded from
  the actuator MVP by policy — blast radius too high, out of scope.
- **Anti-tamper for the responder VM.** Not a hardened target.

### What if we slip

Fallback ladder (see Blue: we are building real actuators note above):

- **T-1 week (Jul 30) go/no-go on Option A.** If actuators + observation
  types aren't stable end-to-end by then, drop to Option C: 2 actuators
  demonstrated on-lab (`disable_ad_account`, `isolate_host_firewall`)
  plus 3 simulated action spans for the demo arc. Honest narration.
- **T-3 days (Aug 3) go/no-go on live standby.** If the responder VM is
  flaky in rehearsal, replay-only for the demo; no live Q&A run.
- **T-0 preflight fails.** Fallback video.

---

## Decisions still open (bring to Jayson)

1. **Confirm Option A commit.** Real actuators means 26 days of focused
   work on the plan in `blue-response-actuators.md`. Confirm scope, owner
   assignments (Jayson lead, Martin on prompts + Prom exports),
   and T-1-week go/no-go for the fallback ladder.
2. **Confidence threshold for actuator dispatch.** Design doc defaults to
   0.8 in `config/ares.yaml`. Confirm and accept that the demo may show
   blue *declining* to act on a real alert if confidence lands at 0.79.
3. **Domain-dominance headline number for the demo.** Blog says "under
   6 min", CFP says "under 20 min". Recommend blog number; hero snapshot
   supports it.
4. **Do we show blue *failing* on any technique?** The honest answer to
   "what's the gap?" is powerful. Recommend: yes — pick a snapshot
   where blue misses one specific IOC and leave the scoreboard at 6/9
   detection. Frames the closing slide.
5. **Live sidebar during Q&A?** After the scored replay finishes, kick
   off a real live run against the standby DreadGOAD during Results
   narration and reveal it during Q&A. High reward, incremental risk
   (uses standby stack). With Option A, this is powerful because blue
   *actually* acts on the lab in front of the audience. Recommend: yes,
   with "this might not finish in time — that's the point."
6. **Cross-forest responder topology.** Design doc recommends one
   responder per forest. Confirm; alternative is one responder with
   cross-forest DA (simpler infra, higher blast radius on compromise).

---

## Framing lines for the deck's demo intro

Two candidate opens for the demo section — pick one in rehearsal:

- *"Everything you're about to see is running. The attacker is deciding what to do next in real time. The defender is watching Loki and building an investigation. Nothing is scripted. The scoreboard is live. Watch what happens."*
- *"This is one run of the benchmark from the paper. Same infrastructure as the paper. Same agents. Same code. The number at the bottom is what the paper actually measures. I'll narrate over it."*

The first is dramatic; the second is honest about the replay path. Recommend the second — it matches the talk's thesis about bottom-up ground truth and doesn't require any hedging when someone asks "was that live?" in Q&A.
