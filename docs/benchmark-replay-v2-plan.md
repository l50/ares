<!-- markdownlint-disable MD013 -->

# Benchmark Replay v2 — Optimal Design & Build Plan

Status: proposal. Supersedes the replay portions of `benchmark-replay-strategy.md`.
Author: drafted with Claude from a full read of `ares-cli/src/benchmark/`,
`ares-tools/src/blue/`, `ares-cli/src/orchestrator/blue/`, and the blue prompt
templates. All file:line references verified 2026-07-03.

## 1. Goal and guiding principle

The replay is a **deterministic simulator of the SOC's observable world at
attack-time**. It exists so we can run a blue-team rollout, score it, tweak the
agent, and run again — attributing every score delta to the agent change, not to
environment noise.

**Principle: freeze the world, move a clock through it.**

- *Freeze the world* — the captured logs and the captured alert firings are the
  ground truth. We replay the recording; we do not re-simulate it.
- *Move a clock through it* — a virtual "replay clock" anchored at the first
  alert makes the frozen world *unfold* in attack-time, without ever depending
  on wall-clock timing (which would reintroduce non-determinism).

Determinism is the constraint that everything else is optimized against. Realism
is maximized *subject to* strict determinism.

## 2. Why not re-run the 77 detection rules (the tempting alternative)

Re-evaluating the rules against poured-in logs feels cleaner but is wrong for the
loop:

- **It won't fire at the same times.** Grafana rules evaluate on a schedule
  against a window relative to `now()`. Poured-in historical logs sit outside
  "the last 5 minutes," so rules **don't fire at all** unless we rewrite every
  timestamp to now and run in ~real time and wait for eval cycles.
- **It's non-deterministic.** Firing depends on eval-interval alignment, `for:`
  durations, ingestion timing, and threshold edges. Two replays of the same
  snapshot can fire a different set at different times — which destroys the
  hill-climbing signal.
- **It's less faithful.** The captured firings are literally what paged the blue
  team, when. Re-evaluation is a reconstruction that can diverge.

So: **seed the captured firings.** Keep live re-evaluation only as an optional,
slow *final-validation* mode (§8), never in the GEPA loop.

## 3. Current state (what's broken), code-referenced

| # | Problem | Location |
|---|---------|----------|
| 1 | Replay stands up **bare Loki only** — no Grafana/Prometheus/Tempo surface | `replay_infra.rs:437-535` |
| 2 | Loki pinned to **3.4.2**; prod is **3.6.7** | `replay_infra.rs:26` |
| 3 | Per-run **base64 chunk-key rename** on EC2 (jank + latency) | `replay_infra.rs:466-476` |
| 4 | **Only the first alert** is replayed | `replay.rs:473` (`alerts.first()`) |
| 5 | Only `LOKI_URL` is injected; `GRAFANA_URL`/`PROMETHEUS_URL` pass-through only, `TEMPO_URL` absent | `replay.rs:171-173`, `ops/submit.rs:12-27` |
| 6 | **Time disorientation**: alert-replay drops the agent into a template branch that tells it to query **wall-clock** now-2h..now | `initial_alert_prompt.md.tera:64-96`, `blue.rs:330` |
| 7 | `query_logs_recent` is hardwired to wall-clock `Utc::now()` | `loki.rs:368` |
| 8 | `time_compression` is accepted and **read by nothing** | `replay.rs` (dead field) |

## 4. Target architecture

Ephemeral lab-account EC2, booted from a **pre-baked AMI** carrying the full
observability stack. Per run: boot → attach snapshot's Loki data → seed that
op's alert firings into Grafana → point the blue agent at the box → run → score →
terminate. Clean isolation per snapshot; fast boot; byte-identical every run.

### 4.0 The parity contract — the blue tool surface (definitive)

Parity is defined by what the agent's tools can query. Per-role surface
(`ares-llm/src/tool_registry/blue/mod.rs:63-116`):

| Role | Loki | Prometheus | Grafana | Observability? |
|------|------|-----------|---------|----------------|
| Orchestrator | — | — | — | none (dispatch + state) |
| Triage | ✓ | — | ✓ | logs + alerts |
| ThreatHunter | ✓ | **✓** | ✓ | logs + **metrics** + alerts |
| LateralAnalyst | ✓ (+detection) | — | ✓ | logs + alerts |
| EscalationTriage | — | — | — | none (callbacks + state) |

Backends that MUST return real data in replay: **Loki, Prometheus (ThreatHunter
only), Grafana**. Confirmed in code: **no blue tool queries Tempo, Mimir
(directly), a standalone Alertmanager, ClickHouse, or Postgres** — those are
*cosmetic* parity (stood up empty to match argonaut; nothing depends on them).

Required captured data, by backend:

- **Loki** — captured (shards). Widen the capture window to **T0−6h … T1+6h**
  (`query_logs_progressive` expands ±6h).
- **Prometheus** — **new capture** (§4.6). ThreatHunter-only but required.
- **Grafana annotations** — **new capture**: *all* annotations in the window
  (not just `type=alert`), since `get_grafana_annotations` returns all;
  `get_alerts_in_time_range` (the key historical tool) reads `type=alert`.
- **Grafana dashboards + alert-rule defs** — configuration (IaC); provision into
  the replay Grafana. `get_grafana_alerts` (live Alertmanager-proxy state) is
  best-effort; the deterministic path is annotations.

### 4.1 The stack (AMI-baked, docker-compose), versions matched to argonaut

| Component | Version | Role in replay |
|-----------|---------|----------------|
| Grafana | 12.3.1 | The surface the agent queries "like a normal person"; datasources + seeded alert annotations |
| Loki | 3.6.7 | Log data (the real captured firehose) |
| Prometheus | 3.11.3 | Metrics surface — **required data** (ThreatHunter queries it; capture via §4.6) |
| Mimir | 3.0.4 | Parity only — agent hits `PROMETHEUS_URL`, not Mimir directly |
| Tempo | 2.9.0 | Parity only — **no blue tool queries traces**; stood up empty so the stack matches argonaut |
| Alertmanager | kube-prom-stack | Parity; live-eval mode |

Grafana provisioning baked into the AMI:

- **Datasources** (uids matching argonaut so nothing has to be rewired): `loki`,
  `prometheus`, `mimir`, `tempo`, `alertmanager` → local compose services.
- **The 77 security alert rules**, imported **paused** (for parity, so
  `get_alert_history`/rule-listing return them; and to enable live-eval mode).
  Paused = they never evaluate in the loop, so they add no non-determinism.
- Dashboards (optional): export from argonaut via `GET /api/search` +
  `GET /api/dashboards/uid/{uid}` and provision, so `search_grafana_dashboards`
  returns parity results.

Blue tools query: **Loki + Prometheus + Grafana** (confirmed — there is **no
Tempo/trace tool** in `ares-tools/src/blue/`). So the *functionally required*
surface is Grafana + Loki (+ Prometheus). Tempo/Mimir/Alertmanager are stood up
for **surface parity** (queries resolve instead of erroring) at ~zero data cost.

### 4.2 Data plane (logs) — keep shards, remove the warts

Bulk Loki API export (`query_range` pagination) does not scale at our volumes —
confirmed operationally. And the capture data flow is dictated by the account
split: capture *reads* the infra bucket `dev-argonaut-loki` (read-only) → copies
to the operator's laptop → uploads to the lab bucket `ares-benchmark-us-west-1`;
replay reads only the lab bucket. Keep all of that. One safe change:

- **Bump Loki to 3.6.7** — one const (`replay_infra.rs:26`); schema v13 + tsdb
  are stable across 3.4→3.6; no config change (verified). This is the *only*
  data-plane change.
- **Keep the base64 chunk-key rename on the replay box** (`replay_infra.rs:466-476`),
  as-is. It runs only on the throwaway replay EC2, over our *copied* chunk files;
  it touches nothing in the infra account and nothing in the production Loki that
  Jayson owns, and it handles existing (raw-key) snapshots with no migration.
  (Considered moving it to capture time or reading chunks straight from S3 —
  neither is worth the added risk/complexity at our scale.)

### 4.3 Alert plane — capture full firings, seed as annotations, unfold via the clock

- **Capture (mostly done, one enrichment).** `fired-alerts.json` already stores
  every firing sorted by `fired_at` (`manifest.rs:70-83`, `capture.rs:480-570`).
  Enrich each with its **triggering query** and `alertId/panelId/severity/MITRE`
  where the annotations/rules API exposes them, so a seeded firing is fully
  *followable* (the agent reads the alert → gets its query + time → pivots into
  Loki, which has the data).
- **Seed on replay.** After Grafana is up, `POST /api/annotations` (type=alert)
  for **every** captured firing at its `fired_at`. This is exactly the endpoint
  the blue tools read.
- **Trigger = first alert; discovery = the annotation tools.** Fix
  `alerts.first()` (`replay.rs:473`): the first firing is the initial page (one
  investigation), and the agent discovers the rest via `get_grafana_annotations`
  / `get_alerts_in_time_range` as it works. This is **one investigation that
  unfolds** — not N independent ones.
- **Tool normalization (small, contained).** From the query-plane audit:
  - `get_grafana_annotations` (`query.rs:76`) reads `/api/annotations` with no
    `alertId` filter → seeded annotations work as-is. **Primary discovery tool.**
  - `get_alerts_in_time_range` (`rules.rs:205`) requires `alertId != 0`
    (`rules.rs:253`) → seed annotations against the (paused) real rule IDs, or
    relax that filter in replay.
  - `get_grafana_alerts` (`query.rs:15`) reads **live Alertmanager state**
    (`/api/alertmanager/grafana/api/v2/alerts`) → add a replay fallback that
    returns seeded firings with `fired_at ≤ replay_now`, so "what's firing"
    reflects the recording deterministically.

### 4.4 Virtual replay clock — deterministic unfolding

- **One clock source.** Add `ares_tools::replay_now() -> DateTime<Utc>` backed by
  an `AtomicI64`/`OnceCell`, initialized from `ARES_REPLAY_CLOCK_START`. Replace
  the wall-clock sites the audit found:
  - `loki.rs:368` — `query_logs_recent`, **unconditional** (top priority)
  - `loki.rs:358`, `loki.rs:419`, `rules.rs:213`, `rules.rs:216` — parse-failure
    fallbacks
  - `annotate.rs:32/107/191` — investigation-lifecycle timestamps (so seeded
    lifecycle annotations land in attack-time)
- **Prompt anchor (one line).** `blue.rs:330` reads `ARES_REPLAY_CLOCK_START`
  instead of `Utc::now()`. The existing template branch then says "query from
  {attack−2h} to {attack}" with **no template rewrite** — problem #6 solved.
- **Prometheus instant gap.** `query_instant` (`prometheus.rs:41`) omits `time` →
  server-side now. Default `time` to `replay_now()` when the clock is set.
- **v1 vs v2 of "unfolding".**
  - *v1 (correctness):* clock anchored at first alert; all captured firings
    visible; time-relative queries land on the attack. Deterministic, unblocks
    GEPA immediately.
  - *v2 (polish):* advance `replay_now` by **investigation step/round** (never by
    wall-clock) and gate firing visibility to `≤ replay_now`, so later alerts
    "arrive" as the analyst works — still fully deterministic.
- Retire the dead `time_compression` field in favor of this.

### 4.5 Control plane — endpoints + env plumbing

- Expose `grafana_url()`, `prometheus_url()`, `tempo_url()` from `ReplayInfra`
  (alongside the existing `loki_url()`), and `set_var` all of them +
  `ARES_REPLAY_CLOCK_START` next to the `LOKI_URL` injection
  (`replay.rs:171-173`).
- Add `TEMPO_URL` and `ARES_REPLAY_CLOCK_START` to `BLUE_ENV_VAR_NAMES`
  (`ops/submit.rs:12-27`).
- **Dispatch must be in-process** (`ARES_TOOL_DISPATCH=local`, already the EC2
  default): the env read-back injects into the orchestrator process
  (`investigation.rs:79-94`) but **not** separately-spawned workers
  (`blue_task_loop.rs:165-273`). In-process dispatch is required for the
  endpoint/clock overrides to reach the query tools.
- **OnceCell caveat.** `loki_config()` caches the Grafana→Loki proxy in a
  `OnceCell` (`loki.rs:29,38-62`). Ephemeral replay uses a fresh process per run,
  so first-call resolution captures the replay endpoints correctly — provided env
  is set before the first Loki call (it is). Provision the replay Grafana's Loki
  datasource with uid `loki` so proxy routing (the prod pattern — `.env`'s
  `LOKI_URL` is itself a Grafana proxy URL) resolves to the local Loki.

### 4.6 Prometheus metric capture (new)

Prometheus in argonaut is local-PVC TSDB (no remote-write/Mimir/S3). Capture
after the op window closes, via the API — volume is tens of MB for a ~2h window,
so no shard hack is needed:

1. `GET /api/v1/query_range?query={__name__=~".+"}&start=T0&end=T1&step=15s`
   (optionally filter metric names to the relevant set to cut size).
2. Serialize to OpenMetrics text; store in the snapshot under `prometheus/`.
3. Replay: `promtool tsdb create-blocks-from openmetrics <dump> /data/prometheus`,
   then start the replay Prometheus on that data dir. Imported blocks serve
   historical range queries with no recency limit (bypasses the out-of-order
   ingestion window). `get_metric_names` is served from the same blocks.

(If the admin API is enabled, `POST /api/admin/tsdb/snapshot` yields a full TSDB
snapshot dir — simpler but larger.)

## 5. Concrete changes by file

| File | Change |
|------|--------|
| `replay_infra.rs:26` | `LOKI_VERSION` → `"3.6.7"` |
| `replay_infra.rs:437-535` | Replace bare-Loki install with: boot AMI stack (compose) / attach + **rename** snapshot chunks (keep 466-476) / seed alerts / ready-checks |
| `replay_infra.rs:26` | `LOKI_VERSION` → `"3.6.7"` (only data-plane change) |
| `replay_infra.rs` | Add `grafana_url()/prometheus_url()/tempo_url()` accessors |
| `capture.rs:480-570` | Enrich `fired-alerts.json` with triggering query + ids |
| `replay.rs:171-173` | `set_var` GRAFANA_URL/PROMETHEUS_URL/TEMPO_URL/ARES_REPLAY_CLOCK_START |
| `replay.rs:464-492` | Replay **all** firings; seed annotations; drop `alerts.first()` |
| `ops/submit.rs:12-27` | Add `TEMPO_URL`, `ARES_REPLAY_CLOCK_START` |
| `ares-tools/src/blue/` (new) | `replay_clock.rs` → `replay_now()` clock source |
| `loki.rs:358,368,419` | Use `replay_now()` |
| `grafana/rules.rs:213,216,253` | Use `replay_now()`; relax `alertId != 0` for replay |
| `grafana/query.rs:15-66` | `get_grafana_alerts` replay fallback → seeded firings ≤ `replay_now` |
| `grafana/annotate.rs:32,107,191` | Use `replay_now()` |
| `prometheus.rs:41` | Default instant `time` to `replay_now()` |
| `ares-llm/src/prompt/blue.rs:330` | Anchor `now` to `ARES_REPLAY_CLOCK_START` |
| new AMI build | docker-compose stack + Grafana provisioning (datasources, 77 rules paused, dashboards) |

## 6. Build order (cheap → meaty)

1. **Replay-stack AMI** — compose + provisioning; bake. *(infra, parallelizable)*
2. **Data plane** — Loki 3.6.7 + rename-at-capture (4b). *(rust, small)*
3. **Control-plane env** — expose + inject endpoints + clock var. *(rust, small)*
4. **Alert seeding** — enrich capture, seed all firings, fix `first()`, normalize
   the 3 grafana tools. *(rust, medium)*
5. **Virtual clock v1** — `replay_now()` + site swaps + prompt anchor + Prom
   `time`. *(rust, medium)*
6. **End-to-end validation** on one snapshot; then **clock v2** (step-advanced
   unfolding). *(rust)*
7. *(optional)* **Live-eval validation mode** (§8).

## 7. Risks & gotchas

- **Worker env isolation** — must run in-process dispatch (§4.5).
- **OnceCell Loki proxy** — set env before first call; fresh process per run (§4.5).
- **Prometheus/Tempo are data-light** — surfaces resolve but return little; fine
  because no blue tool depends on their data, but don't score against them.

## 8. Optional: live-eval validation mode

For occasional realism checks (not the loop): timestamp-shift the snapshot logs
to "now," un-pause the 77 rules, let Grafana/Alertmanager evaluate live, real
firings drive the trigger. Slow and non-deterministic — use only to confirm that
gains found on the deterministic loop hold under realistic firing dynamics.

## 9. What this buys us

A replay that presents the *same surface* the blue team sees live (Grafana + Loki +
Prometheus, with Tempo/Mimir/Alertmanager for parity), triggered by the *real*
alert firings, on the *right* clock, byte-identical every run — so the GEPA loop
measures the agent, and only the agent.
