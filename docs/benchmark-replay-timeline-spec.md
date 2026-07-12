# Benchmark Replay — Timeline / Unfolding Spec (committed)

This is the **implementation contract** for the unfolding replay. It resolves the
open choices in `benchmark-replay-v2-plan.md` §4.4 and supersedes the "v1 frozen
anchor" behavior. Nothing here is optional or "phase 2" — it is the target.

## Intent (unchanged since 2026-07-01)

The blue agent is dropped into an alert **while the attack is still unfolding**,
exactly as it would be live: it sees the world *up to now*, never its own future,
and more of the attack (logs **and** alerts) surfaces as it works. Plus a
`static` mode where the whole (concluded) attack is available up front.

## Resolved decisions

1. **Visibility model = clamp the tools (approach A).** All snapshot data stays
   pre-loaded in the replay stack. The agent only perceives the world through the
   query tools, so we bound *those* to `replay_now`. A query for the future
   returns empty — faithful to a live analyst. (Progressive physical ingestion —
   approach B — is explicitly *not* built; the agent cannot perceive the
   difference and it's a large re-architecture.)
2. **Clock advance = both, step-based default.**
   - `step` (default): `replay_now = attack_start + attack_duration * min(step/max_steps, 1)`.
     Deterministic (independent of LLM/API latency), guarantees a thorough agent
     can see the whole attack by its last step, rewards investigation effort.
   - `wallclock` (opt-in, for real-time demos, not scoring):
     `replay_now = min(attack_start + real_elapsed, attack_end)`.
3. **Trigger = first alert at/after attack start** (both modes). No more
   `alerts.first()` picking pre-attack infra noise.
4. **`time_compression` is retired** (compression was never a required feature).

## Clock state machine (`ares-core/src/replay_clock.rs`)

`replay_now()` resolves against env config (set fresh each call — no cache):

| env | meaning |
|---|---|
| `ARES_REPLAY_CLOCK_START` | anchor = trigger alert `fired_at` (attack entry) |
| `ARES_REPLAY_CLOCK_END`   | `manifest.completed_at` (attack end) |
| `ARES_REPLAY_CLOCK_MODE`  | `static` \| `step` \| `wallclock` |
| `ARES_REPLAY_MAX_STEPS`   | step budget (step mode) |

- **live** (no `START`): `replay_now() = Utc::now()`, `is_replay() = false`. Unchanged.
- **`static`**: `replay_now() = END` → everything ≤ attack end is visible.
- **`step`**: uses a process-global `CURRENT_STEP` (atomic) updated by the agent
  loop via `set_step()`; `replay_now = START + (END-START)*min(step/max,1)`.
- **`wallclock`**: `START + (now_wall - first_call_wall)`, capped at `END`.
- **Back-compat**: if `START` is set but `END`/`MODE` are not, `replay_now() = START`
  (the old frozen-v1 behavior) — nothing else changes.

New public API: `set_step(u64)`, `configure()` helpers; existing
`replay_now()/is_replay()/set_replay_clock()/reset_replay_clock()` kept.

## The clamp (visibility ≤ `replay_now`) — sites

All go through the blue tools; the agent has no raw datastore access.

- **Loki** (`ares-tools/src/blue/loki.rs`): in the single funnel `query_logs`, when
  `is_replay()`, set `end = min(parsed_end, replay_now())`. Covers `query_logs`,
  `_recent`, `_around`, `_progressive`, `execute_parallel_queries` (all funnel here).
  Also cap `get_loki_label_values` end at `replay_now`.
- **Grafana** (`grafana/query.rs`, `rules.rs`): `get_alerts` and
  `get_alerts_in_time_range` / `get_grafana_annotations` return only firings with
  `fired_at ≤ replay_now` (cap `to` at `replay_now`).
- **Prometheus** (`prometheus.rs`): `query_instant` defaults/caps `time` at `replay_now`;
  `query_range` caps `end` at `replay_now`.
- **Prompt** (`ares-llm/src/prompt/blue.rs`): already uses `replay_now()`.

## Step plumbing

`ares-llm/src/agent_loop/runner.rs` calls `ares_core::replay_clock::set_step(step)`
at the top of each loop iteration. No-op unless `MODE=step`.

## Benchmark wiring (`ares-cli/src/benchmark/replay.rs`)

- `build_alert_replay_trigger`: `alerts.iter().find(|a| a.fired_at >= manifest.started_at)`
  (fallback `.first()` + warn).
- In `run_replay`, `set_var`: `ARES_REPLAY_CLOCK_START` (= trigger `fired_at`),
  `ARES_REPLAY_CLOCK_END` (= `manifest.completed_at`), `ARES_REPLAY_CLOCK_MODE`
  (`static` when `replay_mode=static`, else the `--clock` value), `ARES_REPLAY_MAX_STEPS`
  (= `max_steps`). Add all four to `BLUE_ENV_VAR_NAMES` (`ops/submit.rs`).
- New CLI flag `--clock <step|wallclock>` (default `step`), used only in timeline.
- Remove `--time-compression` + `ReplayParams.time_compression` + its store.

## Acceptance criteria

1. `static`: agent triggered by the first post-attack-start alert; all attack data visible.
2. `timeline` (step): a query with `end_time` in the future returns data only up to
   `replay_now`; `get_alerts` early in the run shows only early firings, later ones
   appear as steps advance; by the final step the whole attack is queryable.
3. Same agent + same snapshot + `step` mode → identical visible-data boundaries
   run-to-run (latency-independent).
4. `wallclock` behaves as real-time, capped at attack end.
5. Transcript (session log) shows the agent unable to retrieve post-`replay_now` events.

## SQL persistence: red/blue separation + analysis (committed)

Blue benchmark activity lands in the **same** `ares_history` as red (so "for op X,
what red did vs what blue caught" is a JOIN, and cost/token stats are unified),
tagged so the two are cleanly separable.

- **`team` column** (`red` | `blue`, default `red`) on the activity tables
  (`llm_messages`, `tool_calls`, `worker_events`, `log_lines`, `otel_spans`) —
  migration `20260707170000_team_flag.sql`. Stamped on every SessionLog record and
  carried through by `scripts/ingest_jsonl.py`.
- **Blue keys**: `op_id =` the **replayed** operation (join to red on `op_id`);
  `task_id =` the run/investigation id (per-run separability — each GEPA run is a
  distinct row set, no file collisions since blue's task_id is the run id).
- **Decoupled from correlation**: the SessionLog op_id/team come from env
  (`ARES_SESSION_OP_ID`, `ARES_SESSION_TEAM`) via `SessionLogConfig`, **not** from
  `investigation.operation_id` (which would trigger the red-state correlation
  reader and leak red findings into blue). The benchmark sets both + points
  `ARES_SESSION_LOG_DIR` at the ingester root (`/var/log/ares/session`).
- **Enables**: `SELECT team, op_id, sum(total_tokens), count(*) FROM llm_messages
  GROUP BY 1,2` — red-fleet-vs-red-fleet and red-vs-blue cost/outcome stats.

## `operation` trigger guard (committed)

`--trigger-mode operation` injects the ground-truth techniques + IOCs
(`build_operation_trigger`) the scorer grades — an oracle/upper-bound, never a
valid score. The runner now emits a loud stderr warning and a `⚠ SCORE INVALID`
summary line whenever `effective_trigger_mode == "operation"`. Default remains
`alert-replay`; timeline forces `alert-replay`.
