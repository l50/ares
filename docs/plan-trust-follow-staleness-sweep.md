# Plan: trust_follow dedup staleness sweep

## Problem

`auto_trust_follow` (`ares-cli/src/orchestrator/automation/trust.rs`) marks the
`trust_follow:<src>:<trust_user>$` dedup entry **before** spawning the
`forge_inter_realm_and_dump` dispatch (lines 1981-1989, comment at 1979 explains
the race against the next 30s tick). If anything between `mark_processed` and
the spawn body's `dispatch_tool().await` fails to actually run the tool — a
dropped tracing event, a runtime cancellation, a panic between the `info!` and
the spawn — the dedup persists and **no later tick will retry**, even though
the trust key sits in state ready to use.

Evidence from op-20260606-063217 (2026-06-06, GOAD Ludus range):

| Signal | Value |
| --- | --- |
| Op duration | 2h 5m (hit max_runtime) |
| Outcome | 2/3 DA, 2/3 GT — `essos.local` never compromised |
| `ESSOS$` trust key in `state.hashes` | yes (`is_trust_key: true`, `aes_key` populated) |
| `essos.local` in `state.trusted_domains` | yes (`sid_filtering: false`, so `is_filtered_inter_forest_trust` returned false) |
| `sevenkingdoms.local` domain SID in `state.domain_sids` | yes |
| `dc_map["essos.local"]` | `10.1.10.12` |
| `forge_inter_realm` log lines for this op | **0** |
| `forge_inter_realm` log lines globally | 1586 |
| `Cross-forest forge dispatched` info line | **0** for this op |
| `Suppressing forge_inter_realm_and_dump` | **0** for this op |
| `trust_follow:sevenkingdoms.local:essos$` in dedup set | **present** |

All preconditions for the forge succeeded. The dedup is marked. The forge
never ran. Subsequent ticks see `is_processed=true` at line 1508 and skip the
work item silently.

The same binary (Jun 5 23:05 build) ran op-20260606-031653 earlier the same day
and successfully fired `forge_inter_realm_and_dump`. The bug is a stuck
state, not a hard regression — but once it sticks, the cross-forest pivot is
dead for the rest of the op.

## Proposed fix

Add an in-flight timestamp map keyed by dedup key. Set the timestamp when we
mark_processed; clear it when the spawned dispatch returns (success or
explicit error). At the top of each `auto_trust_follow` tick, sweep the map
for entries older than `FORGE_STALENESS_LIMIT` (3 min) and unmark them so the
next tick re-dispatches.

This keeps the existing pre-spawn mark (still needed to win the 30s tick
race) but bounds the failure mode: a dropped spawn becomes a 3-min stall
instead of a permanent loss.

### Concrete changes

1. **`ares-cli/src/orchestrator/state/mod.rs`** (or `state/inner.rs`) — add
   `forge_in_flight: HashMap<String, Instant>` to `StateInner`.
   `key = dedup_key (trust_follow:src:user$)`, `value = mark_processed_at`.

2. **`ares-cli/src/orchestrator/automation/trust.rs`**
   - Top of the `loop` in `auto_trust_follow` (just after the shutdown check):
     scan `state.forge_in_flight` for entries older than `FORGE_STALENESS_LIMIT`;
     for each, call `unmark_processed(DEDUP_TRUST_FOLLOW, key)`, `unpersist_dedup`
     against Redis, and remove from the map. Emit a `warn!` so the sweep is
     auditable.
   - At the cross-forest forge mark_processed (line ~1985): also
     `state.forge_in_flight.insert(item.dedup_key.clone(), Instant::now())`.
   - In the spawn body's `clear_dedup()` closure (line ~2019) and at the
     successful-exploit path: also `state.forge_in_flight.remove(&dedup_key_bg)`.

3. **Tests** in `ares-cli/src/orchestrator/automation/trust.rs` test module:
   - `forge_in_flight_stale_entry_is_swept`: insert a `(key, Instant::now() - 4 min)`,
     run the sweep helper, assert dedup is unmarked and map is empty.
   - `forge_in_flight_fresh_entry_is_kept`: insert with `Instant::now()`, assert
     untouched after sweep.
   - `forge_in_flight_cleared_on_dispatch_success`: simulate the success path,
     assert the key is removed from the map.

Constants:

```rust
const FORGE_STALENESS_LIMIT: Duration = Duration::from_secs(180);
```

### Non-goals (for this PR)

- Persistence.rs fresh-op clearing of `trust_follow` dedup (the bug we hit
  doesn't require carry-over; the entry was written during the op's own run).
  Document as follow-up if a separate carry-over case is observed.
- Restoring concrete GOAD examples to LLM prompts that PR #57 sanitized
  (`north.sevenkingdoms.local` → `child.contoso.local`). Separate concern,
  separate PR — the slow time-to-first-DA on this range is plausibly that,
  but is orthogonal to the cross-forest pivot bug.
- Replacing the pre-spawn mark with a post-spawn mark. The 30s tick race the
  existing comment describes is real; a sweep is the lower-risk addition.

## Verification

1. `cargo check -p ares-cli` — confirms type changes compile.
2. `cargo clippy -p ares-cli -- -D warnings` — keeps the pre-commit hook happy.
3. `cargo test -p ares-cli --lib orchestrator::automation::trust` — runs the
   new sweep tests and the existing trust-flow tests still pass.
4. Build + push to attacker-1, submit fresh op against the GOAD Ludus range,
   confirm `forge_inter_realm` log lines AND a 3/3 DA outcome — or, if the
   sweep fires, a `warn!` line about the unstuck dedup.

## Future follow-ups (out of scope)

- Investigate WHY the spawn never ran on op-20260606-063217. Top candidates:
  tracing event drop, tokio runtime budget exhaustion, dispatcher state
  lock contention. The sweep is a recovery mechanism, not a root-cause fix.
- Audit other `mark_processed before spawn` sites (lines 681, 1109, 1398, 1604)
  for the same staleness risk.
