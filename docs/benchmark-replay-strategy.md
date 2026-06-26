<!-- markdownlint-disable MD013 -->

# Adversarial Benchmark Replay System

Strategy document for building a reproducible, optimizable adversarial
benchmark from frozen Loki telemetry snapshots.

## Problem

Red team operations produce rich per-operation data in Postgres (hosts,
credentials, hashes, techniques, timeline events). But the defender-side
telemetry -- Windows Security/Sysmon/PowerShell logs that the blue team
actually investigates -- lives in a shared Loki instance with no per-operation
boundary. This means:

- Blue team investigations are not reproducible: running the same investigation
  twice queries live Loki, which has moved on.
- There is no way to A/B test blue team configurations against the same data.
- There is no train/test split for systematic improvement.

## Goal

1. Run N red team operations against GOAD (target: 100+).
2. After each, snapshot the full observable state: all Loki log streams for
   the operation window (noise included), which Grafana alert rules fired and
   when, and the red team state from Postgres.
3. Store these as immutable frozen fixtures.
4. Replay any fixture into an ephemeral Loki instance on demand.
5. Run blue team investigations against the replay, triggered by the same
   alerts that fired during the live operation.
6. Score blue team performance against ground truth derived from the red team
   state.
7. Split the corpus into training (80) and test (20) sets. Optimize blue team
   prompts/rules on the training set, validate on the test set.

## Architecture

```text
Phase 1: CAPTURE
  Red op --> GOAD --> Windows events --> Alloy --> Production Loki
                                                        |
                                              snapshot-capture job
                                                        |
                                  S3: /snapshots/{op-id}/
                                      +-- manifest.json
                                      +-- red-state.json
                                      +-- ground-truth.json
                                      +-- loki/
                                      |   +-- windows-security.jsonl.gz
                                      |   +-- windows-sysmon.jsonl.gz
                                      |   +-- windows-powershell.jsonl.gz
                                      |   +-- ...
                                      +-- alerts/
                                          +-- fired-alerts.json

Phase 2: REPLAY + EVALUATE
  S3 snapshot --> ephemeral Loki pod (K8s)
                       |
                  push all JSONL
                       |
                  alert replay: first alert fired at T=X
                       |
                  blue team starts from T=X, investigates
                       |
                  score against ground truth
                       |
                  EvaluationResult + GapAnalysisReport

Phase 3: OPTIMIZE (GEPA loop)
  for generation in 0..G:
      for scenario in training_set:
          replay(scenario) --> score
      aggregate --> fitness per variant
      select top performers, mutate, next generation
      validate on test_set every K generations
```

## What already exists

| Component | Status | Location |
|-----------|--------|----------|
| Red team operations | Done | `ares-cli/src/orchestrator/red/` |
| Red state persistence to Postgres | Done | `ares-core/src/persistent_store/` |
| NATS JetStream event replay | Done | `ares-cli/src/ops/replay.rs` |
| Ground truth generation from red state | Done | `ares-core/src/eval/ground_truth/transform.rs` |
| 6-metric scoring system (IOC, technique, pyramid, evidence, stage, timeline) | Done | `ares-core/src/eval/scorers/scoring.rs` |
| Gap analysis with actionable recommendations | Done | `ares-core/src/eval/gap_analysis/` |
| Dataset evaluation + aggregation (pass rate, grade distribution) | Done | `ares-core/src/eval/workflow/` |
| Red-blue correlation engine | Done | `ares-core/src/correlation/redblue/` |
| Loki query client (configurable via `LOKI_URL`) | Done | `ares-tools/src/blue/loki.rs` |
| 77 Grafana security alert rules | Done | Grafana instance, Security folder |
| Blue team orchestrator (4 roles) | Done | `ares-cli/src/orchestrator/blue/` |
| Analytical tables (llm_messages, tool_calls, etc.) | Done | `ares-core/migrations/20260615120100_analytical.sql` |
| JSONL session log ingestion | Done | `scripts/ingest_jsonl.py` |
| Artifact archiving to S3 | Done | `scripts/archive_op_artifacts.py` |
| Loki bulk export | **New** | -- |
| Loki push/import | **New** | -- |
| Ephemeral Loki pod management | **New** | -- |
| Snapshot capture CLI | **New** | -- |
| Alert-based blue trigger | **New** | -- |
| Replay runner | **New** | -- |
| GEPA optimization loop | **New** | -- |
| Train/test split management | **New** | -- |

## Phase 1: Snapshot capture

### What gets captured

Each snapshot is a self-contained directory with everything needed to replay
a blue team investigation without the original infrastructure.

| File | Source | Purpose |
|------|--------|---------|
| `manifest.json` | Generated | Op ID, start/end timestamps, GOAD topology version, technique list, strategy preset, tags |
| `red-state.json` | Postgres or NATS replay | Full red team state: hosts, creds, hashes, vulns, techniques, DA path |
| `ground-truth.json` | `create_ground_truth_from_red_state()` | Expected IOCs, expected MITRE techniques, minimum pyramid level |
| `loki/*.jsonl.gz` | Loki `query_range` API | One gzipped JSONL file per log stream |
| `alerts/fired-alerts.json` | Grafana annotations API | Which alert rules fired, when, with what labels |

### Capture window

Extend **1 hour before** operation `started_at` to **30 minutes after**
`completed_at`. The pre-attack window captures ambient noise that was in the
environment before the attack began. This noise is part of the realism -- a
real SOC analyst gets the full firehose, not a sanitized view.

### Loki streams to export

From the Alloy collector config (`ansible/roles/alloy/templates/config.alloy.j2`):

| Stream | Content |
|--------|---------|
| `{job="windows-security"}` | Events 4624/4625/4662/4768/4769/5140/etc. |
| `{job="windows-sysmon"}` | Process creation, network connections, file access |
| `{job="windows-powershell"}` | Script block logging, module logging |
| `{job="windows-directory-service"}` | AD replication events |
| `{job="windows-application"}` | Application errors |
| `{job="windows-system"}` | Service state changes |
| `{job="windows-defender"}` | AV detections |
| `{job="windows-dns-server"}` | DNS queries (DC only) |
| `{job="syslog"}` | Linux syslog (attacker host) |
| `{job="auth"}` | Linux auth.log |
| `{job="user-data"}` | Cloud-init logs |

### Export method

Paginated `GET /loki/api/v1/query_range` with `direction=forward`,
`limit=5000`. Iterate by setting `start` to last-seen timestamp + 1ns.
The existing Loki client in `ares-tools/src/blue/loki.rs` handles auth
(Grafana proxy or direct `LOKI_URL` + `LOKI_AUTH_TOKEN`), retries (3 attempts
with exponential backoff), and rate limiting.

Output format per JSONL line:

```json
{"stream":{"job":"windows-security","host":"DC01"},"values":[["1719403200000000000","<Event xmlns=...>"]]}
```

This is the exact format accepted by `POST /loki/api/v1/push`, so no
transformation is needed for import.

### Alert state capture

Use the Grafana annotations API (`GET /api/annotations?from=&to=&tags=`) to
capture which of the 77 rules fired during the operation window. Store the
alert name, fire timestamp, labels (severity, MITRE technique), and the
LogQL query that triggered it. The existing `get_alerts_in_time_range()` in
`ares-tools/src/blue/grafana/rules.rs` already does this.

### CLI command

```
ares benchmark capture <operation-id> \
    [--output-dir ./snapshots] \
    [--s3-bucket ares-ops-archive-us-west-1] \
    [--pre-window 1h] \
    [--post-window 30m]
```

Steps:
1. Load operation from Postgres (timestamps, config, strategy)
2. Export red team state -> `red-state.json`
3. Generate ground truth -> `ground-truth.json`
4. Export Loki streams for the capture window -> `loki/*.jsonl.gz`
5. Export fired alerts -> `alerts/fired-alerts.json`
6. Write `manifest.json`
7. Sync to S3 if `--s3-bucket` is set

### Implementation

New module: `ares-cli/src/benchmark/capture.rs`

New function in `ares-tools/src/blue/loki.rs`:

```rust
/// Export all entries from a single stream for a time range.
/// Writes Loki push-format JSONL to the provided writer.
pub async fn export_stream(
    &self,
    logql: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    writer: &mut impl Write,
) -> Result<u64>  // returns entry count
```

This paginates through `query_range`, bypasses the 100-entry cap that exists
on the blue team query functions, and writes each batch directly to disk
without holding the full dataset in memory.

## Phase 2: Replay + Evaluate

### Ephemeral Loki instance

A single-replica Loki pod in the `attack-simulation` namespace. Key config
differences from production:

```yaml
limits_config:
  reject_old_samples: false
  reject_old_samples_max_age: 87600h  # 10 years
  ingestion_rate_mb: 50
  ingestion_burst_size_mb: 100
  per_stream_rate_limit: 50MB
  max_entries_limit_per_query: 100000

storage_config:
  filesystem:
    chunks_directory: /loki/chunks

# Single replica, no replication, filesystem storage.
# Data lives on emptyDir -- deleted when pod is removed.
```

Resource requirements: 1-2 GB RAM, 500m-2 CPU, 10 GB emptyDir for chunks.
Startup: ~5-10 seconds. Import of a 2-hour window: ~30-60 seconds.

Managed as a K8s Job (not Deployment) with `restartPolicy: Never`. When the
benchmark run is done, delete the Job and the data disappears.

### Data import

Push exported JSONL back into the ephemeral Loki via `POST /loki/api/v1/push`.
The export format is the push format -- direct passthrough. Batch 1000-5000
entries per request, gzip the payload body.

```
ares benchmark load <snapshot-dir> --loki-url http://loki-replay:3100
```

New function in `ares-tools/src/blue/loki.rs`:

```rust
/// Push a JSONL file of exported entries into a Loki instance.
pub async fn import_stream(
    &self,
    target_url: &str,
    jsonl_path: &Path,
) -> Result<u64>  // returns entry count
```

### Triggering the blue team

There are two trigger modes for the benchmark:

**Alert replay (default)**: Use the captured `fired-alerts.json`. Take the
earliest fired alert, use its timestamp as the investigation start point, and
pass the alert name + LogQL query as the initial context to the blue team.
This is deterministic -- same trigger, same data, every replay.

**Live alert evaluation**: Deploy the 77 Grafana alert rules against the
ephemeral Loki and let them evaluate on their 1-minute cycle. More realistic
but slower (must wait for rule evaluation) and requires a Grafana instance.
Use for final validation, not for the optimization loop.

The change to the blue team submission path:

In `ares-cli/src/blue/submit.rs`, `blue_from_operation()` currently sets:

```rust
let window_start = state.started_at;
let window_end = state.completed_at.unwrap_or_else(Utc::now);
```

Add a `--alert-trigger <path-to-fired-alerts.json>` flag that instead:

1. Reads the first fired alert from the JSON
2. Sets `attack_window_start` to the alert fire time (not `state.started_at`)
3. Does NOT set `attack_window_end` -- blue has to figure out scope
4. Includes the alert name, severity, and triggering LogQL query in the
   operation context

This feeds into the template branch at
`ares-llm/templates/blueteam/agents/initial_alert_prompt.md.tera` (lines
64-96) which already handles "FOCUS YOUR QUERIES ON THIS WINDOW." The
difference is the window now starts from the alert, not the attack.

### Scoring

Unchanged from the existing system:

1. `create_ground_truth_from_red_state()` generates expected IOCs and
   techniques from `red-state.json`
2. `evaluate_live_investigation()` scores the blue team's findings against
   ground truth
3. Output: `EvaluationResult` with 6 sub-scores, overall score (0.0-1.0),
   letter grade (A-F), pass/fail
4. `analyze_detection_gaps()` produces gap analysis with recommendations

The existing `DatasetEvaluationResult` already aggregates across scenarios:
`pass_rate()`, `avg_overall_score()`, `avg_technique_coverage()`,
`grade_distribution()`, `total_cost_usd()`.

### CLI command

```
ares benchmark run <snapshot-path> \
    --loki-mode ephemeral \
    --trigger-mode alert-replay \
    --output-dir ./results
```

Steps:
1. Create ephemeral Loki K8s Job
2. Wait for readiness
3. Import snapshot data (`ares benchmark load`)
4. Extract trigger from `fired-alerts.json`
5. Run blue team investigation with `LOKI_URL` pointing at ephemeral Loki
6. Score against ground truth
7. Save `EvaluationResult` + `GapAnalysisReport`
8. Delete ephemeral Loki Job

## Phase 3: GEPA optimization loop

### What gets optimized

The "genome" is the full blue team configuration:

| Component | Where it lives | Mutation surface |
|-----------|---------------|-----------------|
| Investigation prompts | `ares-llm/templates/blueteam/agents/*.md.tera` | Reword instructions, reorder steps, add/remove example queries, adjust emphasis |
| Detection rules | 77 rules in Grafana + `create_detection_rule` | LogQL query patterns, evaluation intervals, severity thresholds |
| Tool configuration | `ares-tools/src/blue/loki.rs` params | Query limits, progressive time window steps, cache TTL |
| Strategy weights | `config/ares.yaml` | Triage vs. deep-dive balance, evidence thresholds |
| Agent topology | Blue orchestrator config | Which roles active (triage, threat_hunter, lateral_analyst, escalation_triage), parallelism |

### Dataset management

```text
/benchmarks/
  corpus/
    manifest.json
    scenario-001/
    scenario-002/
    ...
    scenario-100/
  splits/
    split-001.json
    split-002.json
```

`manifest.json` indexes all scenarios with metadata:

```json
{
  "name": "goad-v1-corpus",
  "scenarios": [
    {
      "id": "scenario-001",
      "state_file": "scenario-001/red-state.json",
      "tags": ["da-achieved", "kerberoast-heavy", "short-duration"],
      "technique_cluster": "secretsdump-chain",
      "duration_seconds": 420,
      "da_achieved": true
    }
  ]
}
```

Split files define train/test partitions:

```json
{
  "name": "80-20-stratified-001",
  "train": ["scenario-001", "scenario-003", "scenario-004", ...],
  "test": ["scenario-002", "scenario-007", ...]
}
```

Stratified splitting ensures proportional representation of:

- DA achieved vs. not achieved
- Technique clusters (secretsdump-chain, ADCS-chain, delegation-chain, mixed)
- Attack duration (short <10m, medium 10-30m, long >30m)
- Number of domains compromised

The existing `EvaluationDataset` in
`ares-core/src/eval/workflow/dataset.rs` already supports loading scenarios
from a JSON manifest with relative paths. Extend it to accept a split filter.

### Optimization loop

```
ares benchmark optimize \
    --corpus ./benchmarks/corpus \
    --split ./benchmarks/splits/split-001.json \
    --generations 20 \
    --population-size 5 \
    --validate-every 5 \
    --output-dir ./benchmarks/results
```

Each generation:

1. **Evaluate**: Run all training scenarios against each variant in the
   population. Each (variant, scenario) pair is independent -- parallelize
   across K8s Jobs. With 80 training scenarios and 5 variants, that is 400
   evaluations per generation. At ~10 minutes per investigation, this is
   ~67 hours serial or ~7 hours at 10x parallelism.

2. **Score**: Aggregate per-variant fitness:
   - Primary: average `overall_score` across training set
   - Secondary: `technique_coverage` (weighted higher for missed critical techniques like DCSync, Golden Ticket)
   - Penalty: cost (total tokens / estimated USD) -- prefer cheaper variants at equal quality
   - Fitness = `overall_score * 0.6 + technique_coverage * 0.3 - cost_penalty * 0.1`

3. **Select**: Elitism -- keep top 2 variants unchanged. Generate 3 new
   variants via mutation from the top performers.

4. **Mutate**: LLM-assisted mutation. For each new variant:
   - Take the best-performing variant's prompt set as the base
   - Collect gap analysis reports from the 10 worst-scoring scenarios
   - Feed to Claude: "These are detection gaps from 10 scenarios. The current
     prompts are [X]. Modify the investigation prompts to address these gaps
     without regressing on the scenarios that already pass."
   - The LLM produces a mutated prompt set
   - Optionally mutate detection rules: add new LogQL rules targeting the
     missed techniques identified in the gap analysis

5. **Validate** (every K generations): Run current best variant against the
   test set (20 scenarios). Track test-set performance separately. If test-set
   scores degrade while train-set scores improve, the mutations are
   overfitting to the training scenarios.

### Convergence

Stop when:

- Test-set improvement plateaus (<1% gain over 3 consecutive generations)
- Budget exhausted (total token spend or wall-clock time)
- All test-set scenarios pass (grade >= C, `overall_score` >= 0.7)

### Output

```text
/benchmarks/results/
  run-2026-07-15T14:00:00/
    config.json
    generations/
      gen-000/
        variant-0/
          train-results.json
          prompts/
          rules/
        variant-1/
          ...
      gen-001/
        ...
    best/
      prompts/              <-- winning prompt templates
      rules/                <-- winning detection rules
      train-results.json
      test-results.json
    convergence.csv         <-- generation, train_score, test_score, cost
```

`convergence.csv` is the headline chart for the talk:

```csv
generation,train_overall,train_technique_coverage,test_overall,test_technique_coverage,cost_usd
0,0.32,0.28,0.30,0.25,142.50
1,0.41,0.38,0.38,0.33,289.00
2,0.48,0.45,0.44,0.40,431.20
...
19,0.81,0.78,0.76,0.72,2841.00
```

## Implementation order

### Step 1: Loki export/import functions

Add `export_stream()` and `import_stream()` to
`ares-tools/src/blue/loki.rs`.

- `export_stream()`: paginated forward-scan through `query_range`, writes
  push-format JSONL directly to a `BufWriter<GzEncoder>`. Bypasses the
  existing 100-entry query cap. Uses the existing HTTP client, auth, and
  retry infrastructure.
- `import_stream()`: reads JSONL, batches into 1000-5000 entry groups,
  `POST`s to `/loki/api/v1/push` with gzip `Content-Encoding`. Respects
  429/503 backpressure with exponential backoff.

### Step 2: Snapshot capture CLI

New module `ares-cli/src/benchmark/` with `capture.rs`.

- Load operation metadata from Postgres (or NATS replay as fallback)
- Call `export_stream()` for each of the 11 log streams
- Call Grafana annotations API for fired alerts
- Generate ground truth via existing `create_ground_truth_from_red_state()`
- Write `manifest.json`
- Optional S3 sync via `aws s3 sync`

### Step 3: Ephemeral Loki + replay runner

New `.taskfiles/benchmark/Taskfile.yaml` with:

- `benchmark:loki-up`: Create ephemeral Loki K8s Job + Service
- `benchmark:loki-down`: Delete the Job
- `benchmark:load`: Import snapshot into ephemeral Loki
- `benchmark:run`: Full cycle (up, load, investigate, score, down)

New `ares-cli/src/benchmark/run.rs`:

- Orchestrates the full replay cycle
- Manages ephemeral Loki lifecycle via `kubectl` (or K8s API)
- Invokes blue team with `LOKI_URL` pointing at ephemeral instance
- Collects and saves evaluation results

### Step 4: Alert-based blue trigger

Modify `ares-cli/src/blue/submit.rs`:

- Add `--alert-trigger <path>` flag to `blue_from_operation()`
- Parse `fired-alerts.json`, extract earliest alert
- Set `attack_window_start` to alert fire time instead of operation start
- Include alert metadata in operation context

Minimal change to
`ares-llm/templates/blueteam/agents/initial_alert_prompt.md.tera`:

- When alert trigger metadata is present, include alert name and triggering
  query in the prompt context

### Step 5: Corpus generation

Run 100+ red team operations with varied parameters. Use the strategy system
(`docs/strategy.md`) to create diversity:

| Batch | Strategy | Techniques | Expected path |
|-------|----------|-----------|---------------|
| 1-25 | `fast` (default) | All | Kerberoast -> secretsdump -> DA |
| 26-50 | `stealth` | No spray, no relay | ADCS/ACL -> DA |
| 51-65 | `comprehensive` | All, continue after DA | Multiple paths |
| 66-80 | Custom | Exclude secretsdump | Forced ADCS/delegation |
| 81-90 | Custom | Delegation only | Constrained/unconstrained/RBCD |
| 91-100 | `fast` + high temp | All | Nondeterministic fast path |

Capture each with `ares benchmark capture`. Generate stratified train/test
splits.

### Step 6: GEPA optimization loop

New `ares-core/src/benchmark/` module:

- `population.rs`: variant management (prompts + rules + config per variant)
- `mutation.rs`: LLM-assisted prompt mutation from gap analysis
- `selection.rs`: fitness aggregation, elitism, tournament selection
- `optimize.rs`: generation loop, convergence checking, result tracking

New `ares-cli/src/benchmark/optimize.rs`: CLI wrapper for the loop.

## Key design decisions

### Why full Loki snapshots, not sanitized red-side data

The noise is part of the story. A real SOC analyst doesn't get a clean feed
of only attack-related events. They get the full firehose: routine logon
events, scheduled task noise, service restarts, group policy updates, DNS
queries, and somewhere in there, the attack. The blue team's job is to find
the signal in the noise. Sanitizing the data would make the benchmark
unrealistically easy.

### Why alert-based triggers, not attack-window-based triggers

The current `from-operation` mode hands the blue team the exact attack window
(`started_at` to `completed_at`). That's not a benchmark of detection -- it's
a benchmark of reading comprehension. In reality:

1. Red team starts attacking at T=0
2. Attack generates Windows events starting at T=0
3. A detection rule fires at T=X (minutes to hours later)
4. The SOC starts investigating from T=X, looking backwards
5. Finding T=0 is part of their job

The 77 Grafana alert rules already serve as the realistic canary tokens. The
auto-submit trigger (1 credential OR 2 hosts) is the right analogy: by the
time the red team has harvested a credential, there has been LSASS access,
Kerberoasting, SYSVOL enumeration, or similar -- and the corresponding alerts
have already fired.

### Why LLM-assisted mutation, not random mutation

Blue team prompts are natural language instructions. Random character-level
or token-level mutation would produce garbage. LLM-assisted mutation uses
the gap analysis reports (which identify specific missed techniques and IOCs)
to make targeted, semantically meaningful changes. The LLM acts as the
mutation operator: "you missed DCSync detection in 8/10 cases -- here is a
modified prompt that emphasizes Event 4662 monitoring."

### Why train/test splits matter

Without a held-out test set, the optimization loop will overfit to the
training scenarios. The blue team might learn to look for specific IP
addresses or usernames that happen to appear in the training data, rather
than learning generalizable investigation strategies. The test set catches
this: if training scores improve but test scores don't, the mutations are
memorizing rather than learning.

### Why ephemeral Loki, not a persistent replay instance

Each scenario needs a clean Loki with only its own data. If you share a Loki
instance across scenarios, log streams from different operations would mix,
and the blue team would see events from other attacks. The ephemeral pattern
(create, import, investigate, destroy) guarantees isolation. The cost is
~30 seconds of startup + import per scenario, which is negligible compared
to the 10-minute investigation runtime.

## Cost estimates

| Activity | Per unit | For 100 scenarios |
|----------|---------|-------------------|
| Red team operation | ~$5-15 LLM cost | $500-1,500 |
| Snapshot capture | ~$0 (API calls only) | ~$0 |
| Snapshot storage (S3) | ~50 MB per snapshot | 5 GB total, ~$0.12/month |
| Blue team investigation | ~$2-5 LLM cost | $200-500 per evaluation pass |
| GEPA generation (5 variants x 80 training) | 400 investigations | $800-2,000 |
| 20 generations | 8,000 investigations | $16,000-40,000 |
| Ephemeral Loki compute | ~2 vCPU-minutes per run | ~270 vCPU-hours, ~$25 |

The dominant cost is LLM inference during the GEPA loop. Reducing population
size (3 instead of 5) or training set size (40 instead of 80) cuts cost
proportionally. Early stopping on convergence avoids wasted generations.

## Infrastructure requirements

- EKS cluster: `dev-argonaut` (us-west-2, account 897722667582)
- Namespace: `attack-simulation` (admin RBAC via `AresEKSOperator`)
- Loki (production): `https://loki.dev.plundr.ai`
- Grafana: `https://grafana.dev.plundr.ai` with SA token
- S3 bucket: `ares-ops-archive-us-west-1` (existing, used by `archive_op_artifacts.py`)
- PostgreSQL: `ares-persistent-store-rw.attack-simulation.svc.cluster.local:5432/ares`
