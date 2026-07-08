# Benchmark Replay

Deterministic evaluation for the blue team: capture a completed red-team op's
observability state, stand up a self-contained observability stack from that
snapshot, and run a fresh blue investigation against it. The replay is what
makes iterative blue-side improvements comparable across runs.

The workflow has three concerns, split cleanly across three surfaces:

| Concern                        | Where it lives                                                                          |
| ------------------------------ | --------------------------------------------------------------------------------------- |
| Snapshot capture from a real op | `ares benchmark capture` (Rust)                                                        |
| Replay-stack EC2 lifecycle      | `.taskfiles/benchmark/Taskfile.yaml` (AWS CLI)                                          |
| Blue investigation + scoring    | `ares benchmark run` (Rust) against a pre-provisioned `--stack-ip`                     |

`ares benchmark run` no longer provisions EC2 — provisioning is Taskfile-driven.
Call `task benchmark:replay` for the end-to-end flow, `task benchmark:replay:run`
against a stack you provisioned yourself, or `task benchmark:replay:loop` for
tuning workflows that reuse one warm stack across many iterations.

The tuning corpus (what a prompt-search or Vibe Gepa driver iterates on) is
whatever the driver picks; the held-out corpus for generalization scoring
lives at `benchmarks/holdout.yaml` and is swept by `task benchmark:generalize`.
Keep the two lists physically separate so no tuning loop can silently train
on the eval set.

## Prerequisites

The taskfile reads these from `.env` (copy `.env.example`) or the shell:

| Variable                        | Required | Purpose                                                                 |
| ------------------------------- | -------- | ----------------------------------------------------------------------- |
| `BENCHMARK_SECURITY_GROUP_ID`   | yes      | SG opening 3000/3100/9090/3200 from the investigator host               |
| `BENCHMARK_INSTANCE_PROFILE`    | yes      | IAM role granting S3 read on the snapshot bucket                        |
| `BENCHMARK_SUBNET_ID`           | yes      | Subnet reachable from wherever `ares benchmark run` executes            |
| `BENCHMARK_S3_BUCKET`           | no       | Snapshot bucket. Defaults to `ares-benchmark-us-west-1`                 |
| `BENCHMARK_AWS_REGION`          | no       | Defaults to `us-west-1`                                                 |
| `BENCHMARK_INSTANCE_TYPE`       | no       | Defaults to `t3.medium`                                                 |
| `BENCHMARK_AMI_ID`              | no       | Pin a specific AMI (bypasses tag lookup and stock fallback)             |
| `BENCHMARK_REQUIRE_BAKED_AMI`   | no       | Set to `1` to fail if no `ares-replay-stack` AMI exists (skip fallback) |
| `BENCHMARK_SKIP_STACK_VERIFY`   | no       | Set to `1` when the caller cannot reach the private stack (e.g. laptop) |
| `ARES_SECRETS_ID`               | no       | Secrets Manager id for LLM keys during EC2 re-exec. Default `ares/api-keys` |

## Capture a snapshot

Capture from a completed operation. `--wait-for-flush` blocks until Loki's
ingester flushes the attack window to S3 (~30–60 min latency) — without it,
capturing right after an op silently misses the attack logs.

```bash
# Manual capture from any op
ares benchmark capture op-20260706-123045 \
  --wait-for-flush \
  --flush-timeout-mins 60 \
  --attacker-ips 192.168.58.240

# Auto-capture at the end of an EC2 op (opt-in via CAPTURE=true on the wait task)
task ec2:wait EC2_NAME=kali-ares OPERATION_ID=op-20260706-123045 CAPTURE=true
```

Capture writes to `benchmarks/<op-id>/` by default and uploads to
`s3://<bucket>/snapshots/<op-id>/` unless `--no-upload` is set. It also
pre-builds Prometheus TSDB blocks at capture time so replay avoids the
multi-minute OpenMetrics conversion.

Attacker IPs are stored as required IOCs the blue team is scored against —
supply them because they don't live in the target-centric red state.

## List captured snapshots

```bash
ares benchmark list
```

Reads `s3://<bucket>/snapshots/*/manifest.json` and prints operation id,
domain, timestamp, techniques, credential count, and whether Domain Admin
was reached.

## Run a replay

### End-to-end (recommended)

Provisions the stack, runs the investigation, and tears the stack down on
exit. Cleanup is a shell `trap` so it fires even on Ctrl-C or a failed run.

```bash
task benchmark:replay OP_ID=op-20260706-123045

# With overrides
task benchmark:replay \
  OP_ID=op-20260706-123045 \
  SNAPSHOT_DIR=./benchmarks/op-20260706-123045 \
  MODEL=openai/gpt-5.2 \
  MAX_STEPS=75 \
  REPLAY_MODE=timeline \
  TRIGGER_MODE=alert-replay \
  TIME_COMPRESSION=10 \
  OUTPUT_DIR=./reports
```

If `SNAPSHOT_DIR` is omitted, `ares benchmark run` downloads the snapshot
from S3 into a temp dir.

### Split flow (debugging or repeated runs against one stack)

```bash
# Provision — captures STACK_IP and INSTANCE_ID from stdout
eval "$(task benchmark:replay:provision OP_ID=op-20260706-123045 | grep -E '^(STACK_IP|INSTANCE_ID)=')"

# Run — as many times as you want against the same stack
task benchmark:replay:run \
  STACK_IP="$STACK_IP" \
  OP_ID=op-20260706-123045 \
  MAX_STEPS=75 \
  OUTPUT_DIR=./reports

# Teardown when done
task benchmark:replay:teardown INSTANCE_ID="$INSTANCE_ID"
```

`benchmark:replay:run` forwards `SNAPSHOT_DIR`, `MODEL`, `MAX_STEPS`,
`OUTPUT_DIR`, `QUIET_PERIOD`, `CLOCK`, `REPLAY_MODE`, and `TRIGGER_MODE` to
`ares benchmark run`. For flags the Taskfile does not forward
(`--seed`, `--temperature`, `--replicates`), call `ares benchmark run`
directly against the same `--stack-ip`.

### Tuning loop (warm stack across N iterations)

For a prompt-search / Vibe Gepa driver iterating on the same op: provision
once, run N times, tear down once. `HOOK` runs between iterations (not after
the last) with `STACK_IP`, `OP_ID`, and `ITERATION` exported so the driver
can rewrite prompts or config in place.

```bash
task benchmark:replay:loop \
  OP_ID=op-20260706-123045 \
  ITERATIONS=8 \
  HOOK='python -m vibe_gepa.update --op-id "$OP_ID" --iter "$ITERATION"'
```

Failure semantics:

- A single `replay:run` failure counts against a warning tally but does NOT
  abort the loop — K-of-N averaging still works if one iteration flakes.
- A `HOOK` failure IS fatal — subsequent iterations against a broken tuning
  update would be meaningless.

Omit `HOOK` to just repeat the same investigation N times — the built-in
form of K-of-N averaging.

### Deterministic scoring and replicates (`ares benchmark run`)

LLM sampling adds run-to-run variance. Two knobs on `ares benchmark run`
help distinguish a real score change from noise:

| Flag | Purpose |
| ---- | ------- |
| `--seed <u64>` | Best-effort deterministic sampling. Passed to providers that honour it (OpenAI); providers that ignore it (Anthropic, Ollama) log a warning and continue with default sampling. When set without `--temperature`, temperature is forced to `0.0`. |
| `--temperature <f32>` | Override the provider default. `0.0` = greedy decoding. Unset ⇒ provider default (typically `1.0`). |
| `--replicates <K>` | K independent investigations against the same stack. The stack is NOT reprovisioned per replicate; each replicate gets its own `run_id`. |

With `--replicates > 1`, in addition to the per-run JSON at
`<output-dir>/<run_id>.json`, a session summary lands at
`<output-dir>/<session_stem>-summary.json` with `replicate_count`, `mean`,
`stddev` (n-1 denominator), `min`, `max`, the raw `scores` array, and a
`replicates` array with per-run metadata. `K=1` writes only the single
per-run JSON — no summary — so existing callers see identical output.

```bash
# 5 replicates, seeded so temperature is forced to 0 and each replicate
# samples the same way at each turn
ares benchmark run op-20260706-123045 \
  --stack-ip "$STACK_IP" \
  --replicates 5 \
  --seed 42 \
  --output-dir ./reports
```

Replicates run sequentially, not in parallel — running them in parallel
would multiply in-process evidence-store state and interfere with the
shared tool dispatcher.

### Replay modes

- `timeline` (default) — a quiet period precedes the first alert, trigger uses
  `alert-replay` (no attack-window end handed to the agent), simulating an
  unfolding attack. This is the realistic mode.
- `static` — all data pre-loaded, agent knows the full attack window upfront.
  Convenient but less realistic.

## Generalization sweep

Any tuning process (prompt search, config iteration, Vibe Gepa, RL rollouts)
will fit to whatever corpus it sees. To measure whether an improvement
generalizes, sweep a held-out set the tuning process never touched.

`benchmarks/holdout.yaml` is that set. It's hand-curated and physically
separate from the tuning corpus so nothing auto-populates it from recent ops.

```bash
task benchmark:generalize                                # sweep with defaults
task benchmark:generalize OUTPUT_DIR=./reports/gen       # custom output dir
task benchmark:generalize HOLDOUT=benchmarks/other.yaml  # alternate corpus
task benchmark:generalize FAIL_UNDER=0.6                 # fail if mean < 0.6
```

The task iterates each entry via `task benchmark:replay`, collects the
`evaluation.overall_score` from each investigation report, prints a summary
table, and writes `$OUTPUT_DIR/generalize-summary.json` with per-op scores
plus mean and median. Per-op failures are non-fatal so one broken snapshot
doesn't sink the whole sweep; failures are recorded in the summary. Set
`FAIL_UNDER=<float>` to gate CI on the aggregate mean.

Curate `benchmarks/holdout.yaml` manually: pick 3–5 ops covering distinct
attack classes (ADCS ESC1, kerberoast, MSSQL linked servers, constrained
delegation, NTLM relay, etc.). Do not populate it from your most recent ops
— tuning drivers routinely see the latest ops and would silently retrain on
the eval set. The file's top-of-file comment restates this contract.

## The replay-stack AMI

Provisioning prefers a pre-baked `ares-replay-stack` AMI (AL2023 + Docker +
docker-compose + the six observability images baked in, plus the stack config
staged at `/opt/replay-stack/`). Skipping the multi-minute Docker install and
image pulls cuts provision time by ~5–10 min per replay.

### Build the AMI

Requires warpgate ≥ v4.7.0. One-time lab-account prerequisites:

- IAM role + instance profile `warpgate-imagebuilder` with
  `EC2InstanceProfileForImageBuilder` (grants SSM + S3 read on the staging bucket).
- An S3 bucket to stage the file provisioner content into. The lab account
  already has `ec2imagebuilder-warpgate-381491903301-us-west-1`.

Point the global warpgate config at those (one-time):

```bash
warpgate config set aws.ami.instance_profile_name warpgate-imagebuilder
warpgate config set aws.ami.file_staging_bucket   ec2imagebuilder-warpgate-381491903301-us-west-1
warpgate config set aws.region                    us-west-1
warpgate config set aws.profile                   lab
```

Then build (~15 min — installs Docker, pulls the six observability images, stages
`benchmarks/replay-stack/` into `/opt/replay-stack/`, snapshots):

```bash
aws sso login --profile lab

AWS_REGION=us-west-1 AWS_PROFILE=lab \
  warpgate build \
    --target ami \
    --stream-logs \
    --show-ec2-status \
    warpgate-templates/templates/ares-replay-stack/warpgate.yaml
```

Validate the template first with `--dry-run` if you're not sure the config is
right. The final AMI lands in `us-west-1` tagged
`ares:component=benchmark-replay-stack` and is picked up automatically by
`task benchmark:replay:provision`.

Check which AMI provisioning would select:

```bash
task benchmark:replay:ami:current
```

### Version pinning

Two version lists must stay in sync:

1. `benchmarks/replay-stack/docker-compose.yml` — source of truth for image tags.
2. `warpgate-templates/templates/ares-replay-stack/warpgate.yaml` — `docker pull`
   list plus the `docker-compose` plugin version.

Drift means the bake caches the wrong tags and the runtime box re-pulls at
replay, defeating the point.

If no baked AMI is available, provisioning falls back to stock AL2023 and
installs Docker + pulls images + copies stack config from
`s3://<bucket>/benchmark-stack/replay-stack.tar.gz`. Set
`BENCHMARK_REQUIRE_BAKED_AMI=1` to fail loudly instead.

## Troubleshooting

**Provision hangs on stack verify from a laptop.** The security group only
opens the stack ports to the investigator subnet, so a laptop outside the VPC
can't reach `http://<stack-ip>:3000/api/health`. Set
`BENCHMARK_SKIP_STACK_VERIFY=1` and let the investigator host verify.

**Capture ended fast with a thin log set.** You skipped `--wait-for-flush`.
Loki flushes with ~30–60 min ingester latency; re-run
`ares benchmark capture <op-id> --wait-for-flush` — capture is idempotent.

**Teardown failed and the stack is still up.** The taskfile tags failed
instances `ares:orphan=true`. Sweep them:

```bash
aws ec2 describe-instances \
  --filters "Name=tag:ares:component,Values=benchmark-replay" \
            "Name=instance-state-name,Values=running" \
  --query 'Reservations[].Instances[].[InstanceId,Tags[?Key==`ares:operation`]|[0].Value]' \
  --output table
```

**LLM keys missing on the replay box after `--ec2` re-exec.** `ares` calls
`load_secrets_manager_secrets()` in `ares-cli/src/secrets.rs`, which pulls
`OPENAI_API_KEY` / `ANTHROPIC_API_KEY` from Secrets Manager id `ARES_SECRETS_ID`
(default `ares/api-keys`). Confirm the instance profile grants
`secretsmanager:GetSecretValue` on that id.
