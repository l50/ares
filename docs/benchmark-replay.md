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
Call `task benchmark:replay` for the end-to-end flow, or drive
`replay:provision` / `run` / `replay:teardown` individually.

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
ares benchmark run op-20260706-123045 \
  --stack-ip "$STACK_IP" \
  --replay-mode timeline \
  --max-steps 75 \
  --output-dir ./reports

# Teardown when done
task benchmark:replay:teardown INSTANCE_ID="$INSTANCE_ID"
```

### Replay modes

- `timeline` (default) — a quiet period precedes the first alert, trigger uses
  `alert-replay` (no attack-window end handed to the agent), simulating an
  unfolding attack. This is the realistic mode.
- `static` — all data pre-loaded, agent knows the full attack window upfront.
  Convenient but less realistic.

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
