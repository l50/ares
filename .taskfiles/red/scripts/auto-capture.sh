#!/usr/bin/env bash
# Auto-capture backgrounder for red:ec2:multi.
#
# Polls `ares --ec2 … ops status <op-id>` every 30s until the op reports
# completed=true, then invokes `ares benchmark capture <op-id>` LOCALLY (not
# via --ec2) so the aws CLI it spawns uses the operator's SSO creds. The box
# has no `infrastructure` AWS profile (it authenticates via EC2 instance
# role), and capture hardcodes `--profile infrastructure` for Loki S3 chunk
# access; running capture on the box therefore always fails at the S3 flush
# check. Capture reads Redis via a short-lived SSM port-forward that the
# script spawns and tears down around the capture invocation.
#
# Called from .taskfiles/red/Taskfile.yaml ec2:multi. Detached via
# `bash -c 'nohup … &'` because go-task's default shell interpreter
# (mvdan.cc/sh) doesn't preserve `&` background jobs across the cmd
# boundary; a standalone shell script is the cleanest fix.
#
# Runs to a 3-hour wall-clock deadline: op hard-cap is 2× the configured
# red budget, Loki flush adds another 30-60m.
#
# Positional args: <op-id> <ec2-name> <aws-profile> <aws-region> <ares-cli-bin>

set -u

OP_ID="${1:?op-id required}"
EC2_NAME="${2:?ec2-name required}"
AWS_PROFILE_VAL="${3:?aws-profile required}"
AWS_REGION_VAL="${4:?aws-region required}"
ARES_CLI_BIN="${5:?ares-cli required}"

# Local port for the Redis SSM tunnel. Matches the ec2:redis:forward task's
# convention so an operator-established tunnel can be reused if it happens
# to already be up (16379 = "1" prefix + Redis's 6379 default).
LOCAL_REDIS_PORT=16379
# Profile that carries Loki S3 chunk read access. Must exist in the
# operator's ~/.aws/config, populated by SSO login. Not the same as the
# lab profile used for SSM to kali-ares.
LOKI_S3_PROFILE="infrastructure"

DEADLINE=$(($(date +%s) + 10800))

echo "[$(date -u +%FT%TZ)] auto-capture: waiting for op $OP_ID to complete (deadline in 3h)"

while [ "$(date +%s)" -lt "$DEADLINE" ]; do
	STATUS=$("$ARES_CLI_BIN" --ec2 "$EC2_NAME" --ec2-profile "$AWS_PROFILE_VAL" --ec2-region "$AWS_REGION_VAL" \
		ops status "$OP_ID" 2>&1 || true)
	# `ares ops status` prints a "Status: <state>" line where state is
	# `running` while active and `completed` after the completion monitor
	# releases (either naturally or via `ares ops stop`).
	if echo "$STATUS" | grep -qiE '^[[:space:]]*Status:[[:space:]]*completed[[:space:]]*$'; then
		echo "[$(date -u +%FT%TZ)] op complete; preparing local capture invocation"

		# Resolve the box's instance-id for the Redis tunnel target.
		INSTANCE_ID=$(AWS_PROFILE="$AWS_PROFILE_VAL" AWS_REGION="$AWS_REGION_VAL" \
			aws ec2 describe-instances \
			--filters "Name=instance-state-name,Values=running" \
			"Name=tag:Name,Values=*${EC2_NAME}*" \
			--query "Reservations[*].Instances[*].InstanceId" \
			--output text 2>/dev/null | head -1)
		if [ -z "${INSTANCE_ID:-}" ]; then
			echo "[$(date -u +%FT%TZ)] ERROR: could not resolve instance id for $EC2_NAME"
			exit 2
		fi
		echo "[$(date -u +%FT%TZ)] resolved $EC2_NAME → $INSTANCE_ID"

		# Reuse an existing tunnel on LOCAL_REDIS_PORT if one is up, else
		# spawn a fresh SSM port-forward we'll tear down when capture ends.
		SPAWNED_TUNNEL_PID=""
		if lsof -iTCP:"$LOCAL_REDIS_PORT" -sTCP:LISTEN >/dev/null 2>&1; then
			echo "[$(date -u +%FT%TZ)] reusing existing tunnel on localhost:$LOCAL_REDIS_PORT"
		else
			echo "[$(date -u +%FT%TZ)] starting SSM Redis tunnel localhost:$LOCAL_REDIS_PORT → $INSTANCE_ID:6379"
			AWS_PROFILE="$AWS_PROFILE_VAL" AWS_REGION="$AWS_REGION_VAL" \
				aws ssm start-session \
				--target "$INSTANCE_ID" \
				--document-name "AWS-StartPortForwardingSession" \
				--parameters "{\"portNumber\":[\"6379\"],\"localPortNumber\":[\"$LOCAL_REDIS_PORT\"]}" \
				</dev/null >/tmp/auto-capture-tunnel-"$OP_ID".log 2>&1 &
			SPAWNED_TUNNEL_PID=$!
			# Wait up to 15s for the tunnel to accept a TCP connection.
			for _ in $(seq 1 15); do
				if nc -z localhost "$LOCAL_REDIS_PORT" 2>/dev/null; then
					break
				fi
				sleep 1
			done
			if ! nc -z localhost "$LOCAL_REDIS_PORT" 2>/dev/null; then
				echo "[$(date -u +%FT%TZ)] ERROR: tunnel didn't come up within 15s"
				if [ -n "$SPAWNED_TUNNEL_PID" ]; then
					kill "$SPAWNED_TUNNEL_PID" 2>/dev/null || true
				fi
				exit 3
			fi
		fi

		echo "[$(date -u +%FT%TZ)] firing local capture (waits for Loki flush ~30-60m)"
		# Wait-for-flush is the default in `ares benchmark capture`; the
		# explicit flag is `--no-wait-for-flush` (opt-out).
		# ARES_REDIS_URL points at the SSM tunnel; AWS_PROFILE=infrastructure
		# scopes the aws CLI capture spawns for the Loki S3 chunk read.
		ARES_REDIS_URL="redis://localhost:$LOCAL_REDIS_PORT" \
			AWS_PROFILE="$LOKI_S3_PROFILE" \
			"$ARES_CLI_BIN" benchmark capture "$OP_ID" --output-dir benchmarks/
		RC=$?
		echo "[$(date -u +%FT%TZ)] capture exited rc=$RC"

		# Tear down the tunnel we spawned; leave operator-established
		# tunnels alone.
		if [ -n "$SPAWNED_TUNNEL_PID" ]; then
			kill "$SPAWNED_TUNNEL_PID" 2>/dev/null || true
		fi
		exit "$RC"
	fi
	sleep 30
done

echo "[$(date -u +%FT%TZ)] deadline reached without op completion; giving up"
exit 1
