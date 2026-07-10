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

# How long to keep polling for a refreshed SSO token once the current one
# expires. 30 minutes gives the operator enough time to notice the
# desktop notification (or find the log) and run `aws sso login` in
# another terminal without the capture giving up on the S3 flush wait
# already in flight.
SSO_REFRESH_WAIT_SECS=1800
# Interval between `aws sts get-caller-identity` re-checks while waiting
# for the operator to refresh. 30s is short enough that a fresh login
# unblocks the capture within the same terminal breath.
SSO_REFRESH_POLL_SECS=30

DEADLINE=$(($(date +%s) + 10800))

# Emit a desktop notification when SSO expires mid-run. macOS operators
# see it above the task bar without watching the nohup log; other
# platforms silently no-op (`osascript` and `notify-send` failures are
# swallowed so the capture keeps polling either way).
notify_operator() {
	local title="$1"
	local body="$2"
	if command -v osascript >/dev/null 2>&1; then
		osascript -e "display notification \"${body//\"/\\\"}\" with title \"${title//\"/\\\"}\"" \
			>/dev/null 2>&1 || true
	fi
	if command -v notify-send >/dev/null 2>&1; then
		notify-send "$title" "$body" >/dev/null 2>&1 || true
	fi
}

# Return 0 when `$LOKI_S3_PROFILE` has a live SSO/STS session, non-zero
# when the token is expired or missing. Silences stderr because a valid
# check has no output; expired tokens surface via the boolean return.
# Uses `sts get-caller-identity` rather than an SSO-specific probe so it
# also catches an unexpired-but-permissioned-away credential.
check_sso_valid() {
	AWS_PROFILE="$LOKI_S3_PROFILE" AWS_REGION="$AWS_REGION_VAL" \
		aws sts get-caller-identity >/dev/null 2>&1
}

# Poll for SSO refresh, giving the operator a window to run
# `aws sso login --profile <profile>` in another terminal. Emits one
# notification when the wait starts (nohup context has no TTY, so the
# operator is unlikely to be watching the log) and re-checks every
# `SSO_REFRESH_POLL_SECS` seconds. Returns 0 on refresh, non-zero if the
# wait window elapses without a fresh token — the caller then decides
# whether to bail or continue with a degraded plan.
wait_for_sso_refresh() {
	local reason="$1"
	local wait_deadline=$(($(date +%s) + SSO_REFRESH_WAIT_SECS))
	local human_wait=$((SSO_REFRESH_WAIT_SECS / 60))
	echo "[$(date -u +%FT%TZ)] SSO stale ($reason); waiting up to ${human_wait}m for" \
		"'aws sso login --profile $LOKI_S3_PROFILE'"
	notify_operator \
		"Ares auto-capture blocked on SSO" \
		"Run: aws sso login --profile $LOKI_S3_PROFILE (op $OP_ID)"
	while [ "$(date +%s)" -lt "$wait_deadline" ]; do
		if check_sso_valid; then
			echo "[$(date -u +%FT%TZ)] SSO refreshed for $LOKI_S3_PROFILE — resuming"
			return 0
		fi
		sleep "$SSO_REFRESH_POLL_SECS"
	done
	echo "[$(date -u +%FT%TZ)] ERROR: SSO not refreshed within ${human_wait}m; giving up"
	notify_operator \
		"Ares auto-capture gave up" \
		"SSO for $LOKI_S3_PROFILE never refreshed (op $OP_ID)"
	return 1
}

echo "[$(date -u +%FT%TZ)] auto-capture: waiting for op $OP_ID to complete (deadline in 3h)"

# Pre-flight the SSO token: if it's stale before we even start the poll
# loop, the operator would rather know now than after the op runs for
# 90 minutes and the Loki flush wait crashes with "Token has expired".
if ! check_sso_valid; then
	if ! wait_for_sso_refresh "pre-flight check"; then
		exit 4
	fi
fi

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
		#
		# Capture output is teed so we can grep it for a specific SSO
		# expiry signature — the flush-wait fires aws CLI calls repeatedly
		# for 30-60m and the operator's SSO token may expire mid-wait even
		# if pre-flight passed. On that specific failure we retry once
		# after waiting for the operator to `aws sso login`; other errors
		# fall through unchanged.
		CAPTURE_LOG="/tmp/auto-capture-run-$OP_ID.log"
		: >"$CAPTURE_LOG"
		ARES_REDIS_URL="redis://localhost:$LOCAL_REDIS_PORT" \
			AWS_PROFILE="$LOKI_S3_PROFILE" \
			"$ARES_CLI_BIN" benchmark capture "$OP_ID" --output-dir benchmarks/ \
			2>&1 | tee -a "$CAPTURE_LOG"
		RC=${PIPESTATUS[0]}
		echo "[$(date -u +%FT%TZ)] capture exited rc=$RC"
		# The SSO expiry signature the aws CLI emits from botocore is
		# stable across recent versions (observed 2026-07-09 / 07-10 in
		# logs/local-capture-op-*.log). Match exactly that message so a
		# generic non-SSO failure (network, S3 access denied, tunnel
		# drop) is NOT wrongly retried under the SSO refresh path.
		if [ "$RC" -ne 0 ] && grep -qE \
			"Token has expired and refresh failed|ExpiredToken|Error loading SSO Token" \
			"$CAPTURE_LOG"; then
			echo "[$(date -u +%FT%TZ)] capture died on SSO expiry — attempting one refresh + retry"
			if wait_for_sso_refresh "capture aborted mid-flush"; then
				: >"$CAPTURE_LOG"
				ARES_REDIS_URL="redis://localhost:$LOCAL_REDIS_PORT" \
					AWS_PROFILE="$LOKI_S3_PROFILE" \
					"$ARES_CLI_BIN" benchmark capture "$OP_ID" --output-dir benchmarks/ \
					2>&1 | tee -a "$CAPTURE_LOG"
				RC=${PIPESTATUS[0]}
				echo "[$(date -u +%FT%TZ)] capture retry exited rc=$RC"
			fi
		fi

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
