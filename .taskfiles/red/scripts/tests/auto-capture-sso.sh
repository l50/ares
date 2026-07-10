#!/usr/bin/env bats
# Smoke tests for auto-capture.sh SSO expiry handling.
#
# The script's control flow is dominated by three helpers extracted so
# they can be sourced and unit-tested without spawning the full poll
# loop: `check_sso_valid`, `notify_operator`, and `wait_for_sso_refresh`.
# These tests stub `aws` and `command` on PATH so no real AWS or desktop
# notifications are involved.
#
# Run: bats .taskfiles/red/scripts/tests/auto-capture-sso.bats

SCRIPT="$BATS_TEST_DIRNAME/../auto-capture.sh"

# Extract the helper functions from the script without executing its
# top-level polling loop. The functions are defined before the loop
# starts, so a sed cut through `^echo .*waiting for op` gives us the
# runnable helpers.
setup() {
	TMP_STUBS="$(mktemp -d)"
	# Fast defaults so tests don't sleep for real.
	export SSO_REFRESH_WAIT_SECS=2
	export SSO_REFRESH_POLL_SECS=1
	export AWS_REGION_VAL="us-east-1"
	export LOKI_S3_PROFILE="infrastructure"
	export OP_ID="op-test"
	# Extract only the function definitions from the script. The `awk`
	# state machine looks for lines matching `^word() {` or `^word ()`
	# and copies everything up to the matching top-level `}`. This
	# avoids picking up the positional-arg checks (`EC2_NAME=${2:?…}`)
	# or the polling loop at the top of the script.
	awk '
		/^[a-z_][a-z_0-9]*\(\)[[:space:]]*\{[[:space:]]*$/ {in_fn=1}
		in_fn {print}
		in_fn && /^\}[[:space:]]*$/ {in_fn=0; print ""}
	' "$SCRIPT" >"$TMP_STUBS/helpers.sh"
	# shellcheck source=/dev/null
	source "$TMP_STUBS/helpers.sh"
}

teardown() {
	rm -rf "$TMP_STUBS"
}

# Stub `aws` with a scripted exit code. Optional stdout via $2.
stub_aws() {
	local exit_code="$1"
	local out="${2:-}"
	cat >"$TMP_STUBS/aws" <<EOF
#!/usr/bin/env bash
[ -n "$out" ] && echo "$out"
exit $exit_code
EOF
	chmod +x "$TMP_STUBS/aws"
	export PATH="$TMP_STUBS:$PATH"
}

# Stub `aws` that returns non-zero for the first $1 invocations then 0.
# Uses a counter file so the process-per-call semantics are honored.
stub_aws_after() {
	local fail_count="$1"
	local counter_file="$TMP_STUBS/counter"
	echo 0 >"$counter_file"
	cat >"$TMP_STUBS/aws" <<EOF
#!/usr/bin/env bash
count=\$(cat "$counter_file")
count=\$((count + 1))
echo \$count > "$counter_file"
if [ "\$count" -le "$fail_count" ]; then
	exit 255
fi
exit 0
EOF
	chmod +x "$TMP_STUBS/aws"
	export PATH="$TMP_STUBS:$PATH"
}

# Silence desktop notifiers unconditionally.
stub_notifiers_absent() {
	cat >"$TMP_STUBS/command" <<'EOF'
#!/usr/bin/env bash
# Report osascript / notify-send as missing so notify_operator no-ops.
[ "$2" = "osascript" ] && exit 1
[ "$2" = "notify-send" ] && exit 1
/usr/bin/command "$@"
EOF
	chmod +x "$TMP_STUBS/command"
	export PATH="$TMP_STUBS:$PATH"
}

@test "check_sso_valid returns 0 when aws sts succeeds" {
	stub_aws 0
	run check_sso_valid
	[ "$status" -eq 0 ]
}

@test "check_sso_valid returns non-zero when aws sts fails" {
	stub_aws 255
	run check_sso_valid
	[ "$status" -ne 0 ]
}

@test "wait_for_sso_refresh returns 0 when SSO becomes valid mid-wait" {
	# aws fails for one probe then succeeds — must return 0 quickly.
	stub_aws_after 1
	stub_notifiers_absent
	SSO_REFRESH_WAIT_SECS=10 SSO_REFRESH_POLL_SECS=1 \
		run wait_for_sso_refresh "test reason"
	[ "$status" -eq 0 ]
}

@test "wait_for_sso_refresh returns non-zero when SSO never refreshes" {
	# aws always fails — wait window expires without a refresh.
	stub_aws 255
	stub_notifiers_absent
	SSO_REFRESH_WAIT_SECS=2 SSO_REFRESH_POLL_SECS=1 \
		run wait_for_sso_refresh "never refreshed"
	[ "$status" -ne 0 ]
	# The give-up log line surfaces the reason so operators can grep
	# it in the nohup log.
	echo "$output" | grep -qE "never refreshed"
}

@test "notify_operator no-ops when neither notifier is on PATH" {
	stub_notifiers_absent
	run notify_operator "title" "body"
	# The helper swallows all notifier failures; must not propagate.
	[ "$status" -eq 0 ]
}
