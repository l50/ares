#!/usr/bin/env bash
# Shared SSM helpers for .taskfiles/ec2/Taskfile.yaml.
#
# Source from a task cmd block, then call the functions:
#     . .taskfiles/ec2/scripts/run-ssm.sh
#     INSTANCE_ID=$(resolve_instance "$EC2_NAME")
#     run_ssm_cmd "$INSTANCE_ID" "redis-cli ping" 30
#
# Required in the caller's environment: AWS_PROFILE, AWS_REGION.
#
# run_ssm_cmd contract:
#   - On success: writes StandardOutputContent to stdout, returns 0.
#   - On failure: prints an [ERROR] banner (with a PingStatus ConnectionLost
#     recovery hint when StatusDetails == Undeliverable), echoes any captured
#     stdout and StandardErrorContent to stderr, returns 1.
#   - Uses --timeout-seconds equal to the poll budget so SSM does not outlive
#     the local loop.

set -o pipefail

# resolve_instance <name-tag-glob>
#   Prints a single running InstanceId whose Name tag matches *<name>*.
#   Returns non-zero if nothing matches.
resolve_instance() {
	local name="$1"
	local instance_id
	instance_id=$(aws ec2 describe-instances \
		--profile "$AWS_PROFILE" \
		--region "$AWS_REGION" \
		--filters "Name=instance-state-name,Values=running" \
		"Name=tag:Name,Values=*${name}*" \
		--query "Reservations[*].Instances[*].InstanceId" \
		--output text | head -1)
	if [ -z "$instance_id" ]; then
		printf '\033[0;31m[ERROR]\033[0m No running instance found matching: %s\n' "$name" >&2
		return 1
	fi
	printf '%s' "$instance_id"
}

# resolve_targets <name-tag-glob>
#   Prints a comma-separated list of private IPs for running instances whose
#   Name tag matches *<name>* — e.g. `resolve_targets dreadgoad` returns the
#   dreadgoad DCs/SRVs but naturally excludes `kali-ares`. Returns non-zero
#   if nothing matches.
resolve_targets() {
	local name="$1"
	local ips
	ips=$(aws ec2 describe-instances \
		--profile "$AWS_PROFILE" \
		--region "$AWS_REGION" \
		--filters "Name=instance-state-name,Values=running" \
		"Name=tag:Name,Values=*${name}*" \
		--query "Reservations[*].Instances[*].PrivateIpAddress" \
		--output text | tr '[:space:]' '\n' | grep -v '^$' | sort -V | paste -sd, -)
	if [ -z "$ips" ]; then
		printf '\033[0;31m[ERROR]\033[0m No running instances found for range: %s\n' "$name" >&2
		return 1
	fi
	printf '%s' "$ips"
}

# run_ssm_cmd <instance_id> <payload> [timeout_seconds]
#   Ships <payload> to <instance_id> via AWS-RunShellScript, polls once/sec
#   until the command reaches a terminal state or <timeout_seconds> (default
#   120) elapses. Prints StandardOutputContent on success; on failure prints
#   a banner + captured output/stderr to fd 2 and returns 1.
run_ssm_cmd() {
	local instance_id="$1"
	local payload="$2"
	local timeout="${3:-120}"
	local params_file cmd_id status output details

	params_file=$(mktemp)
	jq -n --arg cmd "$payload" '{"commands": [$cmd]}' >"$params_file"

	cmd_id=$(aws ssm send-command \
		--profile "$AWS_PROFILE" \
		--region "$AWS_REGION" \
		--instance-ids "$instance_id" \
		--document-name "AWS-RunShellScript" \
		--parameters "file://$params_file" \
		--timeout-seconds "$timeout" \
		--query "Command.CommandId" --output text)

	rm -f "$params_file"

	status=""
	for _ in $(seq 1 "$timeout"); do
		status=$(aws ssm get-command-invocation \
			--profile "$AWS_PROFILE" \
			--region "$AWS_REGION" \
			--command-id "$cmd_id" \
			--instance-id "$instance_id" \
			--query "Status" --output text 2>/dev/null) || true
		case "$status" in
		Success | Failed | Cancelled | TimedOut) break ;;
		esac
		sleep 1
	done

	output=$(aws ssm get-command-invocation \
		--profile "$AWS_PROFILE" \
		--region "$AWS_REGION" \
		--command-id "$cmd_id" \
		--instance-id "$instance_id" \
		--query "StandardOutputContent" --output text)

	if [ "$status" != "Success" ]; then
		details=$(aws ssm get-command-invocation \
			--profile "$AWS_PROFILE" \
			--region "$AWS_REGION" \
			--command-id "$cmd_id" \
			--instance-id "$instance_id" \
			--query "StatusDetails" --output text 2>/dev/null)
		printf '\033[0;31m[ERROR]\033[0m SSM command failed (status: %s, details: %s)\n' "$status" "$details" >&2
		if [ "$details" = "Undeliverable" ]; then
			printf '\033[0;31m[ERROR]\033[0m SSM could not deliver the command to %s (PingStatus likely ConnectionLost).\n' "$instance_id" >&2
			printf '\033[0;31m[ERROR]\033[0m Recovery: reboot the instance ('\''aws ec2 reboot-instances --instance-ids %s'\'').\n' "$instance_id" >&2
		fi
		if [ -n "$output" ]; then
			printf '%s\n' "$output" >&2
		fi
		aws ssm get-command-invocation \
			--profile "$AWS_PROFILE" \
			--region "$AWS_REGION" \
			--command-id "$cmd_id" \
			--instance-id "$instance_id" \
			--query "StandardErrorContent" --output text >&2
		return 1
	fi

	printf '%s' "$output"
}
