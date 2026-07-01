#!/bin/bash
# Show ares process status on EC2

echo "=== Redis ==="
redis-cli ping 2>/dev/null && redis-cli info server 2>/dev/null | grep -E "redis_version|uptime_in_seconds|connected_clients" || echo "Redis not running"
echo ""

echo "=== NATS ==="
if curl -fsS http://127.0.0.1:8222/varz 2>/dev/null | grep -E '"version"|"now"|"connections"' | head -3; then
	curl -fsS http://127.0.0.1:8222/jsz 2>/dev/null | grep -E '"streams"|"messages"|"bytes"' | head -3 || true
else
	echo "NATS not running"
fi
echo ""

echo "=== Dispatch mode ==="
echo "  in-process (ARES_TOOL_DISPATCH=local) — no separate worker fleet"
echo ""

echo "=== Orchestrator ==="
ORCH_PID=$(pgrep -f 'ares orchestrator' 2>/dev/null || true)
if [ -n "$ORCH_PID" ]; then
	echo "  Running (PID: $ORCH_PID)"
	ps -p "$ORCH_PID" -o etime=,args= 2>/dev/null | head -1
else
	echo "  Not running"
fi
echo ""

echo "=== Disk ==="
df -h / | tail -1
echo ""

echo "=== Logs ==="
ls -lhS /var/log/ares/ 2>/dev/null || echo "  No log directory"
