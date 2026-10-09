#!/usr/bin/env bash
# Beacon acceptance harness: boots one agent per transport mode against a
# running teamserver, waits for check-in, executes a command through the
# control plane and verifies the output.
#
# Usage: scripts/beacon-acceptance.sh <mode> [session|beacon|quic|dns|wireguard|fallback]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${SHIKRA_BEACON_WORK:?set SHIKRA_BEACON_WORK to the test work dir}"
MODE="${1:?usage: beacon-acceptance.sh <session|beacon|quic|dns|wireguard|fallback>}"
IMPLANT="${SHIKRA_IMPLANT_BIN:-$ROOT/target/debug/shikra-implant}"
CLIENT="${SHIKRA_CLIENT_BIN:-$ROOT/target/debug/shikra-client}"

BOOT="$WORK/bootstrap.json"
STATE="$WORK/state"
ENROLL=$(jq -r .enroll_token "$BOOT")
IDENTITY=$(jq -r .server_identity_hex "$BOOT")

export SHIKRA_SERVER=$(jq -r '.grpc_url // "https://127.0.0.1:29443"' "$BOOT" 2>/dev/null || echo "https://127.0.0.1:29443")
export SHIKRA_CA_CERT="$STATE/ca.pem"
export SHIKRA_OPERATOR_TOKEN=$(jq -r .operator_token "$BOOT")

# Snapshot existing sessions so we only accept a newly checked-in agent.
PRIOR=$("$CLIENT" sessions 2>/dev/null | awk -F'\t' 'NF>=5 {print $1}' | sort)

HTTP_URL="http://127.0.0.1:29080"
QUIC_URL="127.0.0.1:29444"
DNS_URL="127.0.0.1:25353"
WG_URL="127.0.0.1:25182"
WG_PUB=$(cat "$WORK/wg_public" 2>/dev/null || echo "")

LOG="$WORK/logs/agent-$MODE.log"
rm -f "$LOG"

common=(--enroll-token "$ENROLL" --ca-cert "$STATE/ca.pem" --server-identity-hex "$IDENTITY")

case "$MODE" in
  session)
    "$IMPLANT" --mode session --c2-url "https://127.0.0.1:29443" \
      "${common[@]}" --heartbeat-secs 2 --max-runtime-secs 120 >"$LOG" 2>&1 &
    ;;
  beacon)
    "$IMPLANT" --mode beacon --http-url "$HTTP_URL" \
      "${common[@]}" --poll-interval-secs 2 --jitter-secs 0 --max-runtime-secs 120 >"$LOG" 2>&1 &
    ;;
  quic)
    "$IMPLANT" --mode quic --quic-url "$QUIC_URL" \
      "${common[@]}" --poll-interval-secs 2 --jitter-secs 0 --max-runtime-secs 120 >"$LOG" 2>&1 &
    ;;
  dns)
    "$IMPLANT" --mode dns --dns-url "$DNS_URL" --dns-zone dns.shikra \
      "${common[@]}" --poll-interval-secs 2 --jitter-secs 0 --max-runtime-secs 120 >"$LOG" 2>&1 &
    ;;
  wireguard)
    "$IMPLANT" --mode wireguard --wg-url "$WG_URL" --wg-server-public "$WG_PUB" \
      "${common[@]}" --poll-interval-secs 2 --jitter-secs 0 --max-runtime-secs 120 >"$LOG" 2>&1 &
    ;;
  fallback)
    "$IMPLANT" --mode fallback --fallback "http,quic,dns,wireguard" \
      --http-url "$HTTP_URL" --quic-url "$QUIC_URL" --dns-url "$DNS_URL" \
      --wg-url "$WG_URL" --wg-server-public "$WG_PUB" --dns-zone dns.shikra \
      "${common[@]}" --poll-interval-secs 2 --jitter-secs 0 --max-runtime-secs 120 >"$LOG" 2>&1 &
    ;;
  *)
    echo "unknown mode: $MODE" >&2; exit 2
    ;;
esac
AGENT_PID=$!
echo "agent($MODE) pid=$AGENT_PID"

# Wait for a new session (id not present in the prior snapshot).
DEADLINE=$((SECONDS + 45))
TARGET=""
while (( SECONDS < DEADLINE )); do
  TARGET=$("$CLIENT" sessions 2>/dev/null | awk -F'\t' 'NF>=5 {print $1}' | sort | comm -13 <(echo "$PRIOR") - | head -1)
  [[ -n "$TARGET" ]] && break
  sleep 1
done

if [[ -z "$TARGET" ]]; then
  echo "FAIL($MODE): no session after 45s"; tail -30 "$LOG"; kill "$AGENT_PID" 2>/dev/null || true; exit 1
fi

echo "session($MODE)=$TARGET"
OUT=$("$CLIENT" shell --session "$TARGET" -- echo "BEACON_${MODE}_OK" 2>&1)
echo "$OUT"
if echo "$OUT" | grep -q "BEACON_${MODE}_OK"; then
  echo "PASS($MODE)"
  RC=0
else
  echo "FAIL($MODE): command output mismatch"
  tail -20 "$LOG"
  RC=1
fi

kill "$AGENT_PID" 2>/dev/null || true
wait "$AGENT_PID" 2>/dev/null || true
exit $RC
