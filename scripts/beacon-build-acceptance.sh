#!/usr/bin/env bash
# Build-then-run acceptance for embedded-config beacons.
#
# Uses `shikra-builder` to produce one beacon per transport mode with the
# server material baked in, then boots each binary, waits for check-in and
# executes a command through the control plane.
#
# Usage: scripts/beacon-build-acceptance.sh [mode ...]
#   modes default to: session beacon quic dns wireguard fallback
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${SHIKRA_BEACON_WORK:?set SHIKRA_BEACON_WORK to the test work dir}"
BUILDER="${SHIKRA_BUILDER_BIN:-$ROOT/target/debug/shikra-builder}"
CLIENT="${SHIKRA_CLIENT_BIN:-$ROOT/target/debug/shikra-client}"

BOOT="$WORK/bootstrap.json"
STATE="$WORK/state"
BUILDS="$WORK/builds"
LOGS="$WORK/logs"
mkdir -p "$BUILDS" "$LOGS"

GRPC_URL="https://127.0.0.1:29443"
HTTP_URL="http://127.0.0.1:29080"
QUIC_URL="127.0.0.1:29444"
DNS_URL="127.0.0.1:25353"
WG_URL="127.0.0.1:25182"
WG_PUB=$(cat "$WORK/wg_public")
DNS_ZONE="dns.shikra"

export SHIKRA_SERVER="$GRPC_URL"
export SHIKRA_CA_CERT="$STATE/ca.pem"
export SHIKRA_OPERATOR_TOKEN=$(jq -r .operator_token "$BOOT")

MODES=("$@")
if [[ ${#MODES[@]} -eq 0 ]]; then
  MODES=(session beacon quic dns wireguard fallback)
fi

COMMON_BUILD=(
  --enroll-token-file "$STATE/enroll.token"
  --server-identity-file "$STATE/server-identity.pub"
  --ca-cert "$STATE/ca.pem"
  --output-dir "$BUILDS"
  --release
  --no-obfuscation
  --heartbeat-secs 2
  --poll-interval-secs 2
)

PASS=0
FAIL=0
for MODE in "${MODES[@]}"; do
  NAME="beacon-$MODE"
  BIN="$BUILDS/$NAME"
  BLOG="$LOGS/build-$NAME.log"
  ALOG="$LOGS/agent-$NAME.log"

  rm -f "$BIN" "$ALOG"
  echo "== build $MODE =="
  case "$MODE" in
    session)   ARGS=(--c2-url "$GRPC_URL") ;;
    beacon)    ARGS=(--http-url "$HTTP_URL") ;;
    quic)      ARGS=(--quic-url "$QUIC_URL" --tls-domain localhost) ;;
    dns)       ARGS=(--dns-url "$DNS_URL" --dns-zone "$DNS_ZONE") ;;
    wireguard) ARGS=(--wg-url "$WG_URL" --wg-server-public "$WG_PUB") ;;
    fallback)  ARGS=(--fallback "http,quic,dns,wireguard" \
                    --http-url "$HTTP_URL" --quic-url "$QUIC_URL" \
                    --dns-url "$DNS_URL" --dns-zone "$DNS_ZONE" \
                    --wg-url "$WG_URL" --wg-server-public "$WG_PUB" \
                    --tls-domain localhost) ;;
    *) echo "unknown mode: $MODE" >&2; FAIL=$((FAIL+1)); continue ;;
  esac

  if ! "$BUILDER" --name "$NAME" --mode "$MODE" "${ARGS[@]}" "${COMMON_BUILD[@]}" >"$BLOG" 2>&1; then
    echo "FAIL($MODE): builder error"; tail -20 "$BLOG"; FAIL=$((FAIL+1)); continue
  fi
  [[ -x "$BIN" ]] || { echo "FAIL($MODE): artifact missing at $BIN"; FAIL=$((FAIL+1)); continue; }

  PRIOR=$("$CLIENT" sessions 2>/dev/null | awk -F'\t' 'NF>=5 {print $1}' | sort)

  echo "== run $MODE =="
  "$BIN" >"$ALOG" 2>&1 &
  AGENT_PID=$!

  TARGET=""
  DEADLINE=$((SECONDS + 60))
  while (( SECONDS < DEADLINE )); do
    TARGET=$("$CLIENT" sessions 2>/dev/null | awk -F'\t' 'NF>=5 {print $1}' | sort | comm -13 <(echo "$PRIOR") - | head -1)
    [[ -n "$TARGET" ]] && break
    if ! kill -0 "$AGENT_PID" 2>/dev/null; then break; fi
    sleep 1
  done

  if [[ -z "$TARGET" ]]; then
    echo "FAIL($MODE): no session after 60s"
    tail -20 "$ALOG" 2>/dev/null || true
    kill "$AGENT_PID" 2>/dev/null || true
    FAIL=$((FAIL+1))
    continue
  fi

  OUT=$("$CLIENT" shell --session "$TARGET" -- echo "BUILT_${MODE}_OK" 2>&1 || true)
  if echo "$OUT" | grep -q "BUILT_${MODE}_OK"; then
    echo "PASS($MODE) session=$TARGET"
    PASS=$((PASS+1))
  else
    echo "FAIL($MODE): command output mismatch"
    echo "$OUT" | tail -5
    tail -10 "$ALOG" 2>/dev/null || true
    FAIL=$((FAIL+1))
  fi

  kill "$AGENT_PID" 2>/dev/null || true
  wait "$AGENT_PID" 2>/dev/null || true
done

echo "== summary: pass=$PASS fail=$FAIL =="
[[ $FAIL -eq 0 ]]
