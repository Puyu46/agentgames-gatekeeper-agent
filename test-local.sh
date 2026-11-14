#!/usr/bin/env bash
# Local test for the Proof Gatekeeper agent.
# Starts the server with a dummy HMAC secret, sends every fixture with a correct
# HMAC signature, and asserts decision + reason_code for each case. Also checks:
#   - sending the same proof_tx twice -> second time is PROOF_REUSED
#   - wrong / missing signature -> HTTP 401
#   - the seen-set file persists the approve proof_tx
#   - every response arrives in < 1 s (the platform's hard deadline is 60 s)
# Order matters: approve.json runs first (its proof_tx is then "seen"), so the
# reuse cases that follow must come back PROOF_REUSED.
set -u
cd "$(dirname "$0")"
export PORT="${PORT:-3456}"
export AGENT_GAMES_HMAC_SECRET="${AGENT_GAMES_HMAC_SECRET:-test-secret-1234567890}"
rm -f seen-proofs.json seen-proofs.json.tmp

node server.mjs > test-server.log 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null; rm -f test-server.log' EXIT

# Wait for the health endpoint (max ~4 s).
for _ in $(seq 1 20); do
  curl -fsS -o /dev/null "http://127.0.0.1:$PORT/health" 2>/dev/null && break
  sleep 0.2
done

FAIL=0
run() {
  if ! node test-client.mjs "$@"; then FAIL=1; fi
}

echo "== decision fixtures =="
run test-fixtures/approve.json --expect-decision APPROVE --expect-reason OK
run test-fixtures/approve.json --expect-decision REJECT --expect-reason PROOF_REUSED
run test-fixtures/proof-reused.json --expect-decision REJECT --expect-reason PROOF_REUSED
run test-fixtures/vk-substitution.json --expect-decision REJECT --expect-reason VK_SUBSTITUTION
run test-fixtures/threshold-mismatch.json --expect-decision REJECT --expect-reason THRESHOLD_MISMATCH
run test-fixtures/recipient-mismatch.json --expect-decision REJECT --expect-reason RECIPIENT_MISMATCH
run test-fixtures/amount-overflow.json --expect-decision REJECT --expect-reason AMOUNT_OVERFLOW
run test-fixtures/expired-condition.json --expect-decision REJECT --expect-reason EXPIRED_CONDITION
run test-fixtures/expired-deadline.json --expect-decision REJECT --expect-reason EXPIRED_CONDITION
run test-fixtures/malformed-proof.json --expect-decision REJECT --expect-reason PROOF_REUSED
run test-fixtures/order-multi-fail.json --expect-decision REJECT --expect-reason VK_SUBSTITUTION

echo "== signature checks =="
run test-fixtures/approve.json --expect-status 401 --bad-signature
run test-fixtures/approve.json --expect-status 401 --no-signature

echo "== seen-set persisted =="
if grep -q "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" seen-proofs.json 2>/dev/null; then
  echo "PASS seen-proofs.json contains the approve proof_tx"
else
  echo "FAIL seen-proofs.json is missing the approve proof_tx"
  FAIL=1
fi
if grep -q "not-a-valid-tx-hash" seen-proofs.json 2>/dev/null; then
  echo "FAIL seen-proofs.json wrongly stored the malformed proof_tx"
  FAIL=1
else
  echo "PASS seen-proofs.json did not store the malformed proof_tx"
fi

echo
if [ "$FAIL" -eq 0 ]; then
  echo "ALL TESTS PASSED"
else
  echo "SOME TESTS FAILED"
  exit 1
fi
