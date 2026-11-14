# Agent Games — Proof Gatekeeper Agent

Deterministic decision-logic agent for the **Proof Gatekeeper** track of
[Agent Games](https://agentgames.zkverify.io) (zkVerify). Account: **@andini456ie**.

The agent receives a proof-gated payment task, verifies the HMAC signature on the
raw request body, and answers **APPROVE** or **REJECT** with a machine-readable
reason code — all in milliseconds, well inside the platform's 60-second deadline.

> **Scope — decision logic only, no ZK proof attached.**
> This agent does **not** verify Groth16 proofs and does **not** attach a proof to
> its decisions. The public-input circuit (names/order of the 13 public inputs)
> has not been published, so a Groth16 pipeline cannot be built correctly yet.
> Per the track rules this costs **−2 points per decision** (no proof attached)
> and no reliability bonus, while a correct decision still earns **+12**
> (a wrong APPROVE costs −6, a wrong REJECT −3). Getting the deterministic
> decision right is the whole game for now; proof integration is a later step,
> once circuit data is available.
>
> The agent also makes **no on-chain calls**: "proof must be on-chain" cannot be
> established from the task payload alone (see *Documented decisions* below).
> It never signs transactions and holds no private keys — the only secret is the
> HMAC secret from the Agent Games dashboard, kept in an environment variable.

## HTTP contract

Base URL is the deployed public HTTPS endpoint (see *Deploy + registration*).

| Method | Path | Description |
| ------ | ---- | ----------- |
| `GET` | `/` or `/health` | Health + description document (unsigned, no HMAC needed). |
| `POST` | `/` or `/task` | Submit one task envelope. |

### Request — task envelope

`Content-Type: application/json`, header **`x-agent-games-signature`** =
HMAC-SHA256 (hex, or base64 of the same digest) of the **raw request body**,
keyed with `AGENT_GAMES_HMAC_SECRET`. The signature is verified **before** the
body is parsed; a missing or wrong signature is rejected with **HTTP 401**
without any processing.

```json
{
  "type": "agent-games.proof-gatekeeper.v1",
  "task_id": "task-approve-001",
  "mode": "practice",
  "issued_at": "2026-11-14T11:00:00.000Z",
  "deadline_at": "2030-01-01T00:00:00.000Z",
  "input": {
    "registered_vk": "0xaaaa…",
    "proof_vk": "0xaaaa…",
    "minimum": "1000000000000000000",
    "public_balance": "1500000000000000000",
    "expiry_block": 1000,
    "current_block": 900,
    "recipient": "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12",
    "condition_recipient": "0xabcdef1234567890abcdef1234567890abcdef12",
    "amount": 100,
    "max_transfer": "1000",
    "proof_tx": "0xaaaa…"
  }
}
```

Numbers may arrive as **decimal strings, hex strings (`0x…`), or JSON numbers**
— all are normalised with `BigInt` (numbers must be safe integers; a float or an
unsafe integer fails closed with that check's own reason code). Addresses are
compared **case-insensitively**. `issued_at` / `deadline_at` accept ISO-8601
strings, epoch seconds, or epoch milliseconds.

### Response

```json
{ "decision": "APPROVE", "reason_code": "OK", "proof_tx": "0xaaaa…" }
```

The response is also signed: header **`x-agent-games-signature`** = hex
HMAC-SHA256 of the raw response body, same secret. `proof_tx` echoes the
request's value exactly as sent.

### Status codes

| Status | Meaning |
| ------ | ------- |
| `200` | A decision was made (APPROVE or REJECT — see `reason_code`). |
| `400` | Envelope malformed (wrong `type`, missing field, unparseable time/JSON). Not a decision. |
| `401` | Missing or invalid `x-agent-games-signature`. Nothing was processed. |
| `404` | Unknown path. |
| `405` | Non-POST on `/` or `/task`. |
| `413` | Body over 1 MB. |
| `500` | Internal error (fail closed — the platform treats a missing answer as a miss). |

## Decision logic

APPROVE only when **all** of these hold; otherwise REJECT with the first
failing check's reason code.

| # | Check | Fails as |
| - | ----- | -------- |
| 0 | Envelope deadline: `now <= deadline_at` (60 s hard window) | `EXPIRED_CONDITION` |
| 1 | `proof_tx` not seen before (and well-formed) | `PROOF_REUSED` |
| 2 | `proof_vk == registered_vk` (exact string match) | `VK_SUBSTITUTION` |
| 3 | `public_balance >= minimum` | `THRESHOLD_MISMATCH` |
| 4 | `recipient == condition_recipient` (case-insensitive) | `RECIPIENT_MISMATCH` |
| 5 | `amount <= max_transfer` | `AMOUNT_OVERFLOW` |
| 6 | `current_block <= expiry_block` | `EXPIRED_CONDITION` |

**Check order is the table order.** When several checks fail at once, the first
one in the table decides the reason code — e.g. a task with a substituted vk,
a balance below the minimum, *and* a wrong recipient is rejected as
`VK_SUBSTITUTION` (see `test-fixtures/order-multi-fail.json`). Check 0 is an
envelope-level rule that runs before the six input checks; the documented order
governs the six input checks.

Reason codes (7 total): `OK` (the APPROVE code) plus the six REJECT codes in
the table. No other reason code is ever emitted.

### Seen-set (replay protection)

`proof_tx` values are kept in a **persistent local seen-set**,
`seen-proofs.json` in the agent folder (loaded at start, saved after every
task — atomic write via temp file + rename). A `proof_tx` is **seen** the moment
it is presented to the agent — even if that task is later rejected for another
reason — so a replayed proof is always `PROOF_REUSED` afterwards. The file
**must survive restarts and deploys** (persistent disk/volume): if it is lost,
proofs that were already used could be approved again. It is git-ignored and
must never be committed.

### Documented decisions (where the spec leaves a gap)

1. **Malformed `proof_tx`** (not `0x` + 64 hex chars) → REJECT with
   `PROOF_REUSED`. There is no reason code for "malformed" in the documented
   set, and inventing one would break the contract; a proof that cannot be
   identified cannot be used, so it is treated as "not usable". Malformed
   values are **not** added to the seen-set.
2. **"Proof must be on-chain"** cannot be checked from the payload — the task
   contains no RPC endpoint, chain id, or proof data, only a tx hash. The
   agent therefore treats a well-formed, never-seen `proof_tx` as usable and
   documents this limitation instead of pretending to verify it. (A later
   version could add an RPC lookup; it would still have to finish inside the
   60 s window.)
3. **Envelope deadline** (`deadline_at` in the past) → REJECT with
   `EXPIRED_CONDITION`, checked before the six input checks. The server clock
   must be NTP-synced, or legitimate tasks near the deadline could be rejected.
4. **Unparseable numbers** fail closed with the reason code of the check they
   belong to (threshold → `THRESHOLD_MISMATCH`, amount → `AMOUNT_OVERFLOW`,
   blocks → `EXPIRED_CONDITION`).
5. **Malformed envelopes** (wrong `type`, missing field, bad JSON) return
   HTTP 400 rather than a REJECT decision — they are not gatekeeper tasks.

## Running

Node.js ≥ 18, zero dependencies.

```bash
export AGENT_GAMES_HMAC_SECRET="<secret from the Agent Games dashboard>"
export PORT=3000        # optional, default 3000
node server.mjs         # or: npm start
```

The server refuses to start without `AGENT_GAMES_HMAC_SECRET`. Optional:
`SEEN_FILE` to point the seen-set at a different path (e.g. a mounted volume).

## Testing

```bash
npm test            # or: bash test-local.sh
```

The script starts the server on port 3456 with a dummy secret, resets the
seen-set, and runs `test-client.mjs` (signs each fixture with HMAC-SHA256,
POSTs it, verifies the response signature, asserts decision + reason code and
a < 1 s response). Expected results:

| Fixture | Expected |
| ------- | -------- |
| `approve.json` | APPROVE / `OK` |
| `approve.json` (sent a second time) | REJECT / `PROOF_REUSED` |
| `proof-reused.json` (same `proof_tx` as approve) | REJECT / `PROOF_REUSED` |
| `vk-substitution.json` | REJECT / `VK_SUBSTITUTION` |
| `threshold-mismatch.json` (hex amounts: minimum 1e18, balance 0.5e18) | REJECT / `THRESHOLD_MISMATCH` |
| `recipient-mismatch.json` | REJECT / `RECIPIENT_MISMATCH` |
| `amount-overflow.json` | REJECT / `AMOUNT_OVERFLOW` |
| `expired-condition.json` (current 1001 > expiry 1000) | REJECT / `EXPIRED_CONDITION` |
| `expired-deadline.json` (`deadline_at` in the past) | REJECT / `EXPIRED_CONDITION` |
| `malformed-proof.json` (`proof_tx` not a tx hash) | REJECT / `PROOF_REUSED` |
| `order-multi-fail.json` (vk + threshold + recipient all wrong) | REJECT / `VK_SUBSTITUTION` |
| `approve.json` with a wrong signature | HTTP 401 |
| `approve.json` with no signature | HTTP 401 |

It also asserts that `seen-proofs.json` contains the approve `proof_tx` after
the run and did **not** store the malformed one. Fixtures use a far-future
`deadline_at` (2030) so the local test never expires; the approve fixture
deliberately uses mixed-case `recipient` vs lowercase `condition_recipient`
(same address) to prove the case-insensitive comparison, and mixes JSON numbers
with decimal/hex strings to prove the BigInt normalisation.

## Deploy + registration (still to do — nothing here is deployed)

1. **HMAC secret** — the 32-byte secret is issued **once** at Agent Games
   registration (dashboard → Proof Gatekeeper track). Put it in the hosting
   environment as `AGENT_GAMES_HMAC_SECRET`. Never commit it, never print it.
2. **Public HTTPS URL** — deploy this folder to a host with a public HTTPS
   endpoint (e.g. Vercel / any Node host). The platform must be able to reach
   `POST /` (or `/task`) from the internet; a localhost URL will not work.
   Keep the process always-on during scored rounds — offline means forfeit.
3. **Persistent seen-set** — `seen-proofs.json` must live on a persistent
   disk/volume that survives restarts and redeploys (otherwise replay
   protection resets). Set `SEEN_FILE` if the host needs a different path.
4. **Clock** — the host clock must be NTP-synced (the deadline check depends
   on it).
5. **Preflight / practice** — from the Agent Games dashboard, run the
   track's preflight/practice dispatch against the deployed URL (practice mode,
   ~10 dispatches/hour) and confirm decisions + signatures verify end-to-end
   before the scored rounds.
6. **Register the endpoint** in the dashboard for the Proof Gatekeeper track
   (competition rounds run nightly; entry is possible between rounds).

## Files

```
agentgames-gatekeeper-agent/
├── server.mjs            # the agent (Node stdlib only)
├── package.json          # no dependencies; npm start / npm test
├── test-client.mjs       # local test helper (sign + POST + verify + assert)
├── test-local.sh         # full local test run
├── test-fixtures/        # one task envelope per case (see table above)
├── seen-proofs.json      # created at runtime; git-ignored, never commit
├── .gitignore
├── LICENSE               # MIT © 2026 Puyu46
└── README.md             # this file
```

## License

MIT © 2026 Puyu46.
