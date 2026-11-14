// Agent Games — Proof Gatekeeper agent (decision logic only, no ZK proof attached)
// Node.js standard library only: no dependencies, no private keys, no transactions.
//
// What it does: receives a proof-gatekeeper task envelope over HTTPS, verifies the
// HMAC signature on the RAW request body BEFORE parsing, then makes a deterministic
// APPROVE / REJECT decision against the task's payment condition, and signs the
// response body with the same HMAC secret.
//
// The agent does NOT verify Groth16 proofs (the public-input circuit has not been
// published) and does NOT check anything on-chain: "proof must be on-chain" cannot
// be established from the task payload alone. See README.md for the documented
// decisions this implies (malformed proof_tx, deadline handling, seen-set).
//
// Scoring (per /rules): +12 per correct decision, -2 without an attached proof,
// no reliability bonus. Proof integration is a later step, once circuit data exists.

import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || "0.0.0.0";
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET;
if (!SECRET) {
  console.error("FATAL: AGENT_GAMES_HMAC_SECRET is not set. Refusing to start.");
  console.error("Set it to the 32-byte HMAC secret issued at Agent Games registration.");
  process.exit(1);
}
// Persistent seen-set: JSON array of proof_tx values (lowercased) already presented
// to this agent. Lives in the agent folder; MUST survive restarts/deploys, or a
// proof that was already used could be accepted again after a restart.
const SEEN_FILE = process.env.SEEN_FILE || path.join(__dirname, "seen-proofs.json");
const MAX_BODY_BYTES = 1_000_000; // 1 MB — task envelopes are a few KB
const TASK_TYPE = "agent-games.proof-gatekeeper.v1";
const VERSION = "0.1.0";

// ---------------------------------------------------------------------------
// Seen-set (persistent on disk)
// ---------------------------------------------------------------------------
const seen = new Set();

function loadSeen() {
  try {
    const raw = fs.readFileSync(SEEN_FILE, "utf8");
    const arr = JSON.parse(raw);
    if (Array.isArray(arr)) {
      for (const x of arr) if (typeof x === "string") seen.add(x.toLowerCase());
    }
    console.log(`seen-set loaded: ${seen.size} proof(s) from ${SEEN_FILE}`);
  } catch (err) {
    if (err.code === "ENOENT") {
      console.log(`seen-set: no ${SEEN_FILE} yet, starting empty`);
    } else {
      console.error(`warning: could not load seen-set (${SEEN_FILE}): ${err.message}; starting empty`);
    }
  }
}

function saveSeen() {
  // Atomic write: temp file + rename, so a crash cannot leave a half-written file.
  const tmp = `${SEEN_FILE}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify([...seen].sort(), null, 2) + "\n");
  fs.renameSync(tmp, SEEN_FILE);
}

loadSeen();

// ---------------------------------------------------------------------------
// HMAC helpers — hex HMAC-SHA256 over the raw body, same secret both directions
// ---------------------------------------------------------------------------
function hmacHex(data) {
  return crypto.createHmac("sha256", SECRET).update(data).digest("hex");
}

// The platform's signature header may be hex or base64 of the same digest;
// accept either encoding of the same 32-byte HMAC, compare in constant time.
function verifySignature(provided, rawBody) {
  if (typeof provided !== "string") return false;
  const p = provided.trim();
  if (!p) return false;
  const digest = crypto.createHmac("sha256", SECRET).update(rawBody).digest();
  const hex = digest.toString("hex");
  const eq = (a, b) => {
    const ba = Buffer.from(a);
    const bb = Buffer.from(b);
    return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
  };
  if (/^[0-9a-fA-F]{64}$/.test(p)) return eq(p.toLowerCase(), hex);
  if (p.length === 44 && p.endsWith("=")) {
    try {
      return eq(Buffer.from(p, "base64"), digest) && Buffer.from(p, "base64").toString("base64") === p;
    } catch {
      return false;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Normalisation helpers — numbers may arrive as decimal/hex strings or numbers
// ---------------------------------------------------------------------------
function toBigInt(v) {
  if (typeof v === "bigint") return v;
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v)) throw new Error("number is not a safe integer");
    return BigInt(v);
  }
  if (typeof v === "string") {
    const s = v.trim();
    if (s === "") throw new Error("empty string");
    return BigInt(s); // accepts "123" and "0x..." ; throws on "1.5" / garbage
  }
  throw new Error(`unsupported type ${typeof v}`);
}

// issued_at / deadline_at may be ISO strings, epoch seconds, or epoch millis.
function parseTime(v) {
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new Error("bad time");
    return v > 1e12 ? Math.trunc(v) : Math.trunc(v) * 1000; // ms vs seconds
  }
  if (typeof v === "string") {
    const s = v.trim();
    if (/^-?\d+$/.test(s)) return parseTime(Number(s));
    const t = Date.parse(s);
    if (Number.isNaN(t)) throw new Error("unparseable time");
    return t;
  }
  throw new Error("unsupported time");
}

const TX_RE = /^0x[0-9a-fA-F]{64}$/; // a proof tx hash is 0x + 64 hex chars

// ---------------------------------------------------------------------------
// Envelope validation (fail closed: anything malformed is a 400, not a decision)
// ---------------------------------------------------------------------------
const INPUT_FIELDS = [
  "registered_vk",
  "proof_vk",
  "minimum",
  "public_balance",
  "expiry_block",
  "current_block",
  "recipient",
  "condition_recipient",
  "amount",
  "max_transfer",
  "proof_tx",
];

function validateEnvelope(task) {
  if (!task || typeof task !== "object" || Array.isArray(task)) return "body must be a JSON object";
  if (task.type !== TASK_TYPE) return `type must be "${TASK_TYPE}"`;
  for (const f of ["task_id", "mode", "issued_at", "deadline_at"]) {
    if (task[f] === undefined || task[f] === null || task[f] === "") return `missing field: ${f}`;
  }
  if (typeof task.task_id !== "string") return "task_id must be a string";
  if (typeof task.mode !== "string") return "mode must be a string";
  try {
    parseTime(task.issued_at);
  } catch {
    return "issued_at is not a valid time";
  }
  try {
    parseTime(task.deadline_at);
  } catch {
    return "deadline_at is not a valid time";
  }
  const input = task.input;
  if (!input || typeof input !== "object" || Array.isArray(input)) return "missing field: input (object)";
  for (const f of INPUT_FIELDS) {
    if (input[f] === undefined || input[f] === null || input[f] === "") return `missing field: input.${f}`;
  }
  if (typeof input.registered_vk !== "string" || typeof input.proof_vk !== "string") {
    return "registered_vk and proof_vk must be strings";
  }
  if (typeof input.recipient !== "string" || typeof input.condition_recipient !== "string") {
    return "recipient and condition_recipient must be strings";
  }
  if (typeof input.proof_tx !== "string") return "proof_tx must be a string";
  return null;
}

// ---------------------------------------------------------------------------
// Decision logic — deterministic, fail closed (doubt/timeout = REJECT).
// Check order (documented in README.md):
//   0. envelope deadline (now > deadline_at -> EXPIRED_CONDITION)
//   1. PROOF_REUSED      (incl. malformed proof_tx — see README)
//   2. VK_SUBSTITUTION
//   3. THRESHOLD_MISMATCH
//   4. RECIPIENT_MISMATCH
//   5. AMOUNT_OVERFLOW
//   6. EXPIRED_CONDITION
// The first failing check decides the reason_code.
// ---------------------------------------------------------------------------
function decide(task) {
  const input = task.input;
  const proofTxEcho = typeof input.proof_tx === "string" ? input.proof_tx : "";
  const reject = (code) => ({ decision: "REJECT", reason_code: code, proof_tx: proofTxEcho });

  // 0. Envelope-level hard deadline (60 s window). Checked before the six
  //    input checks; a task that arrives after its own deadline cannot approve.
  //    (Server clock must be NTP-synced; see README.)
  if (Date.now() > parseTime(task.deadline_at)) return reject("EXPIRED_CONDITION");

  // 1. PROOF_REUSED — a proof_tx is "seen" once it has been presented to this
  //    agent, even if that task was later rejected for another reason. Mark it
  //    seen now, before the remaining checks. A malformed proof_tx (not
  //    0x + 64 hex) is also REJECTed here as PROOF_REUSED: there is no reason
  //    code for "malformed" in the documented set, and a proof that cannot be
  //    identified cannot be used. Malformed values are NOT added to the seen-set.
  const rawTx = input.proof_tx;
  if (typeof rawTx !== "string" || !TX_RE.test(rawTx.trim())) return reject("PROOF_REUSED");
  const txKey = rawTx.trim().toLowerCase();
  if (seen.has(txKey)) return reject("PROOF_REUSED");
  seen.add(txKey);
  saveSeen();

  // 2. VK_SUBSTITUTION — the proof's verification key must be the registered one.
  if (String(input.proof_vk).trim() !== String(input.registered_vk).trim()) {
    return reject("VK_SUBSTITUTION");
  }

  // 3. THRESHOLD_MISMATCH — public balance must reach the required minimum.
  //    Unparseable numbers fail closed with this check's own code.
  try {
    if (toBigInt(input.public_balance) < toBigInt(input.minimum)) return reject("THRESHOLD_MISMATCH");
  } catch {
    return reject("THRESHOLD_MISMATCH");
  }

  // 4. RECIPIENT_MISMATCH — addresses compared case-insensitively.
  if (
    String(input.recipient).trim().toLowerCase() !==
    String(input.condition_recipient).trim().toLowerCase()
  ) {
    return reject("RECIPIENT_MISMATCH");
  }

  // 5. AMOUNT_OVERFLOW — amount must not exceed the transfer cap.
  try {
    if (toBigInt(input.amount) > toBigInt(input.max_transfer)) return reject("AMOUNT_OVERFLOW");
  } catch {
    return reject("AMOUNT_OVERFLOW");
  }

  // 6. EXPIRED_CONDITION — current block must not pass the condition's expiry.
  try {
    if (toBigInt(input.current_block) > toBigInt(input.expiry_block)) return reject("EXPIRED_CONDITION");
  } catch {
    return reject("EXPIRED_CONDITION");
  }

  return { decision: "APPROVE", reason_code: "OK", proof_tx: proofTxEcho };
}

// ---------------------------------------------------------------------------
// HTTP server
// ---------------------------------------------------------------------------
function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(body),
    "x-agent-games-signature": hmacHex(body), // every response is signed
  });
  res.end(body);
}

const server = http.createServer(async (req, res) => {
  const started = Date.now();
  let logged = false; // POST task decisions log their own line with task_id
  try {
    const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);

    if (req.method === "GET" && (url.pathname === "/" || url.pathname === "/health")) {
      sendJson(res, 200, {
        service: "agent-games-proof-gatekeeper",
        version: VERSION,
        status: "ok",
        account: "@andini456ie",
        description:
          "Agent Games Proof Gatekeeper — deterministic decision logic for proof-gated payment conditions. No ZK proof is attached (see README.md). No private keys, no transactions, no on-chain calls.",
        endpoints: {
          "GET /": "This health + description document.",
          "GET /health": "Health check.",
          "POST /": "Submit a task envelope (type agent-games.proof-gatekeeper.v1) with a valid x-agent-games-signature header.",
          "POST /task": "Same as POST /.",
        },
        seenProofs: seen.size,
      });
      return;
    }

    if (url.pathname === "/" || url.pathname === "/task") {
      if (req.method !== "POST") {
        sendJson(res, 405, { error: "Method not allowed. POST a task envelope to / or /task." });
        return;
      }

      // Read the RAW body first; the signature is verified BEFORE parsing.
      const chunks = [];
      let size = 0;
      let tooBig = false;
      for await (const chunk of req) {
        size += chunk.length;
        if (size > MAX_BODY_BYTES) {
          tooBig = true;
          break;
        }
        chunks.push(chunk);
      }
      if (tooBig) {
        sendJson(res, 413, { error: "Body too large (max 1 MB)." });
        return;
      }
      const rawBody = Buffer.concat(chunks);

      const sig = req.headers["x-agent-games-signature"];
      if (!verifySignature(sig, rawBody)) {
        sendJson(res, 401, { error: "Invalid or missing x-agent-games-signature." });
        return;
      }

      let task;
      try {
        task = JSON.parse(rawBody.toString("utf8"));
      } catch {
        sendJson(res, 400, { error: "Invalid JSON body." });
        return;
      }

      const envErr = validateEnvelope(task);
      if (envErr) {
        sendJson(res, 400, { error: envErr });
        return;
      }

      const result = decide(task);
      sendJson(res, 200, result);
      logged = true;
      console.log(
        `${new Date().toISOString()} task ${task.task_id} mode=${task.mode} -> ${result.decision} ${result.reason_code} (${Date.now() - started}ms)`,
      );
      return;
    }

    sendJson(res, 404, { error: `Not found: ${req.method} ${url.pathname}. See GET / for endpoints.` });
  } catch (err) {
    console.error("handler error:", err);
    if (!res.headersSent) sendJson(res, 500, { error: `Internal error: ${err?.message || err}` });
  } finally {
    if (!logged) console.log(`${req.method} ${req.url} -> ${res.statusCode} (${Date.now() - started}ms)`);
  }
});

server.listen(PORT, HOST, () => {
  console.log(`agent-games-proof-gatekeeper v${VERSION} listening on http://${HOST}:${PORT}`);
  console.log(`POST / or /task with a signed task envelope; GET / for docs. Seen-set: ${seen.size} proof(s).`);
});
