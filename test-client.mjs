// Test client for the Proof Gatekeeper agent (local testing only).
// Signs a fixture with HMAC-SHA256 over the raw body, POSTs it to the local
// server, verifies the response signature, and asserts the expected outcome.
//
// Usage:
//   AGENT_GAMES_HMAC_SECRET=<secret> PORT=3456 node test-client.mjs <fixture.json>
//     --expect-decision APPROVE --expect-reason OK
//     [--expect-status 200] [--bad-signature] [--no-signature]
// Exit code 0 = all assertions passed, 1 = something failed.

import crypto from "node:crypto";
import fs from "node:fs";

function arg(name, fallback = null) {
  const i = process.argv.indexOf(name);
  return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : fallback;
}
const has = (name) => process.argv.includes(name);

const fixturePath = process.argv[2];
if (!fixturePath) {
  console.error("usage: node test-client.mjs <fixture.json> [--expect-decision X] [--expect-reason Y] [--expect-status N] [--bad-signature] [--no-signature]");
  process.exit(2);
}

const PORT = Number(process.env.PORT || arg("--port", "3456"));
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET;
if (!SECRET) {
  console.error("AGENT_GAMES_HMAC_SECRET is not set");
  process.exit(2);
}

const expectDecision = arg("--expect-decision");
const expectReason = arg("--expect-reason");
const expectStatus = Number(arg("--expect-status", expectDecision ? "200" : "401"));

const rawBody = fs.readFileSync(fixturePath, "utf8");
const sig = crypto.createHmac("sha256", SECRET).update(rawBody).digest("hex");

const headers = { "Content-Type": "application/json" };
if (!has("--no-signature")) {
  headers["x-agent-games-signature"] = has("--bad-signature") ? "0".repeat(64) : sig;
}

const t0 = Date.now();
const res = await fetch(`http://127.0.0.1:${PORT}/task`, {
  method: "POST",
  headers,
  body: rawBody,
});
const elapsed = Date.now() - t0;
const respBody = await res.text();

let json = null;
try {
  json = JSON.parse(respBody);
} catch {
  // non-JSON response — assertion below will fail on the decision checks
}

// The response itself must always be signed (hex HMAC-SHA256 over raw body).
const respSig = res.headers.get("x-agent-games-signature") || "";
const expectedRespSig = crypto.createHmac("sha256", SECRET).update(respBody).digest("hex");
const respSigOk = respSig === expectedRespSig;

const failures = [];
if (res.status !== expectStatus) failures.push(`status ${res.status} != ${expectStatus}`);
if (expectDecision && json?.decision !== expectDecision) {
  failures.push(`decision ${json?.decision} != ${expectDecision}`);
}
if (expectReason && json?.reason_code !== expectReason) {
  failures.push(`reason_code ${json?.reason_code} != ${expectReason}`);
}
if (!respSigOk) failures.push("response signature invalid");
if (elapsed >= 1000) failures.push(`took ${elapsed}ms (>= 1000ms)`);

const label = `${fixturePath.split("/").pop()}${has("--bad-signature") ? " [bad-signature]" : ""}${has("--no-signature") ? " [no-signature]" : ""}`;
if (failures.length === 0) {
  console.log(
    `PASS ${label} -> HTTP ${res.status} decision=${json?.decision ?? "-"} reason=${json?.reason_code ?? "-"} respSig=ok ${elapsed}ms`,
  );
  process.exit(0);
} else {
  console.log(
    `FAIL ${label} -> HTTP ${res.status} decision=${json?.decision ?? "-"} reason=${json?.reason_code ?? "-"} respSig=${respSigOk ? "ok" : "BAD"} ${elapsed}ms :: ${failures.join("; ")} :: body=${respBody.slice(0, 200)}`,
  );
  process.exit(1);
}
