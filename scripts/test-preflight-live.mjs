// Signed-preflight test against a LIVE endpoint.
// Usage: node scripts/test-preflight-live.mjs <endpoint-agent-url> <secret-file>
// Reads the HMAC secret from the mode-600 file (never prints it).
import fs from "node:fs";
import crypto from "node:crypto";

const endpoint = process.argv[2];
const secretFile = process.argv[3];
if (!endpoint || !secretFile) {
  console.error("usage: node scripts/test-preflight-live.mjs <https://<project>.vercel.app/agent> <secret-file>");
  process.exit(2);
}
const secret = fs.readFileSync(secretFile, "utf8").trim();
const body = JSON.stringify({ type: "agent-games.preflight.v1", agent_id: "agt_test", issued_at: new Date().toISOString(), nonce: "preflight-test-1" });
const sig = crypto.createHmac("sha256", secret).update(body).digest("hex");

const res = await fetch(endpoint, {
  method: "POST",
  headers: { "content-type": "application/json", "x-agent-games-signature": sig },
  body,
});
const text = await res.text();
console.log("HTTP", res.status);
console.log("body:", text);
console.log("response signature header present:", Boolean(res.headers.get("x-agent-games-signature")));
const respSig = res.headers.get("x-agent-games-signature") || "";
const expected = crypto.createHmac("sha256", secret).update(text).digest("hex");
const norm = (s) => s.replace(/^sha256=/, "").replace(/^0x/, "");
console.log("response signature valid:", respSig !== "" && norm(respSig) === expected);
