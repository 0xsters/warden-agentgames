// Local dev server. Production ALSO runs this file: the Vercel project
// builds a single bundled function ("index") from src/server.js, so the
// api/ entries are not what serves production. Keep the health shape in
// BOTH places in sync (api/health.js mirrors this response).
import http from "node:http";
import { handleAgentRequest } from "./handler.js";
import { getSecret, verifySignature } from "./hmac.js";
import { kurierConfigured, kurierSubmitEnabled } from "./proof.js";

const PORT = Number(process.env.PORT || 3000);

function readRaw(req, limit = 1024 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > limit) reject(new Error("body too large"));
      else chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === "GET" && (req.url === "/health" || req.url === "/")) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({
        ok: true,
        service: "warden-agentgames",
        version: "0.1.1",
        time: new Date().toISOString(),
        kurierConfigured: kurierConfigured(),
        // Whether proofs are actually submitted to Kurier (needs the
        // explicit KURIER_SUBMIT=true opt-in, not just the key).
        kurierSubmitEnabled: kurierSubmitEnabled(),
        secretConfigured: Boolean(getSecret()),
        // Boolean only, never the value: the deployed endpoint can only
        // generate vfy-policy proofs when the registered salt is set.
        vfySaltConfigured: Boolean(process.env.AGENT_GAMES_VFY_SALT),
      }));
      return;
    }
    if (req.method === "POST" && req.url === "/agent") {
      const raw = await readRaw(req);
      const out = await handleAgentRequest(raw, req.headers);
      res.writeHead(out.status, out.headers);
      res.end(out.body);
      return;
    }
    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "not found" }));
  } catch (e) {
    console.error("[server]", e);
    if (String(e?.message) === "body too large") {
      res.writeHead(413, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "payload too large" }));
      return;
    }
    res.writeHead(500, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "internal error" }));
  }
});

server.listen(PORT, () => {
  console.log(`warden-agentgames listening on :${PORT} (secret configured: ${Boolean(getSecret())}, kurier: ${kurierConfigured()})`);
});
