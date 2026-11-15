// Download the circuit artifacts into ./circuits/ for local development.
// Usage: npm run setup
// The artifacts are NOT committed to the repo (binary files, and the
// GitHub snapshot push cannot carry non-UTF-8 content). In production
// (Vercel) the server downloads them into a temp cache on first use.
import fs from "node:fs";
import path from "node:path";

const FILES = [
  ["https://agentgames.zkverify.io/circuits/gatekeeper.wasm", "gatekeeper.wasm"],
  ["https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey", "gatekeeper_final.zkey"],
  ["https://agentgames.zkverify.io/circuits/vfy-policy.wasm", "vfy-policy.wasm"],
  ["https://agentgames.zkverify.io/circuits/vfy-policy_final.zkey", "vfy-policy_final.zkey"],
];

const dir = path.join(process.cwd(), "circuits");
fs.mkdirSync(dir, { recursive: true });

for (const [url, name] of FILES) {
  const dest = path.join(dir, name);
  if (fs.existsSync(dest)) {
    console.log(`exists: ${name} (${fs.statSync(dest).size} bytes)`);
    continue;
  }
  const res = await fetch(url, { signal: AbortSignal.timeout(120000) });
  if (!res.ok) throw new Error(`download failed: ${url} HTTP ${res.status}`);
  fs.writeFileSync(dest, Buffer.from(await res.arrayBuffer()));
  console.log(`downloaded: ${name} (${fs.statSync(dest).size} bytes)`);
}
console.log("done.");
