// Generate the vfy-policy strategy commitment for registration.
// Creates a fresh random 248-bit salt, computes the commitment with the
// verified formula (standard circomlibjs Poseidon, 9 inputs
// [params[0..7], salt]), and saves { params, salt, commitment,
// commitmentHex, createdAt } to ~/.config/agentgames/vfy-salt.json
// (mode 600). The VALUES are never printed and never committed: only
// the file path and a short fingerprint are shown. Register the
// commitment hex from that file on the Agent Games dashboard before
// Swiss Round 1, and set AGENT_GAMES_VFY_SALT to the same salt in the
// Vercel env so the deployed endpoint can prove turns.
// Usage: node scripts/register-commitment.mjs [--force]
// (refuses to overwrite an existing salt unless --force; rotating the
// salt means re-registering the commitment).
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { computeCommitment, commitmentToHex } from "../src/steal.js";
import { STRATEGY_PARAMS } from "../src/strategy.js";

const dir = path.join(os.homedir(), ".config", "agentgames");
const file = path.join(dir, "vfy-salt.json");
const force = process.argv.includes("--force");
if (fs.existsSync(file) && !force) {
  console.error(`Salt file already exists: ${file}`);
  console.error("Refusing to overwrite (rotating the salt requires re-registering the commitment). Re-run with --force to replace it.");
  process.exit(1);
}
const salt = BigInt("0x" + crypto.randomBytes(31).toString("hex")); // 248-bit
const commitment = await computeCommitment(STRATEGY_PARAMS, salt);
const record = {
  params: STRATEGY_PARAMS,
  salt: salt.toString(),
  commitment: commitment.toString(),
  commitmentHex: commitmentToHex(commitment),
  createdAt: new Date().toISOString(),
};
fs.mkdirSync(dir, { recursive: true });
fs.chmodSync(dir, 0o700);
fs.writeFileSync(file, JSON.stringify(record, null, 2) + "\n");
fs.chmodSync(file, 0o600);
console.log(`Saved salt + commitment to ${file} (mode 600).`);
console.log(`Params: [${STRATEGY_PARAMS.join(", ")}]`);
console.log(`Commitment fingerprint: ${record.commitmentHex.slice(0, 10)}... (full hex is in the file; register THAT hex on the dashboard)`);
console.log("Next: set AGENT_GAMES_VFY_SALT in the Vercel env to the salt in that file, then redeploy.");
