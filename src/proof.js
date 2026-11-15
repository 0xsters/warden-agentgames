// Circuit artifacts, local Groth16 proving (snarkjs), and Kurier
// submission. All proof work is best-effort inside the 60s platform
// deadline: on any failure the caller still returns its decision with
// proof fields null and a clear log line, never a crash.
//
// Circuit input schemas (reverse-engineered from the published artifacts
// with snarkjs; see README "Circuit input schemas"):
//   gatekeeper (13 inputs, all public):
//     decision, taskId, registeredVkHash, proofVkHash, minimum,
//     publicBalance, expiryBlock, currentBlock, recipient,
//     conditionRecipient, amount, maxTransfer, salt
//   vfy-policy (17 inputs):
//     public signals (witness 1..9): [matchTurnHash, commitment, matchId,
//       turnNumber, selfBalance, opponentBalance, action, amount,
//       circuitVersion]
//       (signal 1 = Poseidon([matchId, turnNumber, circuitVersion]),
//       SOLVED 2026-11-14 — see computeMatchTurnHash in steal.js.)
//     private: strategyParams[8] (witness 10..13 = params[0..3],
//       witness 31..34 = params[4..7]) and salt (witness 14, PRIVATE —
//       the old "salt is public" note was wrong).
//     NOTE: the input OBJECT key order does not matter for proving —
//       snarkjs maps inputs by signal NAME; the public-signal order in
//       the proof is fixed by the circuit.
//     Commitment (VERIFIED 2026-11-14): standard circomlibjs Poseidon,
//       9 inputs [params[0..7], salt], t=10 — see computeCommitment in
//       steal.js. Param validity enforced by the circuit:
//       params[0] in 1..10, params[3] in {0,1}, params[4..7] == 0;
//       policy: FORTIFY if self < params[1], else HOLD if params[3]==1
//       or opponent <= params[2], else EXTRACT params[0].
//       (Full mapping: scratch-probe/FINDINGS-CORRECTED.md.)
//
// Kurier (https://api.kurier.xyz/api/v1): POST /submit-proof/{API_KEY}
// {proofType: "groth16", vkRegistered: true, chainId: 0, proofData:
// {proof, publicSignals, vk: <registered vkHash>}}; GET
// /job-status/{API_KEY}/{jobId} -> Queued|Valid|Submitted|
// IncludedInBlock|Finalized|Failed. Register each vk once first:
// POST /register-vk/{API_KEY} {proofType, proofOptions, vk}.
// STATUS 2026-11-14 17:41 WIB (re-audit): the stored Kurier key is VALID —
// helper job-status returns 404 "Job not found" (key accepted, not 401),
// and both circuit VKs were registered to Kurier mainnet 16:34 WIB. The
// 16:16 WIB 401 was a helper bug (surrogate URL-quoted in the path), not
// the key. UPDATE 2026-11-14 ~20:02 WIB: KURIER_API_KEY was set in the
// Vercel env (live /health shows kurierConfigured:true), which — with no
// separate submit gate in the code — silently turned submissions ON at
// ~$0.005/proof before the owner approved that cost. Fixed 2026-11-14
// ~21:30 WIB audit: submissions now ALSO require the explicit opt-in
// KURIER_SUBMIT=true (see kurierSubmitEnabled below); default OFF.
// Until the owner approves, the agent still returns decisions with
// locally generated proofs and never submits them.
// VM-side verification uses the connector custom.kurier helper, which reads
// the key via dynamic_credentials (surrogate, never hardcoded):
//   python3 ~/workspace/custom-connectors/custom.kurier/bin/client.py
//     job-status <jobId> | register-vk <vk.json> | submit-proof <proof.json>
// The DEPLOYED endpoint cannot use that helper (no authd on Vercel), so it
// reads KURIER_API_KEY from the environment instead.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { groth16, zKey } from "snarkjs";
import { modP, hashToField, addressToField, idToField, randomSalt } from "./field.js";

export const CIRCUIT_INFO = {
  gatekeeper: {
    vkHash: "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0",
    wasmUrl: "https://agentgames.zkverify.io/circuits/gatekeeper.wasm",
    zkeyUrl: "https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey",
    wasmFile: "gatekeeper.wasm",
    zkeyFile: "gatekeeper_final.zkey",
  },
  vfyPolicy: {
    vkHash: "0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047",
    wasmUrl: "https://agentgames.zkverify.io/circuits/vfy-policy.wasm",
    zkeyUrl: "https://agentgames.zkverify.io/circuits/vfy-policy_final.zkey",
    wasmFile: "vfy-policy.wasm",
    zkeyFile: "vfy-policy_final.zkey",
  },
};

function circuitsDir() {
  if (process.env.CIRCUITS_DIR) return process.env.CIRCUITS_DIR;
  const local = path.join(process.cwd(), "circuits");
  if (fs.existsSync(path.join(local, "gatekeeper.wasm"))) return local;
  return path.join(os.tmpdir(), "warden-agentgames-circuits");
}

const downloadLocks = new Map();

async function downloadFile(url, dest) {
  const res = await fetch(url, { signal: AbortSignal.timeout(60000) });
  if (!res.ok) throw new Error(`download ${url} failed: HTTP ${res.status}`);
  const buf = Buffer.from(await res.arrayBuffer());
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.writeFileSync(dest, buf);
  return dest;
}

export async function ensureArtifacts(name) {
  const info = CIRCUIT_INFO[name];
  const dir = circuitsDir();
  const wasmPath = path.join(dir, info.wasmFile);
  const zkeyPath = path.join(dir, info.zkeyFile);
  if (fs.existsSync(wasmPath) && fs.existsSync(zkeyPath)) {
    return { wasmPath, zkeyPath };
  }
  if (!downloadLocks.has(name)) {
    downloadLocks.set(name, (async () => {
      if (!fs.existsSync(wasmPath)) await downloadFile(info.wasmUrl, wasmPath);
      if (!fs.existsSync(zkeyPath)) await downloadFile(info.zkeyUrl, zkeyPath);
      return { wasmPath, zkeyPath };
    })().finally(() => downloadLocks.delete(name)));
  }
  return downloadLocks.get(name);
}

const vkCache = new Map();

export async function getVerificationKey(name) {
  if (vkCache.has(name)) return vkCache.get(name);
  const { zkeyPath } = await ensureArtifacts(name);
  const vk = await zKey.exportVerificationKey(zkeyPath);
  vkCache.set(name, vk);
  return vk;
}

// Generate a Groth16 proof and verify it locally before returning it.
// Returns { proof, publicSignals } or throws with a clear message.
async function prove(name, input, wasmPath, zkeyPath) {
  const { proof, publicSignals } = await groth16.fullProve(input, wasmPath, zkeyPath);
  const vk = await getVerificationKey(name);
  const ok = await groth16.verify(vk, publicSignals, proof);
  if (!ok) throw new Error(`local proof verification failed for ${name}`);
  return { proof, publicSignals };
}

// Gatekeeper decision proof. decision: 1 = APPROVE, 0 = REJECT.
// Encodings (see README): addresses as BigInt, hashes mod p, taskId as
// keccak256(task_id) mod p, salt random per proof.
export async function generateGatekeeperProof(task, decision) {
  const input = task?.input ?? task;
  const salt = randomSalt();
  const circuitInput = {
    decision: decision === 1 || decision === "APPROVE" ? 1 : 0,
    taskId: idToField(String(task.task_id ?? task.taskId ?? "")),
    registeredVkHash: hashToField(input.registered_vk),
    proofVkHash: hashToField(input.proof_vk),
    minimum: BigInt(input.minimum),
    publicBalance: BigInt(input.public_balance),
    expiryBlock: BigInt(input.expiry_block),
    currentBlock: BigInt(input.current_block),
    recipient: addressToField(input.recipient),
    conditionRecipient: addressToField(input.condition_recipient),
    amount: BigInt(input.amount),
    maxTransfer: BigInt(input.max_transfer),
    salt,
  };
  const { wasmPath, zkeyPath } = await ensureArtifacts("gatekeeper");
  return prove("gatekeeper", circuitInput, wasmPath, zkeyPath);
}

// The salt the strategy commitment was registered with. Env first
// (Vercel production: AGENT_GAMES_VFY_SALT), then the local mode-600
// file ~/.config/agentgames/vfy-salt.json (created by
// scripts/register-commitment.mjs). Returns a BigInt, or null when
// neither is configured.
export function getRegisteredSalt() {
  const env = process.env.AGENT_GAMES_VFY_SALT;
  if (env && env.trim() !== "") {
    try {
      return BigInt(env.trim());
    } catch { /* fall through to file */ }
  }
  try {
    const file = path.join(os.homedir(), ".config", "agentgames", "vfy-salt.json");
    const data = JSON.parse(fs.readFileSync(file, "utf8"));
    if (data && data.salt != null) return BigInt(data.salt);
  } catch { /* no file or bad JSON */ }
  return null;
}

// Steal the VFY policy proof. action: "HOLD" | "FORTIFY" | "EXTRACT".
// strategyParams: the 8 private policy parameters (see strategy.js).
// CRITICAL: the salt MUST be the REGISTERED salt (the one the
// commitment was computed from). The circuit's line-72 assert checks
// Poseidon(params, salt) == commitment; a fresh random salt per proof
// (the old behavior) ALWAYS fails it, so the proof is null and the
// turn scores HOLD. When no registered salt is configured this throws
// a clear error instead of silently producing a null proof.
export async function generatePolicyProof({ commitment, matchId, turn, selfBalance, opponentBalance, action, amount, strategyParams }) {
  const { ACTION_CODE } = await import("./strategy.js");
  const salt = getRegisteredSalt();
  if (salt === null) {
    throw new Error("vfy-policy: no registered salt configured — set AGENT_GAMES_VFY_SALT (Vercel env) or ~/.config/agentgames/vfy-salt.json; without it the line-72 commitment assert cannot pass");
  }
  const circuitInput = {
    action: ACTION_CODE[action],
    matchId: BigInt("0x" + String(matchId).replace(/-/g, "")),
    turnNumber: Number(turn),
    commitment: hashToField(commitment),
    selfBalance: BigInt(selfBalance),
    opponentBalance: BigInt(opponentBalance),
    amount: Number(amount ?? 0),
    circuitVersion: 1,
    salt,
    strategyParams: strategyParams.map((v) => BigInt(v)),
  };
  const { wasmPath, zkeyPath } = await ensureArtifacts("vfyPolicy");
  return prove("vfyPolicy", circuitInput, wasmPath, zkeyPath);
}

// ---- Kurier ----
// Docs: https://docs.zkverify.io/overview/getting-started/kurier
//   POST {API_URL}/register-vk/{KEY}      (once per vk)
//   POST {API_URL}/submit-proof/{KEY}     { proofType, vkRegistered, proofOptions, proofData }
//   GET  {API_URL}/job-status/{KEY}/{jobId}  -> { status: Queued|Valid|Submitted|IncludedInBlock|Finalized|Failed }
// Key: create an account at kurier.xyz and generate one from the dashboard.
const KURIER_URL = process.env.KURIER_API_URL || "https://api.kurier.xyz/api/v1";

export function kurierConfigured() {
  return Boolean(process.env.KURIER_API_KEY);
}

// Submission gate (added 2026-11-14 audit): the key being present used
// to be the only switch, so setting KURIER_API_KEY in Vercel on
// 2026-11-14 ~20:02 WIB silently turned submissions ON (~$0.005/proof)
// before the owner approved that cost. Submission now needs the explicit
// opt-in KURIER_SUBMIT=true as well. Default OFF; the owner enables it
// by setting KURIER_SUBMIT=true in the Vercel env (outside a scored
// round window, then redeploy).
export function kurierSubmitEnabled() {
  return process.env.KURIER_SUBMIT === "true" && kurierConfigured();
}

let vkRegistered = new Set();

export async function registerVk(vkHash) {
  const key = process.env.KURIER_API_KEY;
  if (!key) return { status: "skipped", reason: "no KURIER_API_KEY" };
  if (vkRegistered.has(vkHash)) return { status: "already" };
  const res = await fetch(`${KURIER_URL}/register-vk/${key}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    // proofOptions is REQUIRED by the API (422 without it:
    // "[proofOptions]: Invalid input: expected object, received
    // undefined" — seen live 2026-11-14 23:28 WIB).
    body: JSON.stringify({ proofType: "groth16", proofOptions: { library: "snarkjs", curve: "bn128" }, vk: vkHash }),
    signal: AbortSignal.timeout(30000),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) return { status: "failed", http: res.status, data };
  vkRegistered.add(vkHash);
  return { status: "ok", data };
}

export async function submitProofToKurier({ proof, publicSignals, vkHash }) {
  const key = process.env.KURIER_API_KEY;
  if (!key) return { status: "skipped", reason: "no KURIER_API_KEY" };
  const reg = await registerVk(vkHash);
  if (reg.status === "failed") {
    console.warn("[kurier] register-vk failed, submitting anyway:", JSON.stringify(reg).slice(0, 300));
  }
  const res = await fetch(`${KURIER_URL}/submit-proof/${key}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      proofType: "groth16",
      vkRegistered: true,
      proofOptions: { library: "snarkjs", curve: "bn128" },
      proofData: { proof, publicSignals, vk: vkHash },
    }),
    signal: AbortSignal.timeout(30000),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) return { status: "failed", http: res.status, data };
  return { status: "submitted", jobId: data.jobId ?? data.job_id ?? data.id ?? null, data };
}

// Poll job-status until Finalized/Failed or the deadline. Returns the
// last known status. Never throws on network errors (returns "unknown").
export async function pollJobFinalized(jobId, deadlineMs, intervalMs = 5000) {
  const key = process.env.KURIER_API_KEY;
  if (!key || !jobId) return { status: "skipped" };
  let last = "unknown";
  let lastData = null;
  while (Date.now() < deadlineMs) {
    try {
      const res = await fetch(`${KURIER_URL}/job-status/${key}/${jobId}`, {
        signal: AbortSignal.timeout(10000),
      });
      const data = await res.json().catch(() => ({}));
      last = data.status ?? data.state ?? "unknown";
      lastData = data;
      if (last === "Finalized" || last === "Failed") return { status: last, data: lastData };
    } catch (e) {
      last = "unknown";
    }
    const wait = Math.min(intervalMs, Math.max(0, deadlineMs - Date.now()));
    if (wait <= 0) break;
    await new Promise((r) => setTimeout(r, wait));
  }
  return { status: last, data: lastData };
}
