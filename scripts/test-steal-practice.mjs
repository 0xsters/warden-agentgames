// Regression test for the 2026-11-14 23:42 WIB Steal practice failure:
// the platform rejected the turn as "missing or mis-typing a required
// protocol field". Root causes fixed in src/handler.js:
//   1. Practice envelopes carry NO strategyCommitment -> the handler
//      now falls back to the locally registered commitment
//      (STRATEGY_PARAMS + registered salt) so publicInputsHash computes
//      and a real policy proof can be generated.
//   2. policyProof is now exactly the spec shape
//      { circuitVersion, proofReference, publicInputsHash }
//      (proof/publicSignals were sent as null before, failing the
//      platform's schema check).
// Usage: node scripts/test-steal-practice.mjs
//   FULL_PROOF=1  also generate a real Groth16 policy proof (needs the
//   circuit artifacts + the registered salt file; ~1-2 min).
import { handleAgentRequest } from "../src/handler.js";
import { signBody } from "../src/hmac.js";
import { computeCommitment, computePublicInputsHash } from "../src/steal.js";
import { generatePolicyProof, getRegisteredSalt } from "../src/proof.js";
import { STRATEGY_PARAMS } from "../src/strategy.js";

process.env.AGENT_SECRET = "test-secret-steal-practice";
const secret = process.env.AGENT_SECRET;
const FULL_PROOF = process.env.FULL_PROOF === "1";

let pass = 0;
let fail = 0;
function check(name, ok, extra = "") {
  console.log(`${ok ? "PASS" : "FAIL"} ${name} ${extra}`);
  ok ? pass++ : fail++;
}

// A practice turn exactly as the platform sends it: NO strategyCommitment.
const envelope = {
  type: "agent-games.steal-the-vfy.v1",
  eventId: "steal-the-vfy",
  matchId: "11111111-2222-3333-4444-555555555555",
  turn: 1,
  state: { selfBalance: 5, opponentBalance: 100 },
  issued_at: new Date().toISOString(),
  deadline_at: new Date(Date.now() + 300000).toISOString(),
};

const raw = Buffer.from(JSON.stringify(envelope));
const r = await handleAgentRequest(raw, { "x-agent-games-signature": signBody(secret, raw) });
const b = JSON.parse(r.body);

check("status 200", r.status === 200, `status=${r.status}`);
check("signed response", Boolean(r.headers["x-agent-games-signature"]));
check("matchId echoed", b.matchId === envelope.matchId);
check("turn echoed", b.turn === 1);
// Policy: selfBalance 5 < params[1]=6 -> FORTIFY, no amount field.
check("action FORTIFY, no amount", b.action?.type === "FORTIFY" && !("amount" in (b.action ?? {})), JSON.stringify(b.action));
const ppKeys = Object.keys(b.policyProof ?? {}).sort();
check(
  "policyProof exactly {circuitVersion, proofReference, publicInputsHash}",
  JSON.stringify(ppKeys) === JSON.stringify(["circuitVersion", "proofReference", "publicInputsHash"]),
  ppKeys.join(",")
);
check("circuitVersion v1", b.policyProof?.circuitVersion === "v1");
check(
  "publicInputsHash non-null 0x hex",
  typeof b.policyProof?.publicInputsHash === "string" && /^0x[0-9a-f]{64}$/.test(b.policyProof.publicInputsHash),
  String(b.policyProof?.publicInputsHash).slice(0, 20)
);
// The hash must match an independent recomputation from the LOCAL
// commitment (proves the fallback path ran, not the null path).
const salt = getRegisteredSalt();
check("registered salt available", salt !== null);
if (salt !== null) {
  const localCommitment = await computeCommitment(STRATEGY_PARAMS, salt);
  const expected = computePublicInputsHash({
    commitment: localCommitment, matchId: envelope.matchId, turn: 1,
    selfBalance: 5, opponentBalance: 100, action: "FORTIFY", amount: 0,
  });
  check("publicInputsHash matches local-commitment recomputation", b.policyProof?.publicInputsHash === expected);
}
// proofReference is null locally (no Kurier key in this env); live on
// Vercel (KURIER_SUBMIT=true) it must be the Kurier jobId string.
check(
  "proofReference null-or-string (local: null expected)",
  b.policyProof?.proofReference === null || typeof b.policyProof?.proofReference === "string",
  String(b.policyProof?.proofReference)
);

if (FULL_PROOF) {
  // Direct proof generation with the fallback commitment: prove()
  // verifies the proof locally and throws otherwise.
  const localCommitment = await computeCommitment(STRATEGY_PARAMS, salt);
  const t0 = Date.now();
  const { proof, publicSignals } = await generatePolicyProof({
    commitment: localCommitment, matchId: envelope.matchId, turn: 1,
    selfBalance: 5, opponentBalance: 100, action: "FORTIFY", amount: 0,
    strategyParams: STRATEGY_PARAMS,
  });
  check("policy proof generates + verifies locally", Boolean(proof) && Array.isArray(publicSignals) && publicSignals.length > 0, `${((Date.now() - t0) / 1000).toFixed(1)}s, signals=${publicSignals?.length}`);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
