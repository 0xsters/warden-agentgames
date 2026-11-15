// Local smoke test. No real secrets, no network calls to Kurier.
// Usage: node scripts/smoke-test.mjs
//   SMOKE_FULL_PROOF=1  also generate real Groth16 proofs (needs the
//   circuit artifacts from `npm run setup`; slow, ~1-2 min).
import { handleAgentRequest } from "../src/handler.js";
import { decideGatekeeper } from "../src/gatekeeper.js";
import { decideTurn } from "../src/strategy.js";
import { computePublicInputsHash, computeMatchTurnHash } from "../src/steal.js";
import { signBody } from "../src/hmac.js";
import { markProofTxSeen } from "../src/state.js";

process.env.AGENT_SECRET = process.env.AGENT_SECRET || "smoke-test-secret";
const secret = process.env.AGENT_SECRET;
const FULL_PROOF = process.env.SMOKE_FULL_PROOF === "1";

let pass = 0;
let fail = 0;
function check(name, ok, extra = "") {
  console.log(`${ok ? "PASS" : "FAIL"} ${name} ${extra}`);
  ok ? pass++ : fail++;
}

async function post(body, { sign = true } = {}) {
  const raw = Buffer.from(JSON.stringify(body));
  const headers = sign ? { "x-agent-games-signature": signBody(secret, raw) } : {};
  return handleAgentRequest(raw, headers);
}

// 1. Preflight handshake
{
  const r = await post({ type: "agent-games.preflight.v1", agent_id: "agt_test", issued_at: new Date().toISOString(), nonce: "abc123" });
  const b = JSON.parse(r.body);
  check("preflight ok", r.status === 200 && b.ok === true && b.protocolVersion === "v1", `status=${r.status}`);
  check("preflight signed", Boolean(r.headers["x-agent-games-signature"]));
}

// 2. Unsigned request is rejected
{
  const r = await post({ type: "agent-games.preflight.v1" }, { sign: false });
  check("unsigned -> 401", r.status === 401, `status=${r.status}`);
}

// 3. Bad JSON is rejected
{
  const raw = Buffer.from("{not json");
  const r = await handleAgentRequest(raw, { "x-agent-games-signature": signBody(secret, raw) });
  check("bad JSON -> 400", r.status === 400, `status=${r.status}`);
}

// 4. Gatekeeper decision logic (pure, no proof needed)
{
  const good = {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: "gk_smoke_1",
    mode: "competition",
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60000).toISOString(),
    input: {
      registered_vk: "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0",
      proof_vk: "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0",
      minimum: "1000", public_balance: "1460",
      expiry_block: 8430000, current_block: 8420000,
      recipient: "0xDe42000000000000000000000000000000009f01",
      condition_recipient: "0xDe42000000000000000000000000000000009f01",
      amount: "500", max_transfer: "1000",
      proof_tx: "0xa8b2c3d4e5f60000000000000000000000000000000000000000000000000001",
    },
  };
  const d1 = decideGatekeeper(good);
  check("gatekeeper approves a valid request", d1.decision === "APPROVE" && d1.reason_code === "VALID_CONDITION", d1.reason_code);
  const trap = structuredClone(good);
  trap.task_id = "gk_smoke_2";
  trap.input.proof_vk = "0x13aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  trap.input.proof_tx = "0xa8b2c3d4e5f60000000000000000000000000000000000000000000000000002";
  const d2 = decideGatekeeper(trap);
  check("gatekeeper rejects VK substitution", d2.decision === "REJECT" && d2.reason_code === "VK_SUBSTITUTION", d2.reason_code);
  const trap2 = structuredClone(good);
  trap2.task_id = "gk_smoke_3";
  trap2.input.public_balance = "500";
  trap2.input.proof_tx = "0xa8b2c3d4e5f60000000000000000000000000000000000000000000000000003";
  const d3 = decideGatekeeper(trap2);
  check("gatekeeper rejects threshold mismatch", d3.decision === "REJECT" && d3.reason_code === "THRESHOLD_MISMATCH", d3.reason_code);
  const trap3 = structuredClone(good);
  trap3.task_id = "gk_smoke_4";
  trap3.input.current_block = 8440000;
  trap3.input.proof_tx = "0xa8b2c3d4e5f60000000000000000000000000000000000000000000000000004";
  const d5 = decideGatekeeper(trap3);
  check("gatekeeper rejects expired condition", d5.decision === "REJECT" && d5.reason_code === "EXPIRED_CONDITION", d5.reason_code);
  const trap4 = structuredClone(good);
  trap4.task_id = "gk_smoke_5";
  trap4.input.amount = "1500";
  trap4.input.proof_tx = "0xa8b2c3d4e5f60000000000000000000000000000000000000000000000000005";
  const d6 = decideGatekeeper(trap4);
  check("gatekeeper rejects amount overflow", d6.decision === "REJECT" && d6.reason_code === "AMOUNT_OVERFLOW", d6.reason_code);
  const trap5 = structuredClone(good);
  trap5.task_id = "gk_smoke_6";
  trap5.input.recipient = "0xDe42000000000000000000000000000000009f02";
  trap5.input.proof_tx = "0xa8b2c3d4e5f60000000000000000000000000000000000000000000000000006";
  const d7 = decideGatekeeper(trap5);
  check("gatekeeper rejects recipient mismatch", d7.decision === "REJECT" && d7.reason_code === "RECIPIENT_MISMATCH", d7.reason_code);
  markProofTxSeen(good.input.proof_tx);
  const d4 = decideGatekeeper(good);
  check("gatekeeper rejects reused proof_tx", d4.decision === "REJECT" && d4.reason_code === "PROOF_REUSED", d4.reason_code);
}

// 5. Steal the VFY: publicInputsHash is deterministic and well-formed
{
  const args = {
    commitment: "0x7d00000000000000000000000000000000000000000000000000000000000091",
    matchId: "9f4e1b2a-0000-0000-0000-000000000000",
    turn: 3, selfBalance: 95, opponentBalance: 105, action: "EXTRACT", amount: 5,
  };
  const h1 = computePublicInputsHash(args);
  const h2 = computePublicInputsHash(args);
  check("publicInputsHash deterministic + 0x+64hex", h1 === h2 && /^0x[0-9a-f]{64}$/.test(h1), h1);
  // matchTurnHash == publicSignals[0] of a vfy-policy proof (SOLVED
  // 2026-11-14): witness-verified value for matchId
  // 123e4567-e89b-12d3-a456-426614174000, turn 1, version 1.
  const mth = await computeMatchTurnHash({ matchId: "123e4567-e89b-12d3-a456-426614174000", turn: 1, circuitVersion: 1 });
  check("matchTurnHash == witness-verified ps0",
    mth === 21017678960423797365905767365749695188765667476711046899625151230203926919081n, mth.toString());
  const a = decideTurn({ turn: 1, selfBalance: 100, opponentBalance: 100, selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null }, []);
  check("strategy turn 1 extracts", a.type === "EXTRACT" && a.amount === 3, JSON.stringify(a));
  // Circuit policy has NO turn-dependent rule: turn 18, self 120, opp 80
  // is still EXTRACT 3 (self >= 6, opp > 15, hold mode off). The old
  // "protect a late lead by HOLD" heuristic is unprovable, so it was
  // removed from the strategy (see FINDINGS-CORRECTED.md §3).
  const b = decideTurn({ turn: 18, selfBalance: 120, opponentBalance: 80, selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null }, [
    { turn: 16, selfBalance: 118, opponentBalance: 82 },
    { turn: 17, selfBalance: 120, opponentBalance: 80 },
  ]);
  check("strategy late turn still extracts per circuit policy", b.type === "EXTRACT" && b.amount === 3, JSON.stringify(b));
  const c = decideTurn({ turn: 18, selfBalance: 120, opponentBalance: 10, selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null }, []);
  check("strategy holds when opponent is low", c.type === "HOLD", JSON.stringify(c));
  const d = decideTurn({ turn: 5, selfBalance: 4, opponentBalance: 100, selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null }, []);
  check("strategy fortifies when self is low", d.type === "FORTIFY", JSON.stringify(d));
}

// 6. Full Gatekeeper end-to-end with a real proof (slow, opt-in)
if (FULL_PROOF) {
  const task = {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: "gk_smoke_full_1",
    mode: "competition",
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 120000).toISOString(),
    input: {
      registered_vk: "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0",
      proof_vk: "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0",
      minimum: "1000", public_balance: "1460",
      expiry_block: 8430000, current_block: 8420000,
      recipient: "0xDe42000000000000000000000000000000009f01",
      condition_recipient: "0xDe42000000000000000000000000000000009f01",
      amount: "500", max_transfer: "1000",
      proof_tx: "0xa8b2c3d4e5f60000000000000000000000000000000000000000000000000009",
    },
  };
  const r = await post(task);
  const b = JSON.parse(r.body);
  check("full gatekeeper returns APPROVE with a proof", r.status === 200 && b.decision === "APPROVE" && Boolean(b.proof) && Boolean(b.public_signals), `status=${r.status} proof=${Boolean(b.proof)}`);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
