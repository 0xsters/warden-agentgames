// Steal the VFY strategy. THIS IS THE FILE TO TUNE.
//
// Game: 100 VFY each, 20 turns per match, highest balance wins, 5 Swiss
// rounds. Actions: HOLD (free, no amount), FORTIFY (cost 2, blocks up to
// 6 VFY of extraction), EXTRACT N (steals up to N, max 10).
//
// CIRCUIT-VALIDATED POLICY (vfy-policy.wasm, probed live 2026-11-14 with
// the witness calculator; see scratch-probe/FINDINGS-CORRECTED.md).
// The circuit enforces the policy exactly: any other action makes the
// witness fail and policyProof null (turn scored HOLD). The policy is:
//
//   1. selfBalance < params[1]           -> FORTIFY
//   2. else params[3] == 1               -> HOLD (global hold mode)
//   3. else opponentBalance <= params[2] -> HOLD
//   4. else                               -> EXTRACT params[0]
//
// Turn number, history, and fortify state do NOT affect the circuit's
// policy (verified turns 1-20). EXTRACT amount must equal params[0]
// (assert line 149); HOLD/FORTIFY amount must be 0 (line 153).
//
// Param validity enforced by the circuit (assert lines in
// VfyPolicyProof_154): params[0] in 1..10 (lines 38/90/95);
// params[3] in {0,1} (line 98); params[4..7] == 0 (lines 75-78).
// The OLD params [3,6,15,15,2,6,10,0] were INVALID (params[3]=15,
// params[4]=2, params[5]=6, params[6]=10 all violate asserts), which is
// why every policy proof failed. The meanings below are the circuit's
// ground truth, NOT the earlier guesses: there is no "catchUpExtract 6"
// or "protectLeadTurn" in the circuit — EXTRACT is always params[0],
// and there is no turn-dependent rule.
//
//   [0] extractAmount = 3   EXTRACT amount (1..10)
//   [1] fortifyBelow  = 6   FORTIFY when our balance is below this
//   [2] holdAtOrBelow = 15  HOLD when opponent balance is at/below this
//   [3] holdMode      = 0   1 = always HOLD (except FORTIFY); keep 0
//   [4] reserved      = 0   circuit requires 0
//   [5] reserved      = 0   circuit requires 0
//   [6] reserved      = 0   circuit requires 0
//   [7] reserved      = 0   circuit requires 0
export const STRATEGY_PARAMS = [3, 6, 15, 0, 0, 0, 0, 0];

// The circuit version this agent proves against.
export const CIRCUIT_VERSION = "v1";
export const CIRCUIT_VERSION_NUM = 1;

export const ACTION_CODE = { HOLD: 0, FORTIFY: 1, EXTRACT: 2 };

// Decide one turn, following the circuit policy exactly. state:
// { selfBalance, opponentBalance, turn, selfFortifiedUntilTurn,
// opponentFortifiedUntilTurn }. history is accepted for compatibility
// but the circuit ignores it (turn/history/fortify state do not affect
// the policy). Returns { type: "HOLD" | "FORTIFY" | "EXTRACT", amount? }.
// amount is OMITTED for HOLD and FORTIFY (the platform rejects it even
// when it is 0; the circuit also requires amount 0 for them, line 153).
export function decideTurn(state, history = []) {
  const [extractAmount, fortifyBelow, holdAtOrBelow, holdMode] = STRATEGY_PARAMS;
  const self = Number(state.selfBalance);
  const opp = Number(state.opponentBalance);
  if (self < fortifyBelow) return { type: "FORTIFY" };
  if (holdMode === 1) return { type: "HOLD" };
  if (opp <= holdAtOrBelow) return { type: "HOLD" };
  return { type: "EXTRACT", amount: extractAmount };
}
