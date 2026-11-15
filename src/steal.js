// Steal the VFY turn handling.
// publicInputsHash is defined by the platform guide: keccak256 of the
// ABI-packed fields, each padded to 32 bytes big-endian:
//   commitment, matchId (uuid hex as a 128-bit number), turn,
//   selfBalance, opponentBalance, action code (HOLD 0, FORTIFY 1,
//   EXTRACT 2), amount (0 for HOLD / FORTIFY), circuitVersion "v1" -> 1.
import { buildPoseidon } from "circomlibjs";
import { keccakAbiPacked } from "./field.js";
import { ACTION_CODE, CIRCUIT_VERSION_NUM, STRATEGY_PARAMS } from "./strategy.js";

// Strategy commitment (VERIFIED live 2026-11-14 against vfy-policy.wasm):
// standard circomlibjs Poseidon, 9 inputs [params[0..7], salt], t=10,
// RP=60. The leading 0 is the capacity element Poseidon adds itself —
// it is NOT an input: passing [0, ...params, salt] makes t=11 and the
// circuit's line-72 assert fails. The commitment depends on the salt
// chosen at registration; there is no universal hex for the params alone.
let poseidonPromise = null;
export async function computeCommitment(params = STRATEGY_PARAMS, salt) {
  if (!poseidonPromise) poseidonPromise = buildPoseidon();
  const poseidon = await poseidonPromise;
  return poseidon.F.toObject(poseidon([...params.map(BigInt), BigInt(salt)]));
}

export function commitmentToHex(commitment) {
  return "0x" + BigInt(commitment).toString(16).padStart(64, "0");
}

// publicSignals[0] of a vfy-policy proof (SOLVED 2026-11-14, audit round):
// standard circomlibjs Poseidon, 3 inputs [matchId, turnNumber,
// circuitVersion]. Proven two ways: (1) dependency probe — ps[0] changes
// only when matchId/turn/version change, never for balances, action,
// amount, params, salt, or commitment (scratch-probe/ps0-deps.mjs);
// (2) exact match at three distinct inputs (M,1,1), (M,2,1), (M,1,2)
// (scratch-probe/ps0-identify2.mjs, ps0-disambiguate.mjs). It binds the
// proof to one match+turn; the platform can recompute it from the
// envelope alone, no salt or params needed.
export async function computeMatchTurnHash({ matchId, turn, circuitVersion = CIRCUIT_VERSION_NUM }) {
  if (!poseidonPromise) poseidonPromise = buildPoseidon();
  const poseidon = await poseidonPromise;
  const matchNum = BigInt("0x" + String(matchId).replace(/-/g, ""));
  return poseidon.F.toObject(poseidon([matchNum, BigInt(turn), BigInt(circuitVersion)]));
}

export function computePublicInputsHash({ commitment, matchId, turn, selfBalance, opponentBalance, action, amount }) {
  const matchNum = BigInt("0x" + String(matchId).replace(/-/g, ""));
  return keccakAbiPacked([
    BigInt(commitment),
    matchNum,
    BigInt(turn),
    BigInt(selfBalance),
    BigInt(opponentBalance),
    BigInt(ACTION_CODE[action]),
    BigInt(amount),
    BigInt(CIRCUIT_VERSION_NUM),
  ]);
}
