// In-memory state. Serverless instances do not share memory, so this is
// best-effort per instance; a durable store (Vercel KV / Upstash) is a
// TODO for production replay protection across instances.

// Proof references already processed, for Gatekeeper replay protection.
const seenProofTx = new Set();
const MAX_SEEN = 10000;

export function hasSeenProofTx(proofTx) {
  return seenProofTx.has(String(proofTx).toLowerCase());
}

export function markProofTxSeen(proofTx) {
  if (seenProofTx.size >= MAX_SEEN) {
    // Drop the oldest entries (insertion order) to bound memory.
    const drop = seenProofTx.size - MAX_SEEN + 100;
    let i = 0;
    for (const k of seenProofTx) {
      seenProofTx.delete(k);
      if (++i >= drop) break;
    }
  }
  seenProofTx.add(String(proofTx).toLowerCase());
}

// Idempotency cache for Gatekeeper responses, keyed by task_id. The
// platform may retry a task after a network failure; a retry must get
// the SAME decision, not PROOF_REUSED. Bounded FIFO, best-effort per
// instance like the seen set above.
const gatekeeperResponses = new Map();
const MAX_CACHED_RESPONSES = 500;

export function getCachedGatekeeperResponse(taskId) {
  return gatekeeperResponses.get(String(taskId)) ?? null;
}

export function cacheGatekeeperResponse(taskId, response) {
  if (gatekeeperResponses.size >= MAX_CACHED_RESPONSES) {
    const first = gatekeeperResponses.keys().next().value;
    if (first !== undefined) gatekeeperResponses.delete(first);
  }
  gatekeeperResponses.set(String(taskId), response);
}

// Per-match state for Steal the VFY: last balances, last actions, turn log.
const matches = new Map();

export function getMatch(matchId) {
  if (!matches.has(matchId)) {
    matches.set(matchId, { turns: [], lastSelf: null, lastOpp: null });
  }
  return matches.get(matchId);
}

export function recordTurn(matchId, record) {
  const m = getMatch(matchId);
  m.turns.push(record);
  m.lastSelf = record.selfBalance;
  m.lastOpp = record.opponentBalance;
  if (m.turns.length > 40) m.turns.splice(0, m.turns.length - 40);
}

// Idempotency cache for Steal the VFY responses, keyed by (matchId, turn).
// The platform may retry a turn after a network failure; a retry must get
// the SAME response, not a re-decision recorded as a second turn (which
// would corrupt history and could change the next decision). Bounded FIFO,
// best-effort per instance like the gatekeeper cache above.
const stealResponses = new Map();
const MAX_STEAL_CACHED = 200;

export function getCachedStealResponse(matchId, turn) {
  return stealResponses.get(`${String(matchId)}:${Number(turn)}`) ?? null;
}

export function cacheStealResponse(matchId, turn, response) {
  const key = `${String(matchId)}:${Number(turn)}`;
  if (stealResponses.size >= MAX_STEAL_CACHED && !stealResponses.has(key)) {
    const first = stealResponses.keys().next().value;
    if (first !== undefined) stealResponses.delete(first);
  }
  stealResponses.set(key, response);
}
