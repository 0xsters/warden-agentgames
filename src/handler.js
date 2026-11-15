// Request handler: HMAC verification, routing, signing.
// Every inbound request is verified against the RAW body BEFORE parsing.
// Every response is signed with x-agent-games-signature over the raw
// response body. Fail closed everywhere: bad signature -> 401, bad
// JSON -> 400, any uncertainty in a Gatekeeper task -> REJECT.
import crypto from "node:crypto";
import { getSecret, verifySignature, signBody } from "./hmac.js";
import { decideGatekeeper } from "./gatekeeper.js";
import { decideTurn, STRATEGY_PARAMS, CIRCUIT_VERSION } from "./strategy.js";
import { computePublicInputsHash, computeCommitment } from "./steal.js";
import { markProofTxSeen, getMatch, recordTurn, getCachedGatekeeperResponse, cacheGatekeeperResponse, getCachedStealResponse, cacheStealResponse } from "./state.js";
import {
  generateGatekeeperProof,
  generatePolicyProof,
  getRegisteredSalt,
  submitProofToKurier,
  pollJobFinalized,
  kurierConfigured,
  kurierSubmitEnabled,
  CIRCUIT_INFO,
} from "./proof.js";

function jsonResponse(status, obj, secret) {
  const raw = Buffer.from(JSON.stringify(obj));
  const headers = { "content-type": "application/json" };
  if (secret) headers["x-agent-games-signature"] = signBody(secret, raw);
  return { status, headers, body: raw.toString("utf8") };
}

function errorResponse(status, message, secret) {
  return jsonResponse(status, { error: message }, secret);
}

// Budget guard: never let proof work push the response past the platform
// deadline. Returns ms remaining until the earlier of the task deadline
// and now + 55s.
function msRemaining(task) {
  const hard = Date.now() + 55000;
  const d = task?.deadline_at ?? task?.deadlineAt;
  if (d) {
    const t = Date.parse(d);
    if (!Number.isNaN(t)) return Math.max(0, Math.min(t, hard) - Date.now());
  }
  return Math.max(0, hard - Date.now());
}

async function handleGatekeeper(task, secret) {
  const taskId = task?.task_id ?? task?.taskId ?? null;
  // Idempotency: a platform retry of the same task_id gets the exact
  // same response, not a fresh decision (which would misread the
  // already-accepted proof as PROOF_REUSED).
  if (taskId) {
    const cached = getCachedGatekeeperResponse(taskId);
    if (cached) return { ...cached, headers: { ...cached.headers } };
  }
  const decision = decideGatekeeper(task);
  const input = task?.input ?? task;
  // Only an ACCEPTED proof counts as "seen": a rejected task must not
  // poison later tasks that reference the same proof_tx.
  if (decision.decision === "APPROVE" && input?.proof_tx) markProofTxSeen(input.proof_tx);

  const remaining = msRemaining(task);
  let proof = null;
  let publicSignals = null;
  // Proof generation is expensive; only attempt it when there is time.
  if (remaining > 15000) {
    try {
      const r = await generateGatekeeperProof(task, decision.decision === "APPROVE" ? 1 : 0);
      proof = r.proof;
      publicSignals = r.publicSignals;
    } catch (e) {
      console.error("[gatekeeper] proof generation failed:", String(e?.message ?? e).slice(0, 300));
    }
  } else {
    console.warn("[gatekeeper] proof generation skipped: not enough time before deadline");
  }

  if (proof && kurierSubmitEnabled()) {
    try {
      const sub = await submitProofToKurier({ proof, publicSignals, vkHash: CIRCUIT_INFO.gatekeeper.vkHash });
      // For APPROVE, wait for Finalized inside the remaining budget.
      if (decision.decision === "APPROVE" && sub.status === "submitted" && sub.jobId) {
        const pollDeadline = Date.now() + Math.max(0, msRemaining(task) - 3000);
        const polled = await pollJobFinalized(sub.jobId, pollDeadline);
        console.log("[gatekeeper] kurier:", sub.status, "->", polled.status, "job", sub.jobId);
      } else {
        console.log("[gatekeeper] kurier:", sub.status, "job", sub.jobId ?? null);
      }
    } catch (e) {
      console.error("[gatekeeper] kurier error:", String(e?.message ?? e).slice(0, 300));
    }
  } else if (proof && !kurierConfigured()) {
    console.warn("[gatekeeper] KURIER_API_KEY not set; proof generated locally only, not submitted");
  } else if (proof) {
    console.log("[gatekeeper] kurier submit disabled (KURIER_SUBMIT != 'true'); proof generated locally only, not submitted");
  }

  // Response shape: exactly the documented union (build page + starter
  // prompt): decision, reason_code, proof_tx, proof, public_signals.
  // No extra fields — the platform requires responses to match the
  // schema, and extras (task_id, kurier_status, ...) are ours, not
  // the platform's. Kurier/proof diagnostics stay in the server logs.
  const response = jsonResponse(200, {
    decision: decision.decision,
    reason_code: decision.reason_code,
    proof_tx: input?.proof_tx ?? null,
    proof,
    public_signals: publicSignals,
  }, secret);
  if (taskId) cacheGatekeeperResponse(taskId, response);
  return response;
}

async function handleSteal(envelope, secret) {
  const matchId = envelope.matchId;
  const turn = Number(envelope.turn);
  // Retry of an already-answered turn returns the SAME response instead
  // of re-deciding and recording the turn a second time.
  const cachedSteal = getCachedStealResponse(matchId, turn);
  if (cachedSteal) {
    // Never serve a stale BAD response: a cached proofReference that is
    // not an on-chain tx hash (null, or a Kurier jobId) was built by older
    // code and fails the platform schema. Recompute instead.
    let cachedRef = null;
    try { cachedRef = JSON.parse(cachedSteal.body)?.policyProof?.proofReference ?? null; } catch {}
    if (typeof cachedRef === "string" && /^0x[0-9a-fA-F]{64}$/.test(cachedRef)) {
      console.log("[steal] cache hit (good txHash)", matchId, "turn", turn);
      return cachedSteal;
    }
    console.log("[steal] cache stale (bad proofReference), recompute", matchId, "turn", turn);
  }
  const state = envelope.state ?? {};
  const selfBalance = Number(state.selfBalance);
  const opponentBalance = Number(state.opponentBalance);
  const commitment = envelope.strategyCommitment?.hash ?? envelope.strategyCommitment ?? null;
  // Practice turns carry no strategyCommitment (nothing is registered
  // yet): fall back to the locally registered commitment so the proof
  // can still be generated and the response stays schema-valid.
  // Without this, publicInputsHash throws (BigInt(null)), the proof is
  // skipped, and the platform rejects the turn as "missing a required
  // protocol field" — exactly the 23:42 WIB practice failure.
  let effectiveCommitment = commitment;
  if (!effectiveCommitment) {
    const salt = getRegisteredSalt();
    if (salt !== null) {
      try {
        effectiveCommitment = await computeCommitment(STRATEGY_PARAMS, salt);
      } catch (e) {
        console.error("[steal] local commitment failed:", String(e?.message ?? e).slice(0, 200));
      }
    }
  }
  const match = getMatch(matchId);
  const history = match.turns.map((t) => ({
    turn: t.turn, selfBalance: t.selfBalance, opponentBalance: t.opponentBalance,
  }));

  const action = decideTurn(
    {
      turn, selfBalance, opponentBalance,
      selfFortifiedUntilTurn: state.selfFortifiedUntilTurn ?? null,
      opponentFortifiedUntilTurn: state.opponentFortifiedUntilTurn ?? null,
    },
    history
  );
  const amount = action.type === "EXTRACT" ? Number(action.amount) : 0;

  let publicInputsHash = null;
  try {
    publicInputsHash = computePublicInputsHash({
      commitment: effectiveCommitment, matchId, turn, selfBalance, opponentBalance,
      action: action.type, amount,
    });
  } catch (e) {
    console.error("[steal] publicInputsHash failed:", String(e?.message ?? e).slice(0, 200));
  }

  let proof = null;
  let publicSignals = null;
  let proofReference = null;
  let kurierStatus = "skipped";
  const remaining = msRemaining(envelope);
  console.log("[steal] turn", matchId, "turn", turn, "remaining", remaining, "commitment", effectiveCommitment ? "yes" : "no", "action", action.type);
  // Practice envelopes arrive with only ~14s left (the platform's ~30s
  // push window is mostly spent before the request reaches us). The old
  // 15s gate skipped the proof on every practice turn, so proofReference
  // was null and the platform rejected the turn. Proof generation takes
  // ~1s and the Kurier submit ~1.5s, so a 5s gate leaves room for both.
  if (remaining > 5000 && effectiveCommitment) {
    try {
      const r = await generatePolicyProof({
        commitment: effectiveCommitment, matchId, turn, selfBalance, opponentBalance,
        action: action.type, amount, strategyParams: STRATEGY_PARAMS,
      });
      proof = r.proof;
      publicSignals = r.publicSignals;
      if (kurierSubmitEnabled()) {
        try {
          const sub = await submitProofToKurier({ proof, publicSignals, vkHash: CIRCUIT_INFO.vfyPolicy.vkHash });
          kurierStatus = sub.status;
          proofReference = sub.jobId ?? null;
          if (sub.status !== "submitted") {
            console.log("[steal] kurier submit not submitted:", sub.status, JSON.stringify(sub).slice(0, 300));
          }
          // proofReference must be the ON-CHAIN tx hash: the platform
          // checks "policy proof transaction confirmed on-chain", and a
          // Kurier jobId (UUID) is not resolvable on-chain — sending it
          // is what the 23:49 WIB practice re-test rejected as a schema
          // error (proof + submit both succeeded, no error logged).
          // Poll the job until Finalized and use its txHash, keeping
          // the total response inside the ~30s push wait.
          if (sub.status === "submitted" && sub.jobId) {
            const pollBudgetMs = Math.max(0, Math.min(msRemaining(envelope) - 2000, 25000));
            if (pollBudgetMs > 3000) {
              const polled = await pollJobFinalized(sub.jobId, Date.now() + pollBudgetMs, 2000);
              console.log("[steal] kurier:", sub.status, "->", polled.status, "job", sub.jobId);
              if (polled.status === "Finalized" && polled.data?.txHash) {
                proofReference = polled.data.txHash;
                kurierStatus = "Finalized";
              }
            } else {
              console.log("[steal] kurier poll skipped: budget", pollBudgetMs, "proofReference stays jobId");
            }
          }
        } catch (e) {
          kurierStatus = "error";
          console.error("[steal] kurier error:", String(e?.message ?? e).slice(0, 200));
        }
      } else {
        kurierStatus = kurierConfigured() ? "skipped_submit_disabled" : "skipped_no_key";
      }
    } catch (e) {
      console.error("[steal] policy proof failed:", String(e?.message ?? e).slice(0, 300));
    }
  } else {
    console.log("[steal] proof skipped: remaining", remaining, "commitment", effectiveCommitment ? "yes" : "no");
  }

  recordTurn(matchId, { turn, selfBalance, opponentBalance, action: action.type, amount });

  // amount is OMITTED for HOLD and FORTIFY (the platform rejects it even
  // when it is 0).
  const actionOut = action.type === "EXTRACT"
    ? { type: "EXTRACT", amount }
    : { type: action.type };

  // Spec shape (build page): policyProof is exactly
  // { circuitVersion, proofReference, publicInputsHash }. proof and
  // publicSignals stay internal (they go to Kurier, not the platform);
  // sending them as null used to fail the platform's schema check.
  const stealResponse = jsonResponse(200, {
    matchId,
    turn,
    action: actionOut,
    policyProof: {
      circuitVersion: CIRCUIT_VERSION,
      proofReference,
      publicInputsHash,
    },
    agentTimestamp: new Date().toISOString(),
    idempotencyKey: crypto.randomUUID(),
    ...(kurierConfigured() ? {} : { kurier_status: kurierStatus }),
  }, secret);
  console.log("[steal] answer", matchId, "turn", turn, "action", action.type, "proofRef", proofReference === null ? "null" : (String(proofReference).startsWith("0x") ? "txHash" : "jobId"), "kurier", kurierStatus);
  // Only cache GOOD responses (proofReference = on-chain tx hash). A bad
  // one must never be served again from a warm instance.
  if (typeof proofReference === "string" && /^0x[0-9a-fA-F]{64}$/.test(proofReference)) {
    cacheStealResponse(matchId, turn, stealResponse);
  }
  return stealResponse;
}

// Main entry: rawBody is a Buffer of the exact request bytes.
export async function handleAgentRequest(rawBody, headers = {}) {
  const secret = getSecret();
  if (!secret) {
    console.error("[handler] no AGENT_SECRET configured");
    return errorResponse(500, "agent secret not configured", null);
  }
  const sig = headers["x-agent-games-signature"] ?? headers["X-Agent-Games-Signature"] ?? null;
  if (!verifySignature(secret, rawBody, sig)) {
    return errorResponse(401, "invalid signature", secret);
  }
  let body;
  try {
    body = JSON.parse(rawBody.toString("utf8"));
  } catch {
    return errorResponse(400, "invalid JSON", secret);
  }

  // Preflight handshake.
  if (body?.type === "agent-games.preflight.v1") {
    return jsonResponse(200, { ok: true, protocolVersion: "v1" }, secret);
  }
  // Proof Gatekeeper task.
  if (body?.type === "agent-games.proof-gatekeeper.v1") {
    return handleGatekeeper(body, secret);
  }
  // Steal the VFY turn envelope.
  if (body?.eventId === "steal-the-vfy" || body?.type === "agent-games.steal-the-vfy.v1") {
    return handleSteal(body, secret);
  }
  return errorResponse(400, "unknown envelope type", secret);
}
