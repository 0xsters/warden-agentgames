# warden-agentgames

Agent **warden** for [zkVerify Agent Games](https://agentgames.zkverify.io)
(event 21 Oct – 21 Nov 2026, 400,000 VFY total prizes).

Two tracks:

- **Proof Gatekeeper (TASK)** — approve or reject ZK-proof payment requests.
  Approve only when every field agrees. Every decision is backed by a
  Groth16 proof of the gatekeeper circuit.
- **Steal the VFY (MATCH)** — head-to-head match, 100 VFY start, 20 turns,
  5 Swiss rounds. Each turn returns an action (HOLD / FORTIFY / EXTRACT)
  plus a Groth16 proof of the vfy-policy circuit.

## How it works

```
POST /agent   (HMAC-signed JSON envelope, 60s deadline)
GET  /health  (liveness + config status)
```

1. The request HMAC (`x-agent-games-signature`) is verified against the
   **raw body** before any parsing. Bad signature -> 401, bad JSON -> 400.
2. The envelope is routed: `agent-games.preflight.v1` handshake,
   `agent-games.proof-gatekeeper.v1` task, or the Steal the VFY turn envelope.
3. Gatekeeper: pure decision logic (`src/gatekeeper.js`) checks input shape,
   vk match, recipient match, threshold, amount limit, expiry, timestamp,
   and replay (a seen set of `proof_tx`). Fail closed: any doubt -> REJECT.
4. A Groth16 proof is generated locally with snarkjs (circuit artifacts are
   downloaded at startup into a temp cache, never committed).
5. If `KURIER_API_KEY` is set, the proof is submitted to Kurier and, for
   APPROVE decisions, polled until Finalized inside the 60s budget.
6. The response is signed with `x-agent-games-signature` over the raw
   response body.

## Files

| File | Purpose |
| --- | --- |
| `api/agent.js` | Vercel entry: POST /agent |
| `api/health.js` | Vercel entry: GET /health |
| `src/server.js` | Local dev server (same handler) |
| `src/handler.js` | Routing, HMAC, deadline budget, signing |
| `src/hmac.js` | HMAC-SHA256 verify/sign |
| `src/gatekeeper.js` | Pure Gatekeeper decision logic |
| `src/steal.js` | `publicInputsHash` (keccak256, platform field order) |
| `src/strategy.js` | **Steal the VFY strategy — edit this to tune play** |
| `src/proof.js` | snarkjs proving + Kurier submit/poll |
| `src/field.js` | bn128 field helpers (mod p, keccak) |
| `src/state.js` | Replay set + per-match state |
| `scripts/setup-circuits.mjs` | Download circuit artifacts for local dev |
| `scripts/smoke-test.mjs` | Local smoke test (no real secrets, no Kurier) |
| `scripts/audit-test.mjs` | Audit test: reason codes, replay/idempotency, response shape, body limit |
| `scripts/test-preflight-live.mjs` | Signed-preflight test against the LIVE endpoint (reads the secret from `~/.config/agentgames/hmac-secret`, never prints it) |

## Circuits

From https://agentgames.zkverify.io/api/circuit-info (Groth16/BN128, Circom 2.x):

| Circuit | vkHash | nPublic |
| --- | --- | --- |
| gatekeeper | `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0` | 13 |
| vfy-policy | `0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047` | 9 |

Circuit binaries (`.wasm` + `.zkey`, ~5.9 MB total) are **not** in the repo:
GitHub snapshot pushes reject non-UTF-8 files. The server downloads them on
first use from `agentgames.zkverify.io/circuits/` into a temp cache
(`src/proof.js` `ensureArtifacts`). Locally, run `npm run setup` once.

### Gatekeeper circuit inputs (verified live with real proofs)

```
decision, taskId, registeredVkHash, proofVkHash, minimum, publicBalance,
expiryBlock, currentBlock, recipient, conditionRecipient, amount,
maxTransfer, salt
```

Encoding, all as bn128 field elements: hashes (vk, taskId) = keccak256 mod p
(the raw vk hash is larger than the field prime, so mod p is required);
addresses as integers; numbers as-is; decision 1 = APPROVE, 0 = REJECT;
salt random. Verified: a correct APPROVE proves, a correct REJECT proves,
and a wrong decision (approve a trap / reject a valid request) fails the
circuit — the circuit enforces correctness, not just well-formedness.

### vfy-policy circuit inputs

```
public signals (9, in proof order): [matchTurnHash, commitment, matchId, turnNumber,
  selfBalance, opponentBalance, action, amount, circuitVersion]
  (signal 1 = Poseidon([matchId, turnNumber, circuitVersion]), SOLVED
  2026-11-14 — see computeMatchTurnHash in src/steal.js; signals 2-9 are
  the named inputs in that order)
private: strategyParams[8] (witness 10..13 = params[0..3],
  witness 31..34 = params[4..7]) and salt (witness 14, PRIVATE)
```

Action codes: HOLD 0, FORTIFY 1, EXTRACT 2. `matchId` = UUID as a 128-bit
integer. `commitment` = strategy commitment (Poseidon output, a field
element). `circuitVersion`: "v1" -> 1. `strategyParams` are the 8 private
policy parameters in `src/strategy.js`.

> **SOLVED 2026-11-14 (witness-oracle probing, see
> `scratch-probe/FINDINGS-CORRECTED.md`):** the commitment binding is
> standard circomlibjs Poseidon, 9 inputs `[params[0..7], salt]`, t=10
> (assert line 72). The leading 0 is Poseidon's own capacity element,
> NOT an input. Param validity enforced by the circuit: `params[0]` in
> 1..10 (lines 38/90/95), `params[3]` in {0,1} (line 98),
> `params[4..7] == 0` (lines 75-78). Policy enforced by the circuit
> (lines 140/149/153): FORTIFY if `selfBalance < params[1]`; else HOLD
> if `params[3] == 1` or `opponentBalance <= params[2]`; else EXTRACT
> `params[0]`. Turn number, history, and fortify state do NOT affect
> the policy. The OLD params `[3,6,15,15,2,6,10,0]` were INVALID
> (`params[3]=15`, `params[4]=2`, `params[5]=6`, `params[6]=10` all
> violate asserts) — that, plus a fresh random salt per proof, is why
> every policy proof used to be null. The endpoint now uses
> `STRATEGY_PARAMS = [3, 6, 15, 0, 0, 0, 0, 0]` and the REGISTERED
> salt (`AGENT_GAMES_VFY_SALT` env or `~/.config/agentgames/vfy-salt.json`).
> Full policy proofs verified live (groth16.verify OK) for EXTRACT,
> FORTIFY, and HOLD turns.

## Steal the VFY strategy (default)

In `src/strategy.js`, `STRATEGY_PARAMS = [3, 6, 15, 0, 0, 0, 0, 0]`,
`CIRCUIT_VERSION = "v1"`. The policy is dictated by the circuit
(see above); the agent plays exactly what the circuit accepts:

- Our balance below 6: FORTIFY (cost 2, blocks up to 6 extraction).
- Opponent balance at or below 15: HOLD.
- Otherwise: EXTRACT 3.

There is no turn-dependent rule, no catch-up EXTRACT 6, and no
low-balance HOLD in the circuit — the old heuristic (probe/catch-up/
protect-lead) is NOT provable and was removed. `decideTurn(state,
history)` is the only place the policy lives. The response never sends
`action.amount` for HOLD or FORTIFY, and every turn gets a fresh
`idempotencyKey`.

## Run locally

```bash
npm install
npm run setup          # download circuit artifacts into ./circuits/
cp .env.example .env   # set AGENT_SECRET (any test value locally)
npm start              # http://localhost:3000
npm test               # smoke test (fast, no proofs)
npm run audit          # audit test: reason codes, replay/idempotency,
                       # response shape, body limit (fast, no proofs)
SMOKE_FULL_PROOF=1 npm test   # also generate a real Gatekeeper proof
```

## Deploy (Vercel)

```bash
vercel --prod
```

The project is a plain Node serverless app (`api/agent.js`, `api/health.js`,
`maxDuration: 60` on `/agent`). **Production reality (found 2026-11-14
while debugging `/health`): the Vercel project builds ONE bundled
function ("index", ~6MB) from `src/server.js` — that is what actually
serves `/agent` and `/health` in production, not the `api/` entries
(fingerprints: `GET /health?x=1` and `GET /health/` both 404, `GET
/agent` 404 instead of 405, exactly like `src/server.js`'s strict
`req.url === "/health"` check). Keep the health shape in sync in BOTH
`src/server.js` and `api/health.js`. Set these env vars in the Vercel dashboard:

| Var | Value |
| --- | --- |
| `AGENT_SECRET` | HMAC secret from the Agent Games dashboard (**Rotate Secret**, after registration). Set 2026-11-14 17:13 WIB (real platform secret, replaced the placeholder). |
| `AGENT_GAMES_VFY_SALT` | The salt the strategy commitment was registered with (decimal string). The endpoint needs the SAME salt to generate vfy-policy proofs; without it every policy proof is null. Set from `~/.config/agentgames/vfy-salt.json` (mode 600, created by `node scripts/register-commitment.mjs`). Never commit it. |
| `KURIER_API_KEY` | Kurier mainnet API key (see TODO below). Leave unset until the key verifies. |

The public endpoint is the full handler path, e.g.
`https://<project>.vercel.app/agent` (not the root).

## Kurier (proof submission)

Kurier verifies Groth16 proofs on zkVerify without running a node.
Base: `https://api.kurier.xyz/api/v1`. Key is free at kurier.xyz
(mainnet key; testnet keys do not carry over to mainnet, and signup
needs a verified email). Cost per the live pricing endpoint (x402,
Base USDC): **$0.005 per submit-proof, $0.001 per register-vk**.
Kurier submission stays OFF until the owner approves that cost
(explicit opt-in `KURIER_SUBMIT=true` in the Vercel env, in addition to
the key; see `kurierSubmitEnabled()` in `src/proof.js`). History: the
key was set in Vercel ~20:02 WIB 2026-11-14 while the code had no
separate submit gate, so submissions were silently ON until the
2026-11-14 ~21:30 WIB audit added the gate (deploy pending, outside
the scored-round window).

- **Deployed endpoint:** reads `KURIER_API_KEY` from the environment.
  If unset, the agent still runs and returns decisions, but proof
  submission is skipped and logged (`kurier_status: skipped_no_key`).
- **VM-side verification** (connector `custom.kurier`, doc + helper at
  `~/workspace/custom-connectors/custom.kurier/`): the helper reads the
  key via `dynamic_credentials` (surrogate, never hardcoded) and offers
  `job-status` / `register-vk` / `submit-proof`:
  `python3 ~/workspace/custom-connectors/custom.kurier/bin/client.py job-status <jobId>`.
  Before the first proof, register each circuit vk once with `register-vk`.

## TODO (in order)

1. **Register the agent** on the Agent Games dashboard (Proof Gatekeeper
   only; Steal the VFY entry is locked during the tournament). Save the
   issued HMAC secret to a mode-600 file immediately, then set
   `AGENT_SECRET` in the Vercel Production env and redeploy.
2. **Verify live:** `GET /health` returns `secretConfigured: true`, and
   the signed preflight
   (`node scripts/test-preflight-live.mjs <endpoint>/agent <secret-file>`)
   returns HTTP 200 `{"ok":true,"protocolVersion":"v1"}` with a valid
   response signature.
3. **Kurier:** same key as the zeez agent; `KURIER_API_KEY` and
   `KURIER_SUBMIT=true` are set in the Vercel Production env (API-key
   path is free within quota; circuit vks already registered on Kurier
   mainnet, no `register-vk` needed).
4. **No Steal commitment:** this agent is Gatekeeper-only, so no
   `AGENT_GAMES_VFY_SALT` is set.

## Security

- No secret is ever committed: `AGENT_SECRET` and `KURIER_API_KEY` come
  from the environment only. `.env` is gitignored.
- HMAC is verified on the raw body before parsing; responses are signed.
- Fail closed everywhere: bad signature, bad JSON, unknown envelope,
  timeout risk, or any Gatekeeper doubt -> reject / 4xx, never approve.
