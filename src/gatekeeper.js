// Proof Gatekeeper decision logic. Pure and deterministic: APPROVE only
// when EVERY check passes. Never let a language model make the final call.
// Reason codes follow the ones seen in the arena preview.
//
// Task input fields (agent-games.proof-gatekeeper.v1):
//   registered_vk, proof_vk, minimum, public_balance, expiry_block,
//   current_block, recipient, condition_recipient, amount, max_transfer,
//   proof_tx
import { hasSeenProofTx } from "./state.js";

function isHex(str, bytes) {
  if (typeof str !== "string") return false;
  const h = str.startsWith("0x") ? str.slice(2) : str;
  if (!/^[0-9a-fA-F]+$/.test(h)) return false;
  return bytes ? h.length === bytes * 2 : h.length > 0;
}

function toBig(v) {
  if (typeof v === "bigint") return v;
  if (typeof v === "number") return BigInt(v);
  if (typeof v === "string") return BigInt(v);
  throw new Error("not a number");
}

// Returns { decision: "APPROVE" | "REJECT", reason_code, checks: [...] }.
// Each check is { name, pass, detail }. The first failing check decides.
export function decideGatekeeper(task) {
  const checks = [];
  const fail = (name, reason_code, detail) => {
    checks.push({ name, pass: false, detail });
    return { decision: "REJECT", reason_code, checks };
  };
  const input = task?.input ?? task;

  // 1. Shape: all required fields present and well-formed.
  const required = [
    "registered_vk", "proof_vk", "minimum", "public_balance",
    "expiry_block", "current_block", "recipient", "condition_recipient",
    "amount", "max_transfer", "proof_tx",
  ];
  for (const f of required) {
    if (input?.[f] === undefined || input?.[f] === null || input?.[f] === "") {
      return fail("input_shape", "INVALID_INPUT", `missing field: ${f}`);
    }
  }
  if (!isHex(input.registered_vk) || !isHex(input.proof_vk)) {
    return fail("input_shape", "INVALID_INPUT", "vk fields must be hex");
  }
  if (!isHex(input.recipient, 20) || !isHex(input.condition_recipient, 20)) {
    return fail("input_shape", "INVALID_INPUT", "recipient fields must be 20-byte hex addresses");
  }
  let minimum, publicBalance, amount, maxTransfer, expiryBlock, currentBlock;
  try {
    minimum = toBig(input.minimum);
    publicBalance = toBig(input.public_balance);
    amount = toBig(input.amount);
    maxTransfer = toBig(input.max_transfer);
    expiryBlock = toBig(input.expiry_block);
    currentBlock = toBig(input.current_block);
  } catch {
    return fail("input_shape", "INVALID_INPUT", "numeric fields must parse");
  }
  if (minimum <= 0n || amount <= 0n || maxTransfer <= 0n) {
    return fail("input_shape", "INVALID_INPUT", "minimum/amount/max_transfer must be positive");
  }
  checks.push({ name: "input_shape", pass: true, detail: "all fields present" });

  // 2. Verification key: the proof's vk must equal the registered vk.
  if (String(input.proof_vk).toLowerCase() !== String(input.registered_vk).toLowerCase()) {
    return fail("vk_match", "VK_SUBSTITUTION", "proof_vk differs from registered_vk");
  }
  checks.push({ name: "vk_match", pass: true, detail: "proof_vk == registered_vk" });

  // 3. Threshold: the public balance must cover the required minimum.
  // (Documented order: vk -> threshold -> recipient -> replay -> expiry.)
  if (publicBalance < minimum) {
    return fail("threshold", "THRESHOLD_MISMATCH", `public_balance ${publicBalance} < minimum ${minimum}`);
  }
  checks.push({ name: "threshold", pass: true, detail: `public_balance ${publicBalance} >= minimum ${minimum}` });

  // 4. Recipient: the transfer recipient must equal the condition recipient.
  if (String(input.recipient).toLowerCase() !== String(input.condition_recipient).toLowerCase()) {
    return fail("recipient_match", "RECIPIENT_MISMATCH", "recipient differs from condition_recipient");
  }
  checks.push({ name: "recipient_match", pass: true, detail: "recipient == condition_recipient" });

  // 5. Amount: the transfer must not exceed the allowed maximum.
  if (amount > maxTransfer) {
    return fail("amount_limit", "AMOUNT_OVERFLOW", `amount ${amount} > max_transfer ${maxTransfer}`);
  }
  checks.push({ name: "amount_limit", pass: true, detail: `amount ${amount} <= max_transfer ${maxTransfer}` });

  // 6. Replay: the proof reference must not have been used before.
  // (Documented order puts the seen-set check before expiry.)
  if (hasSeenProofTx(input.proof_tx)) {
    return fail("replay", "PROOF_REUSED", `proof_tx ${input.proof_tx} already processed`);
  }
  checks.push({ name: "replay", pass: true, detail: "proof_tx not seen before" });

  // 7. Expiry: the current block must not be past the expiry block.
  if (currentBlock > expiryBlock) {
    return fail("expiry", "EXPIRED_CONDITION", `current_block ${currentBlock} > expiry_block ${expiryBlock}`);
  }
  checks.push({ name: "expiry", pass: true, detail: `current_block ${currentBlock} <= expiry_block ${expiryBlock}` });

  // 8. Timestamp: the task must not be expired or issued in the future.
  const now = Date.now();
  const issuedAt = task?.issued_at ? Date.parse(task.issued_at) : NaN;
  const deadlineAt = task?.deadline_at ? Date.parse(task.deadline_at) : NaN;
  if (!Number.isNaN(deadlineAt) && now > deadlineAt) {
    return fail("timestamp", "EXPIRED_CONDITION", "deadline_at has passed");
  }
  if (!Number.isNaN(issuedAt) && issuedAt > now + 5 * 60 * 1000) {
    return fail("timestamp", "INVALID_TIMESTAMP", "issued_at is in the future");
  }
  checks.push({ name: "timestamp", pass: true, detail: "task is within its time window" });

  return { decision: "APPROVE", reason_code: "VALID_CONDITION", checks };
}
