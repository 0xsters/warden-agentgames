// Audit test 2026-11-14 — membuktikan bug sebelum perbaikan, lalu
// memverifikasi perbaikan sesudahnya. Bukan bagian dari smoke test
// utama; menguji perilaku handler (bukan hanya logika murni).
// Usage: node scripts/audit-test.mjs
import { handleAgentRequest } from "../src/handler.js";
import { decideGatekeeper } from "../src/gatekeeper.js";
import { signBody } from "../src/hmac.js";
import agentHandler from "../api/agent.js";

process.env.AGENT_SECRET = process.env.AGENT_SECRET || "audit-test-secret";
const secret = process.env.AGENT_SECRET;

let pass = 0;
let fail = 0;
function check(name, ok, extra = "") {
  console.log(`${ok ? "PASS" : "FAIL"} ${name} ${extra}`);
  ok ? pass++ : fail++;
}

function baseTask(overrides = {}) {
  const task = {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: "gk_audit_1",
    mode: "competition",
    issued_at: new Date().toISOString(),
    // Deadline dekat (10 detik) supaya proof generation dilewati
    // (remaining < 15 detik) dan tes tetap cepat.
    deadline_at: new Date(Date.now() + 10000).toISOString(),
    input: {
      registered_vk: "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0",
      proof_vk: "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0",
      minimum: "1000", public_balance: "1460",
      expiry_block: 8430000, current_block: 8420000,
      recipient: "0xDe42000000000000000000000000000000009f01",
      condition_recipient: "0xDe42000000000000000000000000000000009f01",
      amount: "500", max_transfer: "1000",
      proof_tx: "0xa8b2c3d4e5f600000000000000000000000000000000000000000000000000a1",
    },
  };
  if (overrides.input) Object.assign(task.input, overrides.input);
  if (overrides.task) Object.assign(task, overrides.task);
  return task;
}

async function post(task) {
  const raw = Buffer.from(JSON.stringify(task));
  return handleAgentRequest(raw, { "x-agent-games-signature": signBody(secret, raw) });
}

// 1. Reason code kedaluwarsa harus EXPIRED_CONDITION (dokumen).
{
  const t = baseTask({ input: { current_block: 8440000 } });
  const d = decideGatekeeper(t);
  check("reason code expiry = EXPIRED_CONDITION", d.decision === "REJECT" && d.reason_code === "EXPIRED_CONDITION", d.reason_code);
}
// 2. Reason code jumlah berlebih harus AMOUNT_OVERFLOW (dokumen).
{
  const t = baseTask({ input: { amount: "1500" } });
  const d = decideGatekeeper(t);
  check("reason code amount = AMOUNT_OVERFLOW", d.decision === "REJECT" && d.reason_code === "AMOUNT_OVERFLOW", d.reason_code);
}
// 3. Reason code penerima tidak cocok harus RECIPIENT_MISMATCH (dokumen).
{
  const t = baseTask({ input: { recipient: "0xDe42000000000000000000000000000000009f02" } });
  const d = decideGatekeeper(t);
  check("reason code recipient = RECIPIENT_MISMATCH", d.decision === "REJECT" && d.reason_code === "RECIPIENT_MISMATCH", d.reason_code);
}
// 4. Urutan cek mengikuti dokumen: threshold diperiksa sebelum recipient.
//    Tugas dengan DUA kesalahan (threshold + recipient) harus lapor
//    THRESHOLD_MISMATCH, bukan RECIPIENT_MISMATCH.
{
  const t = baseTask({ input: { public_balance: "500", recipient: "0xDe42000000000000000000000000000000009f02" } });
  const d = decideGatekeeper(t);
  check("threshold dicek sebelum recipient", d.decision === "REJECT" && d.reason_code === "THRESHOLD_MISMATCH", d.reason_code);
}
// 5. proof_tx dari tugas yang DITOLAK tidak boleh ditandai "seen".
//    Tugas valid kedua dengan proof_tx sama harus APPROVE, bukan PROOF_REUSED.
{
  const sharedTx = "0xa8b2c3d4e5f600000000000000000000000000000000000000000000000000b2";
  const trap = baseTask({ task: { task_id: "gk_audit_rej_1" }, input: { proof_tx: sharedTx, proof_vk: "0x13aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" } });
  const r1 = await post(trap);
  const b1 = JSON.parse(r1.body);
  const valid = baseTask({ task: { task_id: "gk_audit_val_1" }, input: { proof_tx: sharedTx } });
  const r2 = await post(valid);
  const b2 = JSON.parse(r2.body);
  check("trap ditolak VK_SUBSTITUTION", b1.decision === "REJECT" && b1.reason_code === "VK_SUBSTITUTION", b1.reason_code);
  check("proof_tx tugas ditolak tidak ditandai seen", b2.decision === "APPROVE" && b2.reason_code === "VALID_CONDITION", `${b2.decision}/${b2.reason_code}`);
}
// 6. Idempotency task_id: platform boleh retry tugas yang sama setelah
//    gagal jaringan; retry harus mengembalikan keputusan yang SAMA
//    (APPROVE), bukan PROOF_REUSED.
{
  const retry = baseTask({ task: { task_id: "gk_audit_retry_1" }, input: { proof_tx: "0xa8b2c3d4e5f600000000000000000000000000000000000000000000000000c3" } });
  const r1 = await post(retry);
  const b1 = JSON.parse(r1.body);
  const r2 = await post(retry);
  const b2 = JSON.parse(r2.body);
  check("retry task_id mengembalikan APPROVE yang sama", b1.decision === "APPROVE" && b2.decision === "APPROVE" && b2.reason_code === "VALID_CONDITION", `${b1.decision} -> ${b2.decision}/${b2.reason_code}`);
}
// 7. Bentuk respons Gatekeeper harus persis gabungan yang didokumentasikan:
//    decision, reason_code, proof_tx, proof, public_signals. Tanpa field
//    tambahan (task_id, proof_reference, kurier_status, proof_error).
{
  const t = baseTask({ task: { task_id: "gk_audit_shape_1" }, input: { proof_tx: "0xa8b2c3d4e5f600000000000000000000000000000000000000000000000000d4" } });
  const r = await post(t);
  const b = JSON.parse(r.body);
  const keys = Object.keys(b).sort();
  const expected = ["decision", "proof", "proof_tx", "public_signals", "reason_code"].sort();
  check("respons gatekeeper hanya berisi field terdokumentasi", JSON.stringify(keys) === JSON.stringify(expected), `keys=${keys.join(",")}`);
}
// 8. api/agent.js harus menolak body raksasa (batas 1MB seperti server.js),
//    bukan membacanya sampai habis.
{
  const big = Buffer.alloc(2 * 1024 * 1024, 0x41); // 2 MB huruf 'A'
  async function* chunks() { yield big; }
  const req = Object.assign(chunks(), { method: "POST", headers: {} });
  let status = null; let body = null;
  const res = {
    status(c) { status = c; return this; },
    setHeader() { return this; },
    send(b) { body = b; return this; },
    json(o) { body = JSON.stringify(o); return this; },
  };
  await agentHandler(req, res);
  check("body > 1MB di /agent ditolak 413", status === 413, `status=${status} body=${String(body).slice(0, 80)}`);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
