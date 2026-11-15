// HMAC helpers. The platform signs every inbound request with the agent
// secret (dashboard "Rotate Secret") and expects every response signed the
// same way, header: x-agent-games-signature, over the RAW body bytes.
import crypto from "node:crypto";

export function getSecret() {
  return process.env.AGENT_SECRET || process.env.AGENT_GAMES_HMAC_SECRET || null;
}

export function hmacHex(secret, rawBody) {
  return crypto.createHmac("sha256", secret).update(rawBody).digest("hex");
}

// Accept "hex", "sha256=hex", or "0xhex". Returns false on any mismatch.
export function verifySignature(secret, rawBody, headerValue) {
  if (!secret || !headerValue) return false;
  let hex = String(headerValue).trim();
  if (hex.startsWith("sha256=")) hex = hex.slice("sha256=".length);
  if (hex.startsWith("0x")) hex = hex.slice(2);
  if (!/^[0-9a-fA-F]+$/.test(hex)) return false;
  const expected = Buffer.from(hmacHex(secret, rawBody), "hex");
  let given;
  try {
    given = Buffer.from(hex, "hex");
  } catch {
    return false;
  }
  if (given.length !== expected.length) return false;
  return crypto.timingSafeEqual(given, expected);
}

export function signBody(secret, rawBody) {
  return hmacHex(secret, rawBody);
}
