// Field-element helpers for the bn128 curve used by the Groth16 circuits.
import crypto from "node:crypto";
// js-sha3 0.8.0 is a CJS module; the named ESM import does not resolve,
// so take keccak256 off the default export.
import jsSha3 from "js-sha3";
const keccak256 = jsSha3.keccak256;

export const FIELD_PRIME =
  21888242871839275222246405745257275088696311157297823662689037894645226208583n;

export function modP(x) {
  const v = BigInt(x);
  return ((v % FIELD_PRIME) + FIELD_PRIME) % FIELD_PRIME;
}

// A 0x hex hash (e.g. a vk hash or commitment) as a field element.
// NOTE: raw 256-bit hashes can exceed the field prime, so they are reduced
// mod p. This matches the usual convention for passing hashes into a
// bn128 circuit; see README "Circuit input encodings".
export function hashToField(hex) {
  return modP(BigInt(hex));
}

// An Ethereum-style address (20 bytes) as a field element. Addresses fit
// the field, so no reduction is needed.
export function addressToField(hex) {
  return BigInt(hex);
}

// An arbitrary id string (e.g. task "gk_8d31_...") as a field element:
// keccak256 of the UTF-8 bytes, reduced mod p.
export function idToField(str) {
  return modP(BigInt("0x" + keccak256(str)));
}

// A fresh random field element, used as the per-proof blinding salt.
export function randomSalt() {
  return modP(BigInt("0x" + crypto.randomBytes(32).toString("hex")));
}

// keccak256 of ABI-packed fields: each value padded to 32 bytes big-endian.
// Used for Steal the VFY publicInputsHash (see steal.js).
export function keccakAbiPacked(values) {
  const parts = values.map((v) => {
    const b = BigInt(v);
    if (b < 0n) throw new Error("negative value in ABI packing");
    const hex = b.toString(16).padStart(64, "0");
    return Buffer.from(hex, "hex");
  });
  return "0x" + keccak256(Buffer.concat(parts));
}
