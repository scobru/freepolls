// Run with: npm test
import test from "node:test";
import assert from "node:assert/strict";
import * as ed from "@noble/ed25519";
import { bitsOf, challengeBytes, checkProof, grind, makeProof, votePurpose } from "./ante.ts";

const hex = ed.etc.bytesToHex;
const PARAMS = "ab".repeat(48), PK = "cd".repeat(32);

test("grind, sign and check a vote proof the way the delegate and the contract do", async () => {
  const purpose = votePurpose(PARAMS, PK);
  assert.equal(purpose, `freepolls:vote:v1:${PARAMS}:${PK}`); // contract: vote_purpose
  const sk = new Uint8Array(32).fill(7), vk = await ed.getPublicKeyAsync(sk);
  const nonce = await grind(challengeBytes(purpose, vk), 18);
  assert.ok(bitsOf(challengeBytes(purpose, vk), nonce) >= 18);
  const bytes = await makeProof(sk, purpose, nonce, 1700000000000);
  assert.equal((await checkProof(bytes, purpose)).nonce, nonce);
  await assert.rejects(checkProof(bytes, votePurpose(PARAMS, "ef".repeat(32))), /something else/);
  console.log("VECTOR", hex(bytes));
});
