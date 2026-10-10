// Run with: node --test src/whoiam.test.ts
import test from "node:test";
import assert from "node:assert/strict";
import * as ed from "@noble/ed25519";
import { connectMessage, toBase58, verifyProof } from "./whoiam.ts";

const hex = ed.etc.bytesToHex;

test("connect signature matches whoiam's golden vector", async () => {
  const sk = new Uint8Array(32).fill(42), pk = await ed.getPublicKeyAsync(sk);
  const base = "https://example.com/app", challenge = "abc123", ts = 12345;
  const sig = await ed.signAsync(connectMessage(pk, base, challenge, ts), sk);
  // from whoiam: common/src/connect.rs, golden_connect_signature
  assert.equal(hex(sig), "122b675bdbc8772f52631524ac2b500dec76721bff7c0b299025df04e18e8e8ddf2b8d0a232a5785e68d5738be4f5111ae7b58106f5458b966b9b365fff5ac09");
  const proof = { pk: hex(pk), sig: hex(sig), ts, challenge, base };
  assert.equal(await verifyProof(proof), true);
  // any field changed: refused (also covers the length prefixes between fields)
  assert.equal(await verifyProof({ ...proof, base: "https://example.com/evil" }), false);
  assert.equal(await verifyProof({ ...proof, challenge: "abc124" }), false);
  assert.equal(await verifyProof({ ...proof, ts: 12346 }), false);
  assert.equal(await verifyProof({ ...proof, base: base + "a", challenge: "bc123" }), false);
  assert.equal(await verifyProof({ ...proof, pk: hex(await ed.getPublicKeyAsync(new Uint8Array(32).fill(43))) }), false);
  assert.equal(await verifyProof({ ...proof, sig: "zz" }), false);
});

test("base58 matches an independent computation", () => {
  assert.equal(toBase58(Uint8Array.from([0, 0, 1])), "112");
  assert.equal(toBase58(Uint8Array.from([])), "");
  // computed with Python big integers, not with this code
  const pk = ed.etc.hexToBytes("2a76f1666f3aac4f859a1f35300050b69275202d3b880d9f165083c92818b0b5");
  assert.equal(toBase58(pk), "3rmKPdMLRKZPKpEc2UThti8k4EdxzsAH3j7eWx8GhqYY");
});
