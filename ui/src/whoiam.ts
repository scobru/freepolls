// whoiam's "sign in with whoiam" proof and key encoding, kept free of any browser or Freenet import so a plain
// `node --test` can check it against whoiam's own golden vectors (skandragon/freenet-whoiam, common/src/connect.rs).
import * as ed from "@noble/ed25519";

const enc = new TextEncoder();
const unhex = (h: string) => ed.etc.hexToBytes(h);

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
/** Base58 (Bitcoin alphabet), the way whoiam and Freenet show public keys. */
export function toBase58(b: Uint8Array): string {
  const d: number[] = [];
  for (const byte of b) {
    let carry = byte;
    for (let i = 0; i < d.length; i++) { carry += d[i] << 8; d[i] = carry % 58; carry = (carry / 58) | 0; }
    while (carry) { d.push(carry % 58); carry = (carry / 58) | 0; }
  }
  let out = "";
  for (const byte of b) { if (byte) break; out += "1"; }
  return out + d.reverse().map((x) => B58[x]).join("");
}
export const personaName = (pkHex: string) => toBase58(unhex(pkHex));

/** What whoiam signs: "whoiam-connect-v1" || pk || u32le len || base || u32le len || challenge || u64le ts. */
export function connectMessage(pk: Uint8Array, base: string, challenge: string, ts: number): Uint8Array {
  const parts = [enc.encode("whoiam-connect-v1"), pk];
  for (const f of [base, challenge]) { const b = enc.encode(f); parts.push(new Uint8Array(new Uint32Array([b.length]).buffer), b); }
  parts.push(new Uint8Array(new BigUint64Array([BigInt(ts)]).buffer));
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

export interface Proof { pk: string; sig: string; ts: number; challenge: string; base: string }

/** Does the signature hold? (Whether it is about the right identity is checked separately.) */
export async function verifyProof(l: Proof): Promise<boolean> {
  try { return await ed.verifyAsync(unhex(l.sig), connectMessage(unhex(l.pk), l.base, l.challenge, l.ts), unhex(l.pk)); }
  catch { return false; }
}
