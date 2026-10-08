import * as ed from "@noble/ed25519";
import { blake3 } from "@noble/hashes/blake3.js";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  FreenetWsApi, ContractKey, ContractContainer, ContractType, WasmContractV1,
  PutRequest, GetRequest, SubscribeRequest, UpdateRequest, UpdateData, UpdateDataType, DeltaUpdate,
  type ResponseHandler,
} from "@freenetorg/freenet-stdlib";
import { ContractCodeT } from "@freenetorg/freenet-stdlib/common";
import { RelatedContractsT } from "@freenetorg/freenet-stdlib/client-request";
import wasmUrl from "./contract.wasm?url";
import registryWasmUrl from "./registry.wasm?url";

// ---- types mirroring contract/src/lib.rs ----
export type Kind = "single" | "multi" | "avail" | "text"; // avail: per-slot 0 = no, 1 = yes, 2 = maybe
export interface Question { id: string; kind: Kind; text: string; options: string[]; required: boolean }
export interface Schema { title: string; questions: Question[]; allowed?: string[] } // allowed = invited pubkeys (hex), absent = open poll
export interface Response { ts: number; answers_json: string; sig: string }
export interface FormState { schema_json: string; schema_sig: string; responses: Record<string, Response> }
export type Answers = Record<string, number | number[] | string>;

const { bytesToHex: hex, hexToBytes: unhex } = ed.etc;
const enc = new TextEncoder();
const bytes = (s: string) => Array.from(enc.encode(s));

// ---- identity (one ed25519 key per browser; ponytail: localStorage, move to a delegate for real key custody) ----
// Inside the Freenet web container the iframe is sandboxed without allow-same-origin: localStorage throws,
// so the key lives in memory for the session only (`persisted: false`).
let memKey: string | undefined;
export async function identity() {
  let h: string | null | undefined, persisted = true;
  try { h = localStorage.getItem("fp-sk"); } catch { persisted = false; h = memKey; }
  if (!h) {
    h = hex(ed.utils.randomPrivateKey());
    try { localStorage.setItem("fp-sk", h); } catch { persisted = false; }
  }
  memKey = h;
  const sk = unhex(h);
  return { sk, pk: hex(await ed.getPublicKeyAsync(sk)), persisted };
}

/** Identity from an invite secret carried in the link (works without storage, e.g. in the sandboxed container). */
export async function identityFrom(secretHex: string) {
  const sk = unhex(secretHex);
  return { sk, pk: hex(await ed.getPublicKeyAsync(sk)), persisted: true };
}

/** Fresh invite keypairs: the secret goes into the personal link, the pubkey into the signed schema. */
export async function newInvites(n: number) {
  return Promise.all(Array.from({ length: n }, async () => {
    const sk = ed.utils.randomPrivateKey();
    return { secret: hex(sk), pk: hex(await ed.getPublicKeyAsync(sk)) };
  }));
}

// ---- signing: message formats must match the contract ----
export const signSchema = async (sk: Uint8Array, params: string, schema_json: string) =>
  hex(await ed.signAsync(enc.encode(`fps1|${params}|${schema_json}`), sk));

export async function signAnswers(sk: Uint8Array, params: string, pk: string, answers: Answers): Promise<Response> {
  const ts = Date.now(), answers_json = JSON.stringify(answers);
  return { ts, answers_json, sig: hex(await ed.signAsync(enc.encode(`fpr1|${params}|${pk}|${ts}|${answers_json}`), sk)) };
}

// ---- node connection ----
type Listener = () => void;
const listeners = new Set<Listener>();
export const onRemoteChange = (l: Listener) => { listeners.add(l); return () => listeners.delete(l); };

let apiP: Promise<FreenetWsApi> | undefined;
export function api(): Promise<FreenetWsApi> {
  return (apiP ??= new Promise((resolve, reject) => {
    const url = new URL(import.meta.env.DEV
      ? `ws://${import.meta.env.VITE_NODE ?? "127.0.0.1:7509"}/v1/contract/command`
      : `ws://${location.host}/v1/contract/command`);
    const h: ResponseHandler = {
      onContractPut() {}, onContractGet() {}, onContractUpdate() {},
      onContractUpdateNotification: () => listeners.forEach((l) => l()),
      onContractNotFound: () => console.warn("contract not found"),
      onDelegateResponse() {},
      onErr: (e) => { console.error(e.cause); alert(e.cause); },
      onOpen: () => resolve(a),
      onClose: () => { apiP = undefined; reject(new Error("socket closed")); },
    };
    const a = new FreenetWsApi(url, h, ""); // empty token inside the web container shell
  }));
}

// get() responses are matched by arrival order: serialize them
let chain: Promise<unknown> = Promise.resolve();
const serial = <T>(f: () => Promise<T>): Promise<T> => {
  const p = chain.then(f);
  chain = p.catch(() => {});
  return p;
};

// full keys (instance + code hash) learned from get(); UPDATE needs the code hash, links only carry the instance id
const keys = new Map<string, ContractKey>();
const keyOf = (instanceB58: string) => keys.get(instanceB58) ?? ContractKey.fromInstanceId(instanceB58);

/** Fetch a contract's JSON state. */
export const loadJson = <T>(instance: string) =>
  serial(async () => {
    const r = await (await api()).get(new GetRequest(keyOf(instance), false));
    if (r.key?.codePart()?.length === 32) keys.set(instance, r.key);
    return JSON.parse(new TextDecoder().decode(new Uint8Array(r.state))) as T;
  });
export const loadState = (instance: string) => loadJson<FormState>(instance);

export async function watch(instance: string) {
  await (await api()).subscribe(new SubscribeRequest(keyOf(instance)));
}

async function sendDelta(instance: string, delta: object) {
  const d = bytes(JSON.stringify(delta));
  await (await api()).update(new UpdateRequest(keyOf(instance), new UpdateData(UpdateDataType.DeltaUpdate, new DeltaUpdate(d))));
}
export const sendResponse = (instance: string, pk: string, r: Response) =>
  sendDelta(instance, { schema: null, responses: { [pk]: r } });

/** Contract code + key. Instance id = blake3(blake3(wasm) || params), same as freenet-stdlib. */
async function build(wasm: string, params: Uint8Array) {
  const code = new Uint8Array(await (await fetch(wasm)).arrayBuffer());
  const codeHash = blake3(code);
  const key = new ContractKey(blake3(new Uint8Array([...codeHash, ...params])), codeHash);
  return { code, codeHash, key };
}

async function putContract(wasm: string, params: Uint8Array, state: object) {
  const { code, codeHash, key } = await build(wasm, params);
  const contract = new WasmContractV1(new ContractCodeT(Array.from(code), Array.from(codeHash)), Array.from(params), key);
  await (await api()).put(new PutRequest(new ContractContainer(ContractType.WasmContractV1, contract), bytes(JSON.stringify(state)), new RelatedContractsT()));
  return key.encode();
}

/** Publish a new poll. Parameters = owner pubkey || random salt, so one owner can run many polls. */
export async function publish(schema: Schema) {
  const { sk, pk } = await identity();
  const params = pk + hex(crypto.getRandomValues(new Uint8Array(16)));
  const schema_json = JSON.stringify(schema);
  const state: FormState = { schema_json, schema_sig: await signSchema(sk, params, schema_json), responses: {} };
  return { instance: await putContract(wasmUrl, unhex(params), state), params };
}

// ---- public directory (registry contract, see registry/src/lib.rs) ----
// The registry address depends on the admin key (its parameter): changing the key creates a new directory.
export const REGISTRY_ADMIN = "4f3738821e50c271f498aa23a5a569802a418768c84d2a6bd7f643a2d3359d6c";
const POW_BITS = 18; // must match the contract (sha256, about 3 s of mining)
export interface RegEntry { params: string; title: string; ts: number; nonce: number; sig: string }
export interface RegState { entries: Record<string, RegEntry>; blocked: { ts: number; list: string[]; sig: string } }

let regId: Promise<string> | undefined;
const registryId = () => (regId ??= build(registryWasmUrl, unhex(REGISTRY_ADMIN)).then((b) => b.key.encode()));

/** Load the directory. The first visitor on a node creates it (empty). */
export async function loadRegistry(): Promise<RegState> {
  const id = await registryId();
  try { return await loadJson<RegState>(id); }
  catch {
    await putContract(registryWasmUrl, unhex(REGISTRY_ADMIN), { entries: {}, blocked: { ts: 0, list: [], sig: "" } });
    return loadJson<RegState>(id);
  }
}

const zeroBits = (h: Uint8Array) => {
  let n = 0;
  for (const b of h) { n += Math.clz32(b) - 24; if (b) break; }
  return n;
};

/** List a poll you own: sign the entry and mine the proof-of-work (a few seconds). */
export async function listPoll(instance: string, params: string, title: string) {
  const { sk } = await identity(); // must be the poll owner (first 32 bytes of params)
  const ts = Date.now(), msg = `fpl1|${instance}|${params}|${title}|${ts}`;
  const sig = hex(await ed.signAsync(enc.encode(msg), sk));
  let nonce = 0;
  while (zeroBits(sha256(enc.encode(`${msg}|${nonce}`))) < POW_BITS) {
    if (++nonce % 20000 === 0) await new Promise((r) => setTimeout(r)); // let the page breathe while mining
  }
  await loadRegistry(); // makes sure it exists and caches its full key for the update
  await sendDelta(await registryId(), { entries: { [instance]: { params, title, ts, nonce, sig } } });
}

/** Admin only: replace the blocklist (blocked polls disappear from the directory). */
export async function blockPolls(adminSecretHex: string, list: string[]) {
  const ts = Date.now();
  const sig = hex(await ed.signAsync(enc.encode(`fpb1|${ts}|${list.join(",")}`), unhex(adminSecretHex)));
  await loadRegistry();
  await sendDelta(await registryId(), { blocked: { ts, list, sig } });
}
