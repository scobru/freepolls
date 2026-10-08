import * as ed from "@noble/ed25519";
import { blake3 } from "@noble/hashes/blake3.js";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  FreenetWsApi, ContractKey, ContractContainer, ContractType, WasmContractV1,
  PutRequest, GetRequest, SubscribeRequest, UpdateRequest, UpdateData, UpdateDataType, DeltaUpdate,
  DelegateRequest, type DelegateResponse, type ResponseHandler,
} from "@freenetorg/freenet-stdlib";
import { ApplicationMessageT, ContractCodeT } from "@freenetorg/freenet-stdlib/common";
import {
  ApplicationMessagesT, ClientRequestT, ClientRequestType, DelegateCodeT, DelegateContainerT, DelegateKeyT,
  DelegateRequestType, DelegateType, InboundDelegateMsgT, InboundDelegateMsgType, RegisterDelegateT,
  RelatedContractsT, WasmDelegateV1T,
} from "@freenetorg/freenet-stdlib/client-request";
import wasmUrl from "./contract.wasm?url";
import identityWasmUrl from "./identity.wasm?url";
import registryWasmUrl from "./registry.wasm?url";

// ---- types mirroring contract/src/lib.rs ----
export type Kind = "single" | "multi" | "avail" | "text"; // avail: per-slot 0 = no, 1 = yes, 2 = maybe
export interface Question { id: string; kind: Kind; text: string; options: string[]; required: boolean }
export interface Schema { title: string; questions: Question[]; allowed?: string[]; rev?: number } // allowed = invited pubkeys (hex), absent = open poll
export interface Response { ts: number; answers_json: string; sig: string }
export interface FormState { schema_json: string; schema_sig: string; responses: Record<string, Response> }
export type Answers = Record<string, number | number[] | string>;

const { bytesToHex: hex, hexToBytes: unhex } = ed.etc;
const enc = new TextEncoder();
const bytes = (s: string) => Array.from(enc.encode(s));

// ---- identity ----
// Signing identity: `sign` takes the message text and returns the hex signature.
export interface Identity { pk: string; persisted: boolean; sign: (msg: string) => Promise<string> }

const local = async (sk: Uint8Array, persisted: boolean): Promise<Identity> => ({
  pk: hex(await ed.getPublicKeyAsync(sk)),
  persisted,
  sign: async (m) => hex(await ed.signAsync(enc.encode(m), sk)),
});

// Identity delegate: the key lives in the node (one per calling web app), so it survives sessions even
// inside the sandboxed container where the page has no storage. The delegate is optional: if it is missing
// or does not answer, the identity falls back to localStorage, or to memory for the session.
interface Waiter { resolve(r: DelegateResponse): void; reject(e: Error): void }
const delegateWaiters: Waiter[] = [];
let delegateKey: DelegateKeyT | undefined;

// The socket can drop right after the page opens (for example while the shell re-authenticates), which
// would otherwise fail the first load until a manual refresh: retry a couple of times.
async function retrying<T>(f: () => Promise<T>, tries = 3): Promise<T> {
  for (let i = 1; ; i++) {
    try { return await f(); }
    catch (e) {
      if (i >= tries || !/closed/i.test(String(e))) throw e;
      console.warn(`connection dropped, retrying (${i}/${tries - 1}):`, e);
      await new Promise((r) => setTimeout(r, 1500));
    }
  }
}

// Every delegate request, registration included, is answered by one DelegateResponse and the replies carry
// no request id: calls go one at a time and are matched by order.
let delegateChain: Promise<unknown> = Promise.resolve();
function sendDelegate(req: DelegateRequest): Promise<DelegateResponse> {
  const run = async () => {
    let waiter!: Waiter;
    const reply = new Promise<DelegateResponse>((resolve, reject) => {
      waiter = { resolve, reject };
      delegateWaiters.push(waiter);
      setTimeout(() => {
        const i = delegateWaiters.indexOf(waiter);
        if (i >= 0) { delegateWaiters.splice(i, 1); reject(new Error("delegate timeout")); }
      }, 8000);
    });
    // the SDK has no delegate method yet: use its low-level sender
    const a = (await api()) as unknown as { sendRequest(r: ClientRequestT): void };
    a.sendRequest(new ClientRequestT(ClientRequestType.DelegateRequest, req));
    return reply;
  };
  const p = delegateChain.then(run);
  delegateChain = p.catch(() => {});
  return p;
}

async function registerDelegate() {
  const code = new Uint8Array(await (await fetch(identityWasmUrl)).arrayBuffer());
  const codeHash = blake3(code);
  delegateKey = new DelegateKeyT(Array.from(blake3(codeHash)), Array.from(codeHash)); // empty params: blake3(codeHash)
  const wasm = new WasmDelegateV1T([], new DelegateCodeT(Array.from(code), Array.from(codeHash)), delegateKey);
  const container = new DelegateContainerT(DelegateType.WasmDelegateV1, wasm);
  // the node ignores cipher and nonce since freenet-core PR #4146 (secrets use a node-side key) but still checks their sizes
  await sendDelegate(new DelegateRequest(DelegateRequestType.RegisterDelegate, new RegisterDelegateT(container, new Array(32).fill(0), new Array(24).fill(0))));
}

// every delegate operation is safe to repeat (init keeps the first key, the rest are reads, signatures and overwrites)
const callDelegate = (payload: object) => retrying(() => callDelegateOnce(payload));

async function callDelegateOnce(payload: object): Promise<Record<string, any>> { // eslint-disable-line @typescript-eslint/no-explicit-any
  const msg = new InboundDelegateMsgT(InboundDelegateMsgType.common_ApplicationMessage, new ApplicationMessageT(bytes(JSON.stringify(payload)), [], false));
  const r = await sendDelegate(new DelegateRequest(DelegateRequestType.ApplicationMessages, new ApplicationMessagesT(delegateKey, [], [msg])));
  // duck-typed: bundlers can duplicate the SDK classes, which breaks instanceof
  const m = r.values.map((v) => v.inbound).find((x) => Array.isArray((x as ApplicationMessageT | null)?.payload)) as ApplicationMessageT | undefined;
  if (!m) throw new Error("empty delegate reply");
  const out = JSON.parse(new TextDecoder().decode(new Uint8Array(m.payload)));
  if (out.err) throw new Error(out.err);
  return out;
}

let delegateIdentity: Promise<Identity | null> | undefined;
function viaDelegate(): Promise<Identity | null> {
  return (delegateIdentity ??= (async () => {
    try {
      const { pk } = await retrying(async () => {
        await registerDelegate();
        // keep the identity this browser already had (init only stores the key if the delegate has none)
        let sk: string | null = null;
        try { sk = localStorage.getItem("fp-sk"); } catch { /* sandbox: no storage */ }
        return callDelegate({ op: "init", sk: sk ?? hex(ed.utils.randomPrivateKey()) });
      });
      return { pk, persisted: true, sign: async (msg: string) => (await callDelegate({ op: "sign", msg })).sig };
    } catch (e) {
      console.warn("identity delegate unavailable, using local key:", e);
      return null;
    }
  })());
}

let memKey: string | undefined;
export async function identity(): Promise<Identity> {
  const d = await viaDelegate();
  if (d) return d;
  let h: string | null | undefined, persisted = true;
  try { h = localStorage.getItem("fp-sk"); } catch { persisted = false; h = memKey; }
  if (!h) {
    h = hex(ed.utils.randomPrivateKey());
    try { localStorage.setItem("fp-sk", h); } catch { persisted = false; }
  }
  memKey = h;
  return local(unhex(h), persisted);
}

// ---- small per-browser store (poll list, owner's invite links): the delegate when available, else localStorage ----
const mem = new Map<string, string>();
const lsKey = (k: string) => `fp-${k}`;

export async function storeGet(key: string): Promise<string | null> {
  const d = await viaDelegate();
  let local: string | null = null;
  try { local = localStorage.getItem(lsKey(key)); } catch { /* sandbox: no storage */ }
  if (d) {
    try { return (await callDelegate({ op: "get", key })).value ?? local; } catch { /* use local */ }
  }
  return local ?? mem.get(key) ?? null;
}

export async function storePut(key: string, value: string) {
  mem.set(key, value);
  try { localStorage.setItem(lsKey(key), value); } catch { /* sandbox: no storage */ }
  if (await viaDelegate()) {
    try { await callDelegate({ op: "put", key, value }); } catch (e) { console.warn("delegate store failed:", e); }
  }
}

/** Identity from an invite secret carried in the link (works without storage or delegate). */
export const identityFrom = (secretHex: string) => local(unhex(secretHex), true);

/** Fresh invite keypairs: the secret goes into the personal link, the pubkey into the signed schema. */
export async function newInvites(n: number) {
  return Promise.all(Array.from({ length: n }, async () => {
    const sk = ed.utils.randomPrivateKey();
    return { secret: hex(sk), pk: hex(await ed.getPublicKeyAsync(sk)) };
  }));
}

// ---- signing: message formats must match the contract ----
export async function signAnswers(who: Identity, params: string, answers: Answers): Promise<Response> {
  const ts = Date.now(), answers_json = JSON.stringify(answers);
  return { ts, answers_json, sig: await who.sign(`fpr1|${params}|${who.pk}|${ts}|${answers_json}`) };
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
      : `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/v1/contract/command`); // the shell only proxies sockets to its own origin, scheme included
    const h: ResponseHandler = {
      onContractPut() {}, onContractGet() {}, onContractUpdate() {},
      onContractUpdateNotification: () => listeners.forEach((l) => l()),
      onContractNotFound: () => console.warn("contract not found"),
      onDelegateResponse: (r) => delegateWaiters.shift()?.resolve(r),
      onErr: (e) => { console.error(e.cause); alert(e.cause); },
      onOpen: () => resolve(a),
      onClose: () => {
        apiP = undefined;
        delegateWaiters.splice(0).forEach((w) => w.reject(new Error("socket closed"))); // their replies will never come
        reject(new Error("socket closed"));
      },
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
  serial(() => retrying(async () => {
    const r = await (await api()).get(new GetRequest(keyOf(instance), false));
    if (r.key?.codePart()?.length === 32) keys.set(instance, r.key);
    return JSON.parse(new TextDecoder().decode(new Uint8Array(r.state))) as T;
  }));
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

/** Owner only: sign a new schema with the same questions and a new title. The contract keeps the highest rev. */
export async function rename(instance: string, params: string, schema: Schema, title: string) {
  const schema_json = JSON.stringify({ ...schema, title, rev: (schema.rev ?? 0) + 1 });
  const sig = await (await identity()).sign(`fps1|${params}|${schema_json}`);
  await sendDelta(instance, { schema: [schema_json, sig], responses: {} });
}

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
  const me = await identity();
  const params = me.pk + hex(crypto.getRandomValues(new Uint8Array(16)));
  const schema_json = JSON.stringify(schema);
  const state: FormState = { schema_json, schema_sig: await me.sign(`fps1|${params}|${schema_json}`), responses: {} };
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
  const me = await identity(); // must be the poll owner (first 32 bytes of params)
  const ts = Date.now(), msg = `fpl1|${instance}|${params}|${title}|${ts}`;
  const sig = await me.sign(msg);
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
