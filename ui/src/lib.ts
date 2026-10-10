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
import anteWasmUrl from "./ante-delegate.wasm?url";
import { ANTE_CODE_HASH, VOTE_BITS, challengeBytes, checkProof, grind, votePurpose } from "./ante";
import { verifyProof } from "./whoiam";
export { personaName } from "./whoiam";
import { asBytes, cborDecode, cborEncode, enumVariant, mapGet, type CborValue } from "./cbor";

// ---- types mirroring contract/src/lib.rs ----
export type Kind = "single" | "multi" | "avail" | "text"; // avail: per-slot 0 = no, 1 = yes, 2 = maybe
export interface Question { id: string; kind: Kind; text: string; options: string[]; required: boolean }
export interface Schema { title: string; questions: Question[]; allowed?: string[] } // allowed = invited pubkeys (hex), absent = open poll
export interface Response { ts: number; answers_json: string; sig: string; ante?: string } // ante: open polls, hex CBOR proof
export interface Cert { base: string; challenge: string; ts: number; sig: string } // a whoiam delegation, see below
export interface FormState { schema_json: string; schema_sig: string; schema_cert?: Cert; responses: Record<string, Response> }
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
function sendDelegate(req: DelegateRequest, timeoutMs = 8000): Promise<DelegateResponse> {
  const run = async () => {
    let waiter!: Waiter;
    const reply = new Promise<DelegateResponse>((resolve, reject) => {
      waiter = { resolve, reject };
      delegateWaiters.push(waiter);
      setTimeout(() => {
        const i = delegateWaiters.indexOf(waiter);
        if (i >= 0) { delegateWaiters.splice(i, 1); reject(new Error("delegate timeout")); }
      }, timeoutMs);
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

/** Hand a delegate's wasm to the node (idempotent) and return its key: blake3(blake3(wasm)) for empty parameters. */
async function registerWasmDelegate(url: string, expectHash?: string): Promise<DelegateKeyT> {
  const code = new Uint8Array(await (await fetch(url)).arrayBuffer());
  const codeHash = blake3(code);
  if (expectHash && hex(codeHash) !== expectHash) throw new Error("unexpected delegate code");
  const key = new DelegateKeyT(Array.from(blake3(codeHash)), Array.from(codeHash));
  const wasm = new WasmDelegateV1T([], new DelegateCodeT(Array.from(code), Array.from(codeHash)), key);
  const container = new DelegateContainerT(DelegateType.WasmDelegateV1, wasm);
  // the node ignores cipher and nonce since freenet-core PR #4146 (secrets use a node-side key) but still checks their sizes
  await sendDelegate(new DelegateRequest(DelegateRequestType.RegisterDelegate, new RegisterDelegateT(container, new Array(32).fill(0), new Array(24).fill(0))));
  return key;
}

/** One application message to a registered delegate; resolves with the payload of its reply. */
async function messageDelegate(key: DelegateKeyT, payload: Uint8Array, timeoutMs?: number): Promise<Uint8Array> {
  const msg = new InboundDelegateMsgT(InboundDelegateMsgType.common_ApplicationMessage, new ApplicationMessageT(Array.from(payload), [], false));
  const r = await sendDelegate(new DelegateRequest(DelegateRequestType.ApplicationMessages, new ApplicationMessagesT(key, [], [msg])), timeoutMs);
  // duck-typed: bundlers can duplicate the SDK classes, which breaks instanceof
  const m = r.values.map((v) => v.inbound).find((x) => Array.isArray((x as ApplicationMessageT | null)?.payload)) as ApplicationMessageT | undefined;
  if (!m) throw new Error("empty delegate reply");
  return new Uint8Array(m.payload);
}

async function registerDelegate() {
  delegateKey = await registerWasmDelegate(identityWasmUrl);
}

// every delegate operation is safe to repeat (init keeps the first key, the rest are reads, signatures and overwrites)
const callDelegate = (payload: object) => retrying(() => callDelegateOnce(payload));

async function callDelegateOnce(payload: object): Promise<Record<string, any>> { // eslint-disable-line @typescript-eslint/no-explicit-any
  const out = JSON.parse(new TextDecoder().decode(await messageDelegate(delegateKey!, enc.encode(JSON.stringify(payload)))));
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

// ---- open-poll anti-spam: ante (github.com/soudasuwa/ante), as in FreeTunes reports ----
// The respondent's node asks for consent, the page grinds a few seconds of proof of work, the node signs it. The proof
// is bound to the poll and the respondent key, so it is made once and reused when the answer changes.
const CONSENT_MS = 75_000; // the node keeps the consent prompt open for 60 s
let anteKey: Promise<DelegateKeyT> | undefined;
async function anteCall(req: CborValue, timeoutMs?: number) {
  const key = await (anteKey ??= registerWasmDelegate(anteWasmUrl, ANTE_CODE_HASH).catch((e) => { anteKey = undefined; throw e; }));
  const out = enumVariant(cborDecode(await messageDelegate(key, cborEncode(req), timeoutMs)));
  if (out.variant === "Error") throw new Error(`ante: ${String(mapGet(out.fields!, "message"))}`);
  return out;
}

export class VoteDeclined extends Error { constructor() { super("You declined the proof of work, so the answer was not sent."); } }

/** The ante proof (hex) for answering poll `params` as `pk`. `step` narrates what is happening. */
export async function voteProof(params: string, pk: string, step: (msg: string) => void = () => {}): Promise<string> {
  const purpose = votePurpose(params, pk);
  step("Opening your ante identity…");
  const vk = asBytes(mapGet((await anteCall("GetIdentity")).fields!, "verifying_key"));
  step("Your Freenet node asks you to allow a few seconds of anti-spam work. Approve it there…");
  const grant = await anteCall({ RequestGrind: { purpose, min_bits: VOTE_BITS } }, CONSENT_MS);
  if (grant.variant === "Denied") throw new VoteDeclined();
  const challenge = asBytes(mapGet(grant.fields!, "bytes"));
  if (hex(challenge) !== hex(challengeBytes(purpose, vk))) throw new Error("ante returned an unexpected challenge");
  const nonce = await grind(challenge, VOTE_BITS, (n) => step(`Working… ${n.toLocaleString()} tries`));
  step("Signing…");
  const signed = await anteCall({ Commit: { purpose, nonce, min_bits: VOTE_BITS, ts: Date.now() } }, CONSENT_MS);
  if (signed.variant === "Denied") throw new VoteDeclined();
  const proof = asBytes(mapGet(signed.fields!, "proof"));
  await checkProof(proof, purpose); // catch a bad proof here: the node would only answer "Request timeout"
  return hex(proof);
}

/** Polls published by this contract version check ante on open polls; older ones were published without it. */
export const needsAnte = async (instance: string, params: string, schema: Schema) =>
  !schema.allowed && (await build(wasmUrl, unhex(params))).key.encode() === instance;

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

// ---- owner identity: a whoiam persona, through a delegated app key ----
// whoiam signs `wd1.<app key>.<nonce>` for this app's address: "this app key may act for me in FreePolls"
// (whoiam-delegation, in the freenames repo). The persona owns the polls; the app key only signs for it.
// The app key is NOT the respondent key above: delegations are public, and answers must not be linkable to a persona.

/** The app's own path: delegations and poll parameters are bound to it (in dev, "/"). */
const APP_PATH = location.pathname;
export const APP_PATH_HEX = hex(enc.encode(APP_PATH));

const appSecret = async () => {
  let h = await storeGet("app-sk");
  if (!h) await storePut("app-sk", (h = hex(ed.utils.randomPrivateKey())));
  return h;
};

export interface Session { persona: string; cert: Cert; sign: (msg: string) => Promise<string> }

/** The signed-in persona, if its delegation still holds for this node's app key. */
export async function session(): Promise<Session | null> {
  const raw = await storeGet("session");
  if (!raw) return null;
  const { persona, cert } = JSON.parse(raw) as { persona: string; cert: Cert };
  const sk = unhex(await appSecret());
  if (cert.challenge.split(".")[1] !== hex(await ed.getPublicKeyAsync(sk))) return null; // app key changed: sign in again
  return { persona, cert, sign: async (m) => hex(await ed.signAsync(enc.encode(m), sk)) };
}

async function requireSession(): Promise<Session> {
  const s = await session();
  if (!s) throw new Error("Sign in with whoiam first.");
  return s;
}

export const signOut = () => storePut("session", "");

/** The official whoiam web contract; any other whoiam site on this node can be used instead. */
export const WHOIAM_KEY = "87upyDfYzYHVY1Ypu9knhGUGRdydz54FHrBB6Bp2VBTg";
export const officialWhoiam = () => `${location.protocol}//${location.host}/v1/contract/web/${WHOIAM_KEY}/`;
const LINK_MAX_AGE_MS = 10 * 60 * 1000;
const linkBase = () => `${location.protocol}//${location.host}${APP_PATH}`; // whoiam binds its proof to it

/** Where to send the user to sign in. Remembers the one-time challenge in the delegate store. */
export async function startSignIn(whoiamUrl: string): Promise<string> {
  const u = new URL(whoiamUrl);
  if (u.host !== location.host || !/^\/v[12]\/contract\/web\/[^/]+\/?$/.test(u.pathname)) {
    throw new Error("Paste the address of your whoiam site on this node (it starts with the same host as this page).");
  }
  const appKey = hex(await ed.getPublicKeyAsync(unhex(await appSecret())));
  const challenge = `wd1.${appKey}.${hex(crypto.getRandomValues(new Uint8Array(16)))}`;
  await storePut("signin-pending", challenge);
  return `${u.origin}${u.pathname}?connect=v1&challenge=${challenge}&return=${encodeURIComponent(linkBase())}`;
}

/** Handle whoiam's callback: check challenge, freshness and signature, then keep the delegation. */
export async function finishSignIn(q: URLSearchParams): Promise<string> {
  if (q.get("whoiam") === "denied") throw new Error("You chose not to share a persona.");
  const pending = await storeGet("signin-pending");
  await storePut("signin-pending", ""); // one use: burn it whatever happens next
  const persona = q.get("pk") ?? "";
  const cert: Cert = { base: linkBase(), challenge: q.get("challenge") ?? "", ts: Number(q.get("ts")), sig: q.get("sig") ?? "" };
  if (!pending || cert.challenge !== pending) throw new Error("This sign-in is unknown or was already used. Start again.");
  if (!Number.isFinite(cert.ts) || Math.abs(Date.now() - cert.ts) > LINK_MAX_AGE_MS) throw new Error("The proof is too old or its clock is off. Start again.");
  if (!(await verifyProof({ ...cert, pk: persona }))) throw new Error("whoiam's signature does not verify.");
  await storePut("session", JSON.stringify({ persona, cert }));
  return persona;
}

/** Publish a new poll. Parameters = owner persona || random salt || app path, so one owner can run many polls. */
export async function publish(schema: Schema) {
  const me = await requireSession();
  const params = me.persona + hex(crypto.getRandomValues(new Uint8Array(16))) + APP_PATH_HEX;
  const schema_json = JSON.stringify(schema);
  const state: FormState = { schema_json, schema_sig: await me.sign(`fps1|${params}|${schema_json}`), schema_cert: me.cert, responses: {} };
  return { instance: await putContract(wasmUrl, unhex(params), state), params };
}

// ---- public directory (registry contract, see registry/src/lib.rs) ----
// The registry address depends on the admin key (its parameter): changing the key creates a new directory.
export const REGISTRY_ADMIN = "4f3738821e50c271f498aa23a5a569802a418768c84d2a6bd7f643a2d3359d6c";
const POW_BITS = 18; // must match the contract (sha256, about 3 s of mining)
export interface RegEntry { params: string; title: string; ts: number; nonce: number; sig: string; cert: Cert }
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
  const me = await requireSession(); // must be the poll owner (first 32 bytes of params)
  const ts = Date.now(), msg = `fpl1|${instance}|${params}|${title}|${ts}`;
  const sig = await me.sign(msg);
  let nonce = 0;
  while (zeroBits(sha256(enc.encode(`${msg}|${nonce}`))) < POW_BITS) {
    if (++nonce % 20000 === 0) await new Promise((r) => setTimeout(r)); // let the page breathe while mining
  }
  await loadRegistry(); // makes sure it exists and caches its full key for the update
  await sendDelta(await registryId(), { entries: { [instance]: { params, title, ts, nonce, sig, cert: me.cert } } });
}

/** Admin only: replace the blocklist (blocked polls disappear from the directory). */
export async function blockPolls(adminSecretHex: string, list: string[]) {
  const ts = Date.now();
  const sig = hex(await ed.signAsync(enc.encode(`fpb1|${ts}|${list.join(",")}`), unhex(adminSecretHex)));
  await loadRegistry();
  await sendDelta(await registryId(), { blocked: { ts, list, sig } });
}
