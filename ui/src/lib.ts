import * as ed from "@noble/ed25519";
import { blake3 } from "@noble/hashes/blake3.js";
import {
  FreenetWsApi, ContractKey, ContractContainer, ContractType, WasmContractV1,
  PutRequest, GetRequest, SubscribeRequest, UpdateRequest, UpdateData, UpdateDataType, DeltaUpdate,
  type ResponseHandler,
} from "@freenetorg/freenet-stdlib";
import { ContractCodeT } from "@freenetorg/freenet-stdlib/common";
import { RelatedContractsT } from "@freenetorg/freenet-stdlib/client-request";
import wasmUrl from "./contract.wasm?url";

// ---- types mirroring contract/src/lib.rs ----
export type Kind = "single" | "multi" | "avail" | "text"; // avail: per-slot 0 = no, 1 = yes, 2 = maybe
export interface Question { id: string; kind: Kind; text: string; options: string[]; required: boolean }
export interface Schema { title: string; questions: Question[] }
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

// ---- signing: message formats must match the contract ----
export const signSchema = async (sk: Uint8Array, schema_json: string) =>
  hex(await ed.signAsync(enc.encode(`fps1|${schema_json}`), sk));

export async function signAnswers(sk: Uint8Array, owner: string, pk: string, answers: Answers): Promise<Response> {
  const ts = Date.now(), answers_json = JSON.stringify(answers);
  return { ts, answers_json, sig: hex(await ed.signAsync(enc.encode(`fpr1|${owner}|${pk}|${ts}|${answers_json}`), sk)) };
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

export const loadState = (instance: string) =>
  serial(async () => {
    const r = await (await api()).get(new GetRequest(keyOf(instance), false));
    if (r.key?.codePart()?.length === 32) keys.set(instance, r.key);
    return JSON.parse(new TextDecoder().decode(new Uint8Array(r.state))) as FormState;
  });

export async function watch(instance: string) {
  await (await api()).subscribe(new SubscribeRequest(keyOf(instance)));
}

export async function sendResponse(instance: string, pk: string, r: Response) {
  const delta = bytes(JSON.stringify({ schema: null, responses: { [pk]: r } }));
  await (await api()).update(new UpdateRequest(keyOf(instance), new UpdateData(UpdateDataType.DeltaUpdate, new DeltaUpdate(delta))));
}

/** Publish a new form. Instance id = blake3(blake3(wasm) || owner pubkey), same as freenet-stdlib. */
export async function publish(schema: Schema) {
  const { sk, pk } = await identity();
  const code = new Uint8Array(await (await fetch(wasmUrl)).arrayBuffer());
  const codeHash = blake3(code), owner = unhex(pk);
  const instance = blake3(new Uint8Array([...codeHash, ...owner]));
  const key = new ContractKey(instance, codeHash);
  const contract = new WasmContractV1(new ContractCodeT(Array.from(code), Array.from(codeHash)), Array.from(owner), key);
  const schema_json = JSON.stringify(schema);
  const state: FormState = { schema_json, schema_sig: await signSchema(sk, schema_json), responses: {} };
  await (await api()).put(new PutRequest(new ContractContainer(ContractType.WasmContractV1, contract), bytes(JSON.stringify(state)), new RelatedContractsT()));
  return { instance: key.encode(), owner: pk };
}
