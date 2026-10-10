# FreePolls

Polls and forms on [Freenet](https://freenet.org). No server, no account: every poll is a Freenet contract, every answer is signed by the respondent's own key.

- **Contract**: Rust compiled to WASM (`contract/`).
- **UI**: TypeScript + Vite, no framework (`ui/`). Talks to the node through [`@freenetorg/freenet-stdlib`](https://freenet.org/build/manual/typescript-sdk).
- **Invite-only polls**: one personal link = one vote, no accounts and no external services.
- **Stable identity**: the signing key and the owner's data live in a Freenet delegate, so they survive sessions even inside the sandboxed web container.
- **Question types**: single choice, multiple choice, free text, and **availability** (Doodle-style: one yes / maybe / no per date slot, with the best slot highlighted). Required flag, reordering, live results.

## How it works

One contract instance per poll. The contract **parameters** are the owner's ed25519 public key (32 bytes) followed by a random 16-byte salt. The salt gives every poll its own address, so one owner can run any number of polls:

```
code_hash   = blake3(contract.wasm)
instance_id = blake3(code_hash || owner_pubkey || salt)
```

The UI computes the same id before publishing (same derivation as `freenet-stdlib`), so the link is known up front.

### State (JSON)

```jsonc
{
  "schema_json": "{\"title\":\"...\",\"questions\":[{\"id\":\"q1\",\"kind\":\"single\",\"text\":\"...\",\"options\":[\"a\",\"b\"],\"required\":true}]}",
  "schema_sig":  "<hex ed25519 signature by the owner>",
  "responses": {
    "<respondent pubkey hex>": { "ts": 1791409999000, "answers_json": "{\"q1\":1}", "sig": "<hex>" }
  }
}
```

### Invite-only polls

The schema may carry `"allowed": ["<pubkey hex>", ...]` (up to 1000 keys, signed by the owner together with the rest of the schema). When present, the contract accepts responses **only from those keys**.

At creation the UI generates one ed25519 keypair per invite: the public key goes into `allowed`, the secret goes into the personal link `#/f/<instance>.<params>/i/<secret>`. Opening that link makes the browser sign as that invite, so it works even without local storage (for example inside the Freenet web container). One invite = one vote; reopening the link lets the invitee change their answer.

- The invite secrets exist only in the browser that created the poll. They are shown once after publishing and, where `localStorage` is available, kept so the owner can see them again. They cannot be recomputed.
- The number of invites is fixed when the poll is created.
- Anyone holding a personal link can vote as that invite, so share each link with one person only.
- Open polls (no `allowed`) take one response per key, and each respondent must carry an ante proof of work (below).

### Open polls and ante

Keys are free to create, so an open poll asks each respondent for a proof of work from [ante](https://github.com/soudasuwa/ante), as FreeTunes does for reports. The response carries `ante`: the hex CBOR `AnteProof` signed by the respondent's *ante identity*, which lives in the ante delegate on their own node (`ui/src/ante-delegate.wasm`, pinned by blake3 `f10f40a3...925f`).

- Purpose `freepolls:vote:v1:<params_hex>:<respondent_hex>`, at least 18 bits of work (a few seconds in the browser). The node asks the respondent's consent before any work is spent.
- The proof is bound to the poll and the respondent key, not the answers, so changing an answer reuses it.
- One respondent per ante identity. If two respondent keys carry the same ante identity, the smaller key is kept, so every merge order converges.
- It raises the cost of each fake respondent; it does not prove one person = one vote: someone willing to grind can still answer many times with many ante identities.
- Polls published before this contract version have no ante check; the UI only asks for the work where the poll's address matches the current contract.

Answer values by question kind: `single` = option index, `multi` = list of option indexes, `text` = string, `avail` = one value per option (slot) in order, `0` = no, `1` = yes, `2` = maybe. The best availability slot is the one with most "yes", ties broken by "maybe".

`schema_json` and `answers_json` are kept as the exact strings that were signed, so no JSON canonicalization is needed on either side.

### Signed messages

| What | Signer | Message |
| --- | --- | --- |
| Schema | owner | `fps1\|<params_hex>\|<schema_json>` |
| Answers | respondent | `fpr1\|<params_hex>\|<respondent_hex>\|<ts>\|<answers_json>` |

`params_hex` is the full contract parameters (owner key plus salt). Binding both messages to it stops a signed schema from being cloned into another poll, and stops a response from being replayed into another poll, even one by the same owner.

### Contract rules (`contract/src/lib.rs`)

- `validate_state`: schema signature valid; every response signature valid; every answer matches the schema (known question ids, option indexes in range, `avail` length equal to the number of slots, required questions answered, text up to 2000 bytes).
- `validate_state`: open polls also need a valid ante proof per respondent and no ante identity used twice.
- `update_state`: the schema is set once. Responses merge **per respondent, last write wins by `ts`**. Older or equal `ts` is ignored. For open polls, a respondent whose ante identity is already held by a smaller key is ignored, and one held by a larger key is replaced. Anything invalid rejects the update.
- `summarize_state` / `get_state_delta`: summary = `{ has_schema, responses: pubkey -> ts }`; delta = the schema if the peer lacks it, plus responses newer than the peer's summary. An empty summary or empty state means "nothing known yet" (the node sends one on subscribe).

### UI (`ui/src/`)

- `lib.ts`: ed25519 identity (stored key or invite secret) and signing (`@noble/ed25519`), blake3 key derivation, WebSocket API wrapper, publish / get / update / subscribe.
- `main.ts`: hash router. `#/` is the poll builder, `#/f/<instance>.<params>[/i/<invite_secret>]`, `#/explore` is the public directory is the fill-in and results page. Inside the Freenet container the router also posts the hash to the shell so the address bar stays shareable. On an update notification the UI refetches the full state.
- The bundled `ui/src/contract.wasm` is what gets published with each new poll. Rebuild and copy it after any contract change.

## Identity delegate

Inside the Freenet web container the page is sandboxed without storage, so a key kept in the page would be lost on every reload. The `delegate/` crate (`freepolls-identity`) keeps it in the node instead:

- **Per-app identity.** One ed25519 key per calling web app. The namespace is the app's contract id, which the node attests, so another app cannot read or use this key. Local clients that are not a web app share one `dev` namespace.
- **Signing.** The page sends `{"op":"sign","msg":"..."}` and receives the signature; the key is never sent back. The UI generates the key once and hands it over with `{"op":"init","sk":"..."}`, which is ignored if the delegate already holds one (that is also how a key from an earlier `localStorage` session is kept). The secret therefore passes through the page once.
- **Small store.** `put` / `get` keep short strings under validated key names: the "My polls" list and the owner's invite links (otherwise lost with the page). Values are capped at 256 KB.
- **Registration.** The UI registers the delegate on each load (the delegate code is bundled as `ui/src/identity.wasm`). The node ignores the cipher and nonce fields since freenet-core #4146 but still checks their sizes (32 and 24 bytes). The SDK has no delegate method yet, so the UI uses its low-level `sendRequest`. Delegate replies carry no request id, so calls are serialized and matched by order.
- **Fallback.** If the delegate does not answer within 8 s, the UI falls back to `localStorage`, then to memory for the session (with a warning).
- **Trust.** The delegate signs whatever the calling app asks, like a key kept in the page would. It protects the key from other apps and from storage loss, not from the app itself.

## Public directory

Polls can opt in to a shared directory, shown on the **Explore** page. It is a second contract (`registry/`), one instance per admin key (the admin public key is its parameter).

- **Listing.** In the builder, tick "List in the public directory" (off by default, never available for invite-only polls). The owner of an open poll can also list it later with the button on the poll page. The UI signs an entry `fpl1|<instance>|<params>|<title>|<ts>` with the owner key and attaches a proof-of-work nonce.
- **Proof-of-work.** `sha256("<message>|<nonce>")` must start with 18 zero bits (about 260k hashes, a few seconds in the browser). It makes bulk spam costly, but a determined flooder can still push older polls out.
- **Size.** The newest 500 entries are kept (deterministic pruning, so merge order does not matter). Titles are limited to 120 characters.
- **Moderation.** The admin key can publish a signed blocklist (`fpb1|<ts>|<ids>`); blocked polls vanish from the directory and cannot be re-added. The admin page is at `#/admin` (not linked anywhere): paste the admin secret and the ids to hide. Entries are not checked against the polls themselves, so an entry can point to a poll that does not exist.
- **Bootstrap.** The directory address is derived from its code and the admin key, so the UI can compute it. The first visitor on a node creates it empty; that first load can take up to 30 s.
- **Privacy.** Listing makes the title and the owner key discoverable. Publishing is permanent: there is no global delete on Freenet.

The admin public key is `REGISTRY_ADMIN` in `ui/src/lib.ts`. The secret is not in the repo (`.secrets/` is ignored). Changing the admin key, or the registry code, creates a new, empty directory.

## Development

Requirements: `rustup` with the `wasm32-unknown-unknown` target, `freenet` and `fdev` (freenet-core), Node 20+.

```bash
# contract: test, build, copy the wasm into the UI
cargo test
(cd ui && npm test)   # the ante proof as the UI builds it
cargo build --release --target wasm32-unknown-unknown -p freepolls-contract -p freepolls-registry -p freepolls-identity
cp target/wasm32-unknown-unknown/release/freepolls_contract.wasm ui/src/contract.wasm
cp target/wasm32-unknown-unknown/release/freepolls_registry.wasm ui/src/registry.wasm
cp target/wasm32-unknown-unknown/release/freepolls_identity.wasm ui/src/identity.wasm
```

On Windows, make sure `~/.cargo/bin` comes before any standalone Rust install in `PATH`, otherwise `cargo` will not see the wasm target.

Run an isolated local node (does not touch a node you already run on 7509):

```bash
mkdir -p .devnode/config .devnode/data .devnode/log
freenet local local --ws-api-port 7510 \
  --config-dir .devnode/config --data-dir .devnode/data --log-dir .devnode/log \
  --disable-auto-update
```

Run the UI against it:

```bash
cd ui
npm install
echo VITE_NODE=127.0.0.1:7510 > .env.local
npm run dev        # http://localhost:5173
```

In production the UI connects to `ws://<page host>/v1/contract/command`; `VITE_NODE` only applies to `npm run dev`.

## Publishing the site

```bash
cd ui
npm run build
fdev website init freepolls            # once: creates the signing key. Back it up!
fdev website publish dist --key freepolls
# later releases:
fdev website update dist --key freepolls
```

`publish` prints the site URL, `http://127.0.0.1:7509/v1/contract/web/<key>/`. Losing the signing key means the site can no longer be updated.

## Limitations

- **Answers are public.** Anyone with the poll link can read the state. Do not collect personal or sensitive data: Freenet has no global delete, so published polls and answers cannot be withdrawn.
- **Open polls: one response per ante identity, not per person.** Each extra identity costs a few seconds of work, which slows spam but does not stop a determined grinder. Use an invite-only poll when the vote count matters.
- Changing the contract changes its code hash: polls already published keep running the old contract.
- `subscribe()` does not resolve in local mode, so the UI does not wait for it.
- No way to close a poll yet.

- **The identity belongs to your node.** A different node or computer is a different identity (Freenet does not sync delegates across devices yet). Polls and answers stay valid; you just cannot edit them from the other node.

## Roadmap

- Encrypted answers readable only by the owner.
- Owner-signed "closed" flag.
- Conditional questions, import/export of results.
- Directory: re-check entries against the polls themselves, search, pagination.
- [Ghost Keys](https://freenet.org/ghostkey/) as a stronger alternative to ante for open polls.
- Re-issue or add invites after creation.

## License

MIT, see [LICENSE](LICENSE).
