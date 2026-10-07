# FreePolls

Polls and forms on [Freenet](https://freenet.org). No server, no account: every poll is a Freenet contract, every answer is signed by the respondent's own key.

- **Contract**: Rust compiled to WASM (`contract/`).
- **UI**: TypeScript + Vite, no framework (`ui/`). Talks to the node through [`@freenetorg/freenet-stdlib`](https://freenet.org/build/manual/typescript-sdk).
- **Invite-only polls**: one personal link = one vote, no accounts and no external services.
- **Question types**: single choice, multiple choice, free text, and **availability** (Doodle-style: one yes / maybe / no per date slot, with the best slot highlighted). Required flag, reordering, live results.

## How it works

One contract instance per poll. The contract **parameters** are the owner's ed25519 public key (32 bytes), so every owner gets a distinct address:

```
code_hash   = blake3(contract.wasm)
instance_id = blake3(code_hash || owner_pubkey)
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

At creation the UI generates one ed25519 keypair per invite: the public key goes into `allowed`, the secret goes into the personal link `#/f/<instance>.<owner>/i/<secret>`. Opening that link makes the browser sign as that invite, so it works even without local storage (for example inside the Freenet web container). One invite = one vote; reopening the link lets the invitee change their answer.

- The invite secrets exist only in the browser that created the poll. They are shown once after publishing and, where `localStorage` is available, kept so the owner can see them again. They cannot be recomputed.
- The number of invites is fixed when the poll is created.
- Anyone holding a personal link can vote as that invite, so share each link with one person only.
- Open polls (no `allowed`) behave as before: one response per key, and keys are free to create.

Answer values by question kind: `single` = option index, `multi` = list of option indexes, `text` = string, `avail` = one value per option (slot) in order, `0` = no, `1` = yes, `2` = maybe. The best availability slot is the one with most "yes", ties broken by "maybe".

`schema_json` and `answers_json` are kept as the exact strings that were signed, so no JSON canonicalization is needed on either side.

### Signed messages

| What | Signer | Message |
| --- | --- | --- |
| Schema | owner | `fps1\|<schema_json>` |
| Answers | respondent | `fpr1\|<owner_hex>\|<respondent_hex>\|<ts>\|<answers_json>` |

Including the owner key in the answer message stops a response from being replayed into another poll.

### Contract rules (`contract/src/lib.rs`)

- `validate_state`: schema signature valid; every response signature valid; every answer matches the schema (known question ids, option indexes in range, `avail` length equal to the number of slots, required questions answered, text up to 2000 bytes).
- `update_state`: the schema is set once. Responses merge **per respondent, last write wins by `ts`**. Older or equal `ts` is ignored. Anything invalid rejects the update.
- `summarize_state` / `get_state_delta`: summary = `{ has_schema, responses: pubkey -> ts }`; delta = the schema if the peer lacks it, plus responses newer than the peer's summary. An empty summary or empty state means "nothing known yet" (the node sends one on subscribe).

### UI (`ui/src/`)

- `lib.ts`: ed25519 identity (stored key or invite secret) and signing (`@noble/ed25519`), blake3 key derivation, WebSocket API wrapper, publish / get / update / subscribe.
- `main.ts`: hash router. `#/` is the poll builder, `#/f/<instance>.<owner_pubkey>[/i/<invite_secret>]` is the fill-in and results page. Inside the Freenet container the router also posts the hash to the shell so the address bar stays shareable. On an update notification the UI refetches the full state.
- The bundled `ui/src/contract.wasm` is what gets published with each new poll. Rebuild and copy it after any contract change.

## Development

Requirements: `rustup` with the `wasm32-unknown-unknown` target, `freenet` and `fdev` (freenet-core), Node 20+.

```bash
# contract: test, build, copy the wasm into the UI
cargo test
cargo build --release --target wasm32-unknown-unknown -p freepolls-contract
cp target/wasm32-unknown-unknown/release/freepolls_contract.wasm ui/src/contract.wasm
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
- **Open polls: one response per key, not per person.** Anyone can generate more keys. Use an invite-only poll when the vote count matters.
- **Key custody.** The respondent key lives in `localStorage`. Inside the Freenet web container the page is sandboxed without `allow-same-origin`, so storage is unavailable and the key lasts only for the session; the UI shows a warning. A delegate would fix this.
- Changing the contract changes its code hash: polls already published keep running the old contract.
- `subscribe()` does not resolve in local mode, so the UI does not wait for it.
- No way to close a poll yet.

## Roadmap

- Key custody in a Freenet delegate (stable identity, persistent "my polls").
- Encrypted answers readable only by the owner.
- Owner-signed "closed" flag.
- Conditional questions, import/export of results.
- Optional anti-spam stamps for open polls ([ante](https://github.com/soudasuwa/ante) proof-of-work or [Ghost Keys](https://freenet.org/ghostkey/)). Both only raise the cost of fake identities; neither proves one person = one vote.
- Re-issue or add invites after creation.

## License

MIT, see [LICENSE](LICENSE).
