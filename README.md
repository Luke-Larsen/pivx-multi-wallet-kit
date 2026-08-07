# PIVX Wallet Kit

[![CI](https://github.com/PIVX-Labs/pivx-wallet-kit/actions/workflows/ci.yml/badge.svg)](https://github.com/PIVX-Labs/pivx-wallet-kit/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@pivx-labs/pivx-wallet-kit?color=cb3837&logo=npm)](https://www.npmjs.com/package/@pivx-labs/pivx-wallet-kit)

Pure-Rust wallet primitives for [PIVX](https://pivx.org), with first-class Sapling shield support.

Designed as the shared core that powers PIVX wallet clients (native CLIs, MCP servers, desktop apps, and embeddable web wallets) from a single audited codebase.

## Why

Every PIVX wallet reinvents the same primitives: BIP39 seeds, BIP44 derivation, address encoding, transparent tx construction, Sapling note management, shielded tx building. Each reimplementation is a new surface for subtle bugs and divergent behaviour between clients.

PIVX Wallet Kit consolidates that core into one library:

- **No I/O, no network, no filesystem.** The kit is pure logic. Consumers provide block data, current heights, proving-parameter bytes, and their own encryption keys.
- **Native + WASM.** Compiles to x86_64, aarch64, and `wasm32-unknown-unknown`, so the same code runs in [`pivx-agent-kit`](https://github.com/PIVX-Labs/pivx-agent-kit) on a server and in a browser wallet with zero logic drift.
- **Sapling-native.** Built on the [`librustpivx`](https://github.com/Duddino/librustpivx) fork of the Zcash Sapling crates, with PIVX's v3 type 0 transaction format.

## Architecture

```
pivx-wallet-kit (pure Rust, cdylib + rlib)
        │
        ├── native → pivx-agent-kit (CLI + MCP server, HTTP, disk)
        │
        └── WASM   → embeddable web wallets (npm @pivx-labs/pivx-wallet-kit)
```

## Modules

| Module                          | Purpose                                                                    |
|---------------------------------|----------------------------------------------------------------------------|
| `params`                        | PIVX chain constants: coin type, prefixes, Sapling param SHA256 hashes     |
| `amount`                        | PIV amount parsing / formatting (exact integer, no float)                  |
| `checkpoints`                   | Embedded mainnet checkpoint data for fast initial sync                     |
| `keys`                          | BIP32/BIP44 derivation, Sapling ZIP32 keys, transparent address encoding   |
| `messages`                      | PIVX Core-compatible message signing / verification                        |
| `fees`                          | Component-based fee estimation for v3 and raw v1 transactions              |
| `wallet`                        | In-memory `WalletData`, (de)serialization, symmetric secret encryption, Blockbook UTXO parser |
| `sync`                          | Pure shield stream parser: bytes → block batches                          |
| `sapling::sync`                 | `handle_blocks`: decrypt notes, advance tree, extract nullifiers           |
| `sapling::tree`                 | Commitment tree root extraction and empty-tree helpers                     |
| `sapling::prover`               | SHA256-verified proving parameter loader (consumer supplies bytes)         |
| `sapling::builder`              | Shield → anything transaction builder (`select_shield_notes` + `create_shield_transaction`) |
| `transparent::builder`          | `create_shielding_transaction` (t → shield) + `create_raw_transparent_transaction` (canonical entry: no prover needed for transparent dests) |
| `transparent::coldstake`        | Pay-to-cold-staking: P2CS script build/parse, `S...` addresses, delegation and withdrawal builders |
| `wasm` *(wasm32 only)*          | Class-style `Wallet` / `SaplingParams` / `Mnemonic` / `Fee` API for JS consumers |

## Building

```bash
# Native (release)
cargo build --release

# WASM (wasm-pack), bundler target for npm
wasm-pack build --release --target bundler --scope pivx-labs

# Tests (55 total: 14 unit + 2 messages + 39 integration with real
# mainnet tx fixtures)
cargo test
```

The native `rlib` is what downstream Rust consumers (e.g. `pivx-agent-kit`) depend on. The `wasm32-unknown-unknown` `cdylib` is the target for web wallets, distributed via npm as [`@pivx-labs/pivx-wallet-kit`](https://www.npmjs.com/package/@pivx-labs/pivx-wallet-kit).

### Parallel proving (`multicore`)

Groth16 proving is single-threaded by default on every target. The `multicore` feature turns on
rayon-parallel proving in `bellman` and `sapling`:

```bash
# Native: parallelises the Groth16 FFT/multiexp across cores.
# Recommended for servers, CLIs, and anything else not running in a browser.
cargo build --release --features multicore
```

There is no downside to enabling it natively; it is off by default only so that the same default
build is safe on every target. Downstream Rust consumers that care about proving latency should
turn it on.

On `wasm32` the feature additionally pulls in `wasm-bindgen-rayon`, and needs real setup: a
nightly toolchain with `-Z build-std`, the `atomics` and `bulk-memory` target features, COOP/COEP
headers on the serving origin, and a call to `initThreadPool` before any proving. **Without all
of that, leave it off**: rayon in a threadless WASM build blocks forever waiting for worker
threads that can never be spawned. The default single-threaded build proves in ~6s in-browser,
which is slower than native but always returns.

## How to use

### Native (Rust)

Add the kit to your `Cargo.toml`:

```toml
[dependencies]
pivx-wallet-kit = { git = "https://github.com/PIVX-Labs/pivx-wallet-kit" }
```

```rust
use pivx_wallet_kit::{wallet, sapling, transparent, keys};

// Import from mnemonic: consumer fetches current height from its RPC source.
let current_height = fetch_from_rpc();
let mut w = wallet::import_wallet(&mnemonic, current_height)?;

// Derive addresses (no prover needed):
let shield      = keys::get_default_address(&w.extfvk)?;
let transparent = w.get_transparent_address()?;

// Sign an arbitrary message with the transparent key (PIVX Core-compatible).
let bip39_seed = w.get_bip39_seed()?;
let (_, _, privkey) = keys::transparent_key_from_bip39_seed(&bip39_seed, 0, 0)?;
let signature = pivx_wallet_kit::messages::sign_message(&privkey, "hello")?;

// Build a pure transparent send (still no prover needed):
let tx = transparent::builder::create_raw_transparent_transaction(
    &mut w, &bip39_seed, &to_t_addr, amount_sat,
    0, None, // block_height / prover only used when destination is shield
)?;

// For anything touching Sapling, load the proving parameters once:
let prover = sapling::prover::verify_and_load_params(&output_bytes, &spend_bytes)?;

// Build a shield transaction: pure function, no I/O.
let tx = sapling::builder::create_shield_transaction(
    &mut w, &to_address, amount, &memo, block_height, &prover,
)?;

// Consumer broadcasts `tx.txhex` via whatever transport it chooses.
```

### Browser (npm)

```bash
npm install @pivx-labs/pivx-wallet-kit
```

The package exports a class-style API. The seed and mnemonic stay on the WASM heap: JS only ever sees handles and serialized JSON.

```js
import init, {
  Wallet,
  SaplingParams,
  Mnemonic,
  Fee,
  parseBlockbookUtxos,
  parseShieldStream,
  formatSatToPiv,
} from '@pivx-labs/pivx-wallet-kit';

await init();

// Create or import a wallet. `currentHeight` picks the latest embedded
// checkpoint for fast initial sync.
const phrase = Mnemonic.generate(12);
const wallet = Wallet.fromMnemonic(phrase, currentHeight);

const shield      = wallet.shieldAddress();
const transparent = wallet.transparentAddress();

// Sync transparent UTXOs from any Blockbook explorer. Cold staking needs one
// more call per funding tx; see "Cold staking needs scripts" below.
const raw = await fetch(`/api/v2/utxo/${transparent}`).then(r => r.json());
wallet.setUtxos(parseBlockbookUtxos(raw));
const transparentSat = wallet.transparentBalanceSat();

// Sync shield blocks from a PIVX Core compact-stream RPC.
const bytes = new Uint8Array(await (await fetch(streamURL)).arrayBuffer());
const blocks = parseShieldStream(bytes);
wallet.applyBlocks(blocks);
const shieldSat = wallet.shieldBalanceSat();

// Build a transparent → transparent tx (no prover required).
const tx = wallet.sendTransparentToTransparent(toAddress, 100_000n);

// Pay several transparent recipients from one transaction. Recipients are
// paid in order; any remainder returns to the wallet as change. `amount`
// is the recipient total, excluding change and fee.
const split = wallet.sendTransparentToMany({ recipients: [
  { address: sellerAddress,   amount: 95_000_000n },
  { address: referrerAddress, amount:  5_000_000n },
]});

// Build a shield-source tx (load proving params once per session).
const params = new SaplingParams(outputParamsBytes, spendParamsBytes);
const shieldTx = wallet.sendShield({
  to_address: shieldAddress,
  amount_sat: 50000,
  memo: '',
  block_height: chainTip,
}, params);

// Pay several recipients from shield notes. Unlike the transparent
// multi-send, shield and transparent destinations can be mixed in one
// transaction, and each shield recipient can carry its own memo.
const shieldSplit = wallet.sendShieldToMany({ recipients: [
  { address: shieldAddress,      amount: 95_000_000n, memo: 'invoice 41' },
  { address: transparentAddress, amount:  5_000_000n },
]}, chainTip + 1, params);

// Cold staking. The staking address may stake the coins but never move them;
// this wallet keeps spending authority, so the delegation can be withdrawn.
// Amounts at or above 500 PIV are split into staking-sized outputs.
const delegation = wallet.delegateColdStake(stakingAddress, 200_000_000n);

// Withdraw part of a delegation and keep the remainder staked. Without the
// staking address, change comes back as an ordinary output and stops staking.
const partial = wallet.withdrawColdStakeKeepingRest(
  0, 0, { utxos: delegatedUtxos }, myAddress, 400_000_000n, stakingAddress);

// Identify delegated outputs. Needs the script, which the UTXO endpoint does
// not return; see "Cold staking needs scripts" below.
const info = Wallet.inspectColdStakeScript(scriptHex);
// { isColdStake, isLof, stakingAddress, ownerAddress }

// Consumer broadcasts `shieldTx.txhex` via whatever transport it chooses.

// Encrypt before persisting to localStorage / IndexedDB:
const encrypted = wallet.toSerializedEncrypted(passphraseDerivedKey32Bytes);
localStorage.setItem('wallet', encrypted);
```

**See [`examples/web-wallet/`](examples/web-wallet/) for a full runnable demo**: one HTML file + ~200 lines of JS, hits a real PIVX explorer for transparent balance, runs a real shield sync from mainnet, and demonstrates the encrypt → reload → unlock cycle a web wallet would run before writing to `localStorage`.

### Cold staking needs scripts

A delegation is recognisable *only* from its `scriptPubKey`, and no explorer returns one from its UTXO endpoint: not Blockbook, not its work-alikes such as [rusty-blox](https://github.com/Liquid369/rusty-blox). Nothing else about a delegated output distinguishes it from an ordinary one, and the sighash commits to the exact script, so it cannot be inferred either.

Skip this and there is no error, just wrong answers: `delegatedBalanceSat()` reads 0, delegated outputs are counted as spendable and can be picked for an ordinary send that the network then rejects, and `withdrawColdStake` has nothing to sign against. Wallets that never delegate are unaffected.

The script comes from a second call. `/api/v2/tx/{txid}` returns `vout[n].hex`, the scriptPubKey of outpoint `(txid, n)`. Join it on before parsing:

```js
const utxos = await fetch(`/api/v2/utxo/${transparent}`).then(r => r.json());

// One fetch per distinct funding tx, not per UTXO, and bound the concurrency.
// A delegation that has been staking a while has one output per stake, so this
// list reaches the hundreds; see `mapWithLimit` in examples/web-wallet.
const txids = [...new Set(utxos.map(u => u.txid))];
const txs = await mapWithLimit(txids, 6, id =>
  fetch(`/api/v2/tx/${id}`).then(r => r.json()));

const scripts = new Map();
for (const tx of txs) for (const o of tx.vout) scripts.set(`${tx.txid}:${o.n}`, o.hex);

wallet.setUtxos(parseBlockbookUtxos(
  utxos.map(u => ({ ...u, script: scripts.get(`${u.txid}:${u.vout}`) ?? '' })),
));

wallet.delegatedBalanceSat(); // now non-zero if anything is delegated
```

`parseBlockbookUtxos` reads the script from `script`, `scriptPubKey` (flat or Core's nested verbose-RPC object) or `hex`, so copy it across under whichever name is handiest. Anything that is not valid even-length hex is treated as absent.

`/api/v2/address/{addr}?details=txs` is the bulk alternative: it returns the same `vout[].hex` for every transaction touching the address, in one paged call.

#### Staked delegations are coinstake outputs

Staking a delegation **consumes and recreates it**. The script is preserved byte-for-byte (consensus requires it, so the delegation keeps working and `is_p2cs` keeps matching), but the outpoint changes on every stake and the replacement lives in a *coinstake* transaction. Two consequences:

- **The outpoint churns.** Refresh the UTXO set immediately before building a withdrawal and treat a missing-inputs rejection as "re-fetch and rebuild". A set cached for an hour may already be stale.
- **The new output is immature.** PIVX applies `COINBASE_MATURITY` to coinstake outputs, so it cannot be spent until it is 100 blocks deep. Explorers list it as an ordinary UTXO well before then: on mainnet a live delegation showed up in `/api/v2/utxo` with 19 confirmations, indistinguishable in that response from a spendable one.

The kit enforces this, but it can only do so with information you supply: it performs no I/O, so it cannot see confirmations or transaction types for itself. Set `coinstake` and `confirmations` on each UTXO and every builder respects them. Both default to "ordinary, spendable", so this changes nothing for consumers that don't populate them.

Detect a coinstake from the same tx responses the script join already fetched:

```js
// PIVX marks a coinstake with an empty zero-value first output, and unlike a
// coinbase it always spends a real input.
const isCoinstakeTx = tx =>
  tx.vout.length >= 2 && tx.vout[0].value === '0' && !!tx.vin?.[0]?.txid;

// `txs` is from the join above, so this costs no extra requests.
const coinstakeTxids = new Set(txs.filter(isCoinstakeTx).map(tx => tx.txid));

wallet.setUtxos(parseBlockbookUtxos(utxos.map(u => ({
  ...u,
  script: scripts.get(`${u.txid}:${u.vout}`) ?? '',
  coinstake: coinstakeTxids.has(u.txid),
  confirmations: u.confirmations,   // explorers return this already
}))));

wallet.transparentBalanceSat();  // spendable now
wallet.immatureBalanceSat();     // exists, but not yet spendable
wallet.delegatedBalanceSat();    // delegated, mature or not
```

With that in place a builder will not select an immature output, and naming one explicitly is an error that says how long the wait is:

```
UTXO abc…:1 was created by a coinstake 19 block(s) ago and needs 101.
It was staked recently, so it becomes withdrawable in 82 block(s)
```

Balance semantics are worth stating precisely, because the three overlap:

| accessor | includes |
|---|---|
| `transparentBalanceSat` | ordinary outputs, mature only: what a plain send can spend right now |
| `delegatedBalanceSat` | every P2CS output, mature or not: what is committed to staking |
| `immatureBalanceSat` | every coinstake/coinbase output below maturity, delegated or not |

A freshly staked delegation appears in both `delegatedBalanceSat` and `immatureBalanceSat`, and in neither `transparentBalanceSat`. That is deliberate: one answers "what do I hold", the other "what is still landing".

## Status

**v0.4.0**: **cold staking**, plus dust handling that was missing crate-wide.

Delegate transparent funds to a staking key that can stake them but never move them,
and withdraw them again: `delegateColdStake`, `withdrawColdStake`,
`withdrawColdStakeKeepingRest`, `stakingAddress` / `stakingAddressAt`,
`inspectColdStakeScript`, and matching fee estimators. Delegations at or above 500 PIV
are split into staking-sized outputs, matching MyPIVXWallet's `stakeSplitTarget`:
staking works per output, so one large delegation is a single staking unit where several
compete independently.

Every script constant was verified byte-for-byte against both PIVX Core and
MyPIVXWallet rather than reconstructed, and the delegate → withdraw cycle is confirmed
on mainnet (blocks 5522082 and 5522083). A wrong P2CS script does not fail loudly: it
produces an output that is either unspendable or spendable by the wrong party.

**One behaviour changed for everyone, not just cold staking.** PIVX rejects any output
worth less than it costs to spend: `IsStandardTx` fails with `reason = "dust"`, so no
node relays the transaction. The crate had no notion of this and would build
transactions nothing would accept. See *Upgrading to 0.4.0*.

### Upgrading to 0.4.0

The cold-staking API is entirely new; nothing existing changed shape. Two behaviours
differ:

1. **Dust outputs are now handled.** The threshold is 5460 sat for an ordinary output
   (6240 for a cold-staking one). Recipients below it are **rejected** rather than
   silently producing an unrelayable transaction; change below it is **dropped to the
   miner** rather than emitted.

2. **`result.fee` is now the fee actually paid**, computed from inputs minus outputs,
   rather than the estimate. When dust change is absorbed the two differ: the reported
   figure is the larger, true one. Consumers displaying a fee to users will show a
   slightly higher number in that case, which is the number the user actually pays.

Detecting delegated outputs needs each UTXO's `script`, and no explorer returns one from
its UTXO endpoint. A delegated output whose script is unknown is treated as ordinary, so
it counts as spendable and an ordinary send may select it, which the network then
rejects. **Consumers using cold staking must join the script on themselves**, from
`/api/v2/tx/{txid}` as `vout[n].hex`; `parseBlockbookUtxos` carries it through when it is
present. See [Cold staking needs scripts](#cold-staking-needs-scripts). Wallets that
never delegate are unaffected.

**v0.3.0**: multi-recipient sends (`sendTransparentToMany`, `sendShieldToMany`,
`sendTransparentFromUtxosToMany`, plus matching fee estimators), and four fixes to
pre-existing bugs found while building them. **The API is purely additive: no existing
signature changed, and existing single-recipient sends produce byte-identical
transactions**, but three fixes tighten validation, so input that was previously accepted
is now refused. See *Upgrading to 0.3.0* below.

### Upgrading to 0.3.0

Existing calls keep working unchanged. Four behaviours differ, all deliberately:

1. **Transparent addresses are now checksum- and version-validated.** Previously
   `address_to_p2pkh_script` decoded base58 without verifying either, so a single mistyped
   character was accepted and paid a pubkey hash nobody holds the key for. Addresses from
   other networks, and PIVX P2SH addresses (`7...`), were also accepted and wrapped in a
   P2PKH script, which is unspendable. All of these now error. If a consumer was relying on
   sending to P2SH addresses, those sends were never recoverable and need a real P2SH path.

2. **Duplicate outpoints are rejected.** Blockbook lists the same UTXO twice while a
   transaction is confirming, which made the wallet read double its balance and build a
   transaction spending one output twice. `parseBlockbookUtxos` now collapses duplicates,
   and the builders refuse a set that still contains any, including UTXOs supplied
   directly to `sendTransparentFromUtxos*`.

3. **`applyBlocks` now advances `lastBlock()` and skips already-applied heights.** This is
   the one that needs an action. Previously `last_block` only ever moved in
   `resetToCheckpoint`, so a consumer syncing from `lastBlock() + 1`: the pattern this
   README and the web-wallet example both document: re-applied the whole range from the
   checkpoint on every sync after the first, advancing the commitment tree twice and
   shifting every witness position.

   **Wallets persisted by an earlier version carry that stale cursor**, so their first sync
   after upgrading re-applies once more. Call `resetToCheckpoint()` and resync once after
   upgrading; that restores state byte-identical to a fresh sync. Wallets created on 0.3.0
   need nothing.

4. **Over-long shield memos are rejected by the fee estimator**, not only by the builder.
   The 512-byte Sapling limit is on encoded bytes, so a 200-character string of multi-byte
   characters (600 bytes) is refused.

**v0.2.5**: **fixes a hang that made every shield send unusable in the browser.** `sendTransparentToShield` (and any other Groth16 proving path) never returned in WASM builds, spinning at 100% CPU indefinitely; the same transaction built in ~0.35s natively. Cause: `bellman` and `sapling` both default-enable a `multicore` feature that pulls in rayon, and this crate declared them without `default-features = false`, so rayon shipped inside the default WASM artifact and blocked forever waiting for worker threads that a threadless build can never spawn. Both dependencies are now pinned single-threaded: matching what librustpivx's own workspace already does, and CI asserts the built artifact is rayon-free. Parallel proving remains available behind the `multicore` feature, which now switches rayon and the `wasm-bindgen-rayon` thread pool together instead of only the latter. Shield proofs take ~6s single-threaded in-browser. No API change.

**v0.2.4**: `sync`: parse compact spend/output counts as CompactSize varint.

**v0.2.3**: exposes `create_raw_transparent_transaction_from_utxos` to JS as `Wallet.sendTransparentFromUtxos(fromChange, fromIndex, utxos, toAddress, amountSat)`. Same primitive that was Rust-only in v0.2.2, now available to web wallets and Node.js consumers. Backwards-compatible; existing callers see no API change.

**v0.2.2**: adds `transparent::builder::create_raw_transparent_transaction_from_utxos` for spending from any HD-indexed address with caller-supplied UTXOs. Unblocks consumers that maintain multiple receive addresses (payment processors, hierarchical accounting). Backwards-compatible; existing callers see no API change.

**v0.2.1**: adds diversifier-based shield address derivation (`shield_address_at`) for merchant use cases where one address per invoice is needed. Backwards-compatible; existing callers see no API change.

**v0.2.0**: class-style WASM API, full audit pass (3 rounds), end-to-end mainnet verification across all four send paths (T↔T, T↔S, S↔T, S↔S). Used in production by [`pivx-agent-kit`](https://github.com/PIVX-Labs/pivx-agent-kit) and [`pivx-tasks`](https://github.com/PIVX-Labs/pivx-tasks).

## License

MIT © JSKitty
