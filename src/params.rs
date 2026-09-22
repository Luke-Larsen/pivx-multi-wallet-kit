//! Chain constants: single source of truth for chain-specific values.
//!
//! [`Chain`] selects which transparent-chain constants a call uses; Sapling
//! shielding and cold-staking have no Litecoin equivalent and stay
//! PIVX-only, ungated by this enum (see the modules that implement them).

/// Satoshis per PIV (8 decimals).
pub const COIN: u64 = 100_000_000;

/// BIP44 coin type for PIVX mainnet.
pub const PIVX_COIN_TYPE: u32 = 119;

/// Base58Check version byte for PIVX transparent pubkey addresses (produces `D...`).
pub const PIVX_PUBKEY_PREFIX: u8 = 30;

/// Base58Check version byte for PIVX cold-staking addresses (produces `S...`).
///
/// A staking address encodes the hash of the key permitted to *stake* a
/// delegated output, never to spend it. Verified against PIVX Core
/// (`chainparams.cpp`, mainnet `base58Prefixes[STAKING_ADDRESS]`) and
/// MyPIVXWallet (`chain_params.json`, `main.STAKING_ADDRESS`).
pub const PIVX_STAKING_PREFIX: u8 = 63;

/// Expected SHA256 of the Sapling output parameters (Groth16 proving key).
pub const OUTPUT_PARAMS_SHA256: &str =
    "2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4";

/// Expected SHA256 of the Sapling spend parameters (Groth16 proving key).
pub const SPEND_PARAMS_SHA256: &str =
    "8e48ffd23abb3a5fd9c5589204f32d9c31285a04b78096ba40a79b75677efc13";

/// SIGHASH_ALL flag byte appended to legacy (v1) transparent signature preimages.
pub const SIGHASH_ALL: u32 = 1;

/// Confirmations a coinbase or coinstake output needs before it may be spent.
///
/// `consensus.nCoinbaseMaturity` for mainnet, from PIVX Core's `chainparams.cpp`
/// (`CMainParams`). Testnet uses 15 and regtest 100, so this is a mainnet-only
/// constant like the rest of this module.
///
/// Two Core rules govern spending, and this crate follows the stricter one:
///
/// * **Consensus** (`validation.cpp`, `CheckInputs`) rejects a spend when
///   `nSpendHeight - coin.nHeight < nCoinbaseMaturity`, for
///   `IsCoinBase() || IsCoinStake()` alike.
/// * **Core's wallet** (`wallet.cpp`) waits one block longer:
///   `GetBlocksToMaturity` is `max(0, (nCoinbaseMaturity + 1) - depth)`, and
///   `IsInMainChainImmature` is `depth <= nCoinbaseMaturity`.
///
/// [`crate::wallet::SerializedUTXO::is_mature`] matches the wallet rule, so an
/// output is mature once its depth *exceeds* this value. The two differ at
/// exactly one depth (100), where consensus would accept a spend that Core's
/// wallet still declines to build. Being the stricter of the two is what
/// guarantees this crate never emits a premature spend. Both rules are
/// transcribed and cross-checked in `tests/coinstake_maturity.rs`.
///
/// The 600 that appears in staking discussions is `nStakeMinDepth`, the depth an
/// input needs before it may be used *to stake*. It is not a spend-maturity rule
/// and does not belong here.
///
/// This matters for cold staking specifically: staking a delegation consumes it
/// and recreates it inside a coinstake transaction, so a live delegation spends
/// most of its life as a coinstake output.
pub const COINBASE_MATURITY: u32 = 100;

/// A transparent chain this kit can build addresses/transactions for.
///
/// Only the transparent-tx surface (`keys`, `messages`, `fees`,
/// `transparent::builder`) dispatches on this. Sapling shielding and
/// P2CS cold-staking have no Litecoin equivalent, so those modules stay
/// unconditionally PIVX-only rather than taking a `Chain` they'd never
/// use a second value of.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, serde::Serialize, serde::Deserialize, tsify::Tsify)]
pub enum Chain {
    #[default]
    Pivx,
    Litecoin,
}

/// The constants [`Chain`] selects between for transparent-tx work.
pub struct ChainParams {
    /// BIP44 coin type (SLIP-44).
    pub coin_type: u32,
    /// Base58Check version byte for a P2PKH address.
    pub pubkey_prefix: u8,
    /// Base58Check version byte for a P2SH address, and the alternate byte
    /// where a chain accepts two (Litecoin has both `M...` and the older
    /// `3...`). `None` on a chain whose builder pays P2PKH only, which keeps
    /// the address parser refusing P2SH there exactly as it did before.
    pub p2sh_prefixes: &'static [u8],
    /// Human-readable part for native segwit (bech32) addresses. `None` on a
    /// chain without segwit, which makes every `hrp1...` address an error
    /// rather than something to guess at.
    pub bech32_hrp: Option<&'static str>,
    /// Base58Check version byte for a cold-staking address. `None` where the
    /// chain has no P2CS opcodes (Litecoin).
    pub staking_prefix: Option<u8>,
    /// Confirmations a coinbase output needs before it may be spent.
    pub coinbase_maturity: u32,
    /// Magic prefix for the `signmessage`/`verifymessage` digest.
    pub msg_magic: &'static str,
    /// Flat relay-fee rate, in satoshis per byte, for the raw P2PKH builder.
    pub fee_per_byte: u64,
    /// `DUST_RELAY_TX_FEE`-equivalent, in satoshis per kilobyte.
    pub dust_relay_fee: u64,
}

pub const PIVX: ChainParams = ChainParams {
    coin_type: PIVX_COIN_TYPE,
    pubkey_prefix: PIVX_PUBKEY_PREFIX,
    // PIVX has P2SH addresses, but this kit's builder has never paid one and
    // adding that is a separate decision with its own testing. Empty here
    // keeps the parser's behaviour on PIVX byte-for-byte what it was.
    p2sh_prefixes: &[],
    // PIVX has no segwit. The `ps1...` prefix that looks bech32-shaped is a
    // Sapling shielded payment address, routed long before this.
    bech32_hrp: None,
    staking_prefix: Some(PIVX_STAKING_PREFIX),
    coinbase_maturity: COINBASE_MATURITY,
    msg_magic: "DarkNet Signed Message:\n",
    fee_per_byte: 10,
    dust_relay_fee: 30_000,
};

/// Litecoin mainnet transparent-chain constants.
///
/// Each value below was read from Litecoin Core master, not inferred from
/// Bitcoin. That distinction matters: Litecoin keeps Bitcoin's relay floor but
/// not its dust rate, so a constant that looks reasonable next to Bitcoin's can
/// still be wrong by a factor of ten. Sources, in order:
///
/// * `coin_type`: SLIP-44 2.
/// * `pubkey_prefix`: `PUBKEY_ADDRESS` 48 in `chainparams.cpp`.
/// * `p2sh_prefixes`: `SCRIPT_ADDRESS` 5 and `SCRIPT_ADDRESS2` 50, both in
///   `chainparams.cpp`. Litecoin carries two: 50 produces the `M...` form
///   modern wallets display, 5 the older `3...` form that collides with
///   Bitcoin's P2SH. Core accepts both, so both are here. Note Core's naming
///   makes 5 the primary and 50 the alternate, which reads backwards next to
///   what wallets actually show.
/// * `bech32_hrp`: `bech32_hrp` in `chainparams.cpp`.
/// * `coinbase_maturity`: `COINBASE_MATURITY` in `consensus/consensus.h`.
/// * `msg_magic`: `MESSAGE_MAGIC` in `util/message.cpp`.
/// * `fee_per_byte`: 10 sat/B is 10,000 sat/kB, matching the wallet default
///   `DEFAULT_TRANSACTION_MINFEE` and clearing the 1,000 sat/kB
///   `DEFAULT_MIN_RELAY_TX_FEE` floor in `validation.h` ten times over.
/// * `dust_relay_fee`: `DUST_RELAY_TX_FEE` in `policy/policy.h`, which is
///   30,000, the same as PIVX. Bitcoin's is 3,000. Pinned by
///   `tests/litecoin_dust_threshold.rs`, because using Bitcoin's value here
///   builds change outputs a Litecoin node rejects as dust.
pub const LITECOIN: ChainParams = ChainParams {
    coin_type: 2,
    pubkey_prefix: 0x30,
    p2sh_prefixes: &[50, 5],
    bech32_hrp: Some("ltc"),
    staking_prefix: None,
    coinbase_maturity: 100,
    msg_magic: "Litecoin Signed Message:\n",
    fee_per_byte: 10,
    dust_relay_fee: 30_000,
};

impl Chain {
    /// The constants for this chain.
    pub const fn params(self) -> &'static ChainParams {
        match self {
            Chain::Pivx => &PIVX,
            Chain::Litecoin => &LITECOIN,
        }
    }
}
