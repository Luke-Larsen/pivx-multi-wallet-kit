//! PIVX chain constants — single source of truth for chain-specific values.

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
/// PIVX Core's `CWalletTx::GetBlocksToMaturity` returns
/// `(COINBASE_MATURITY + 1) - GetDepthInMainChain()` and applies it to coinstake
/// outputs as well as coinbase ones, so an output is mature once its depth
/// *exceeds* this value. (The 600 that appears in staking discussions is
/// `nStakeMinDepth`, the depth an input needs before it may be used to stake.
/// It is not a spend-maturity rule and does not belong here.)
///
/// This matters for cold staking specifically: staking a delegation consumes it
/// and recreates it inside a coinstake transaction, so a live delegation spends
/// most of its life as a coinstake output.
pub const COINBASE_MATURITY: u32 = 100;
