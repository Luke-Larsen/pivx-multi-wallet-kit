//! Pay-to-cold-staking (P2CS) script construction and parsing.
//!
//! Cold staking splits authority over an output in two: a *staking* key that
//! may stake the coins but never move them, and an *owner* key that may spend
//! them. The output script encodes both hashes and selects between them with a
//! branch the spender chooses at redeem time.
//!
//! # Provenance
//!
//! Every constant and offset below was verified byte-for-byte against two
//! independent sources rather than reconstructed from memory, because a wrong
//! script here does not fail loudly — it produces an output that is either
//! unspendable or spendable by the wrong party.
//!
//! * **PIVX Core** — `src/script/standard.cpp`
//!   (`GetScriptForStakeDelegation`, `GetScriptForStakeDelegationLOF`,
//!   `MatchPayToColdStaking`), `src/script/script.cpp`
//!   (`CScript::IsPayToColdStaking`), `src/script/script.h` (opcode values),
//!   `src/chainparams.cpp` (address prefixes, upgrade heights).
//! * **MyPIVXWallet** — `scripts/script.js` (`isP2CS`, `getAddressFromHash`),
//!   `scripts/transaction_builder.js` (`addColdStakeOutput`),
//!   `scripts/transaction.js` (`signInput`).
//!
//! Note that MyPIVXWallet's `OWNER_START_INDEX` / `COLD_START_INDEX` constants
//! are named the opposite way round to what they hold — index 6 is rendered as
//! a `coldaddress` (staking, `S...`) and index 28 as a `pubkeyhash` (owner,
//! `D...`). The offsets here follow Core's `MatchPayToColdStaking`, which is
//! unambiguous.

use crate::keys;
use crate::params::{PIVX_PUBKEY_PREFIX, PIVX_STAKING_PREFIX};
use std::error::Error;

// Opcodes, from PIVX Core `src/script/script.h`.
const OP_DUP: u8 = 0x76;
const OP_HASH160: u8 = 0xa9;
const OP_ROT: u8 = 0x7b;
const OP_IF: u8 = 0x63;
const OP_ELSE: u8 = 0x67;
const OP_ENDIF: u8 = 0x68;
const OP_EQUALVERIFY: u8 = 0x88;
const OP_CHECKSIG: u8 = 0xac;
const OP_FALSE: u8 = 0x00;
const PUSH_20: u8 = 0x14;

/// `OP_CHECKCOLDSTAKEVERIFY_LOF` — "last output free", permitting the final
/// output of a coinstake to pay elsewhere (masternode and budget payments).
const OP_CHECKCOLDSTAKEVERIFY_LOF: u8 = 0xd1;

/// `OP_CHECKCOLDSTAKEVERIFY` — the post-v6.0 form, which drops the last-output
/// exemption.
const OP_CHECKCOLDSTAKEVERIFY: u8 = 0xd2;

/// Exact serialized length of a P2CS script. Core's `IsPayToColdStaking`
/// requires equality, not a minimum.
pub const P2CS_SCRIPT_LEN: usize = 51;

/// Offsets of the two embedded hashes, per Core's `MatchPayToColdStaking`:
/// `stakerPubKeyHash = script[6..26]`, `ownerPubKeyHash = script[28..48]`.
const STAKER_HASH_OFFSET: usize = 6;
const OWNER_HASH_OFFSET: usize = 28;

/// The two P2CS variants. Both are accepted by `IsPayToColdStaking`, so an
/// output of either kind is spendable by the same owner path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColdStakeVariant {
    /// `OP_CHECKCOLDSTAKEVERIFY_LOF` (`0xd1`). **The current network form.**
    ///
    /// Core selects between the two on `UPGRADE_V6_0` activation, and V6 is set
    /// to `NO_ACTIVATION_HEIGHT` on mainnet, testnet and regtest alike — so
    /// `fV6Enforced` is false everywhere today and Core itself emits LOF.
    /// MyPIVXWallet emits LOF unconditionally, which agrees.
    Lof,
    /// `OP_CHECKCOLDSTAKEVERIFY` (`0xd2`), for after v6.0 activates.
    ///
    /// Provided so the switch is a one-line change rather than a re-derivation,
    /// but do not emit it until V6 is actually active: pre-activation nodes
    /// treat the delegation differently.
    V6,
}

impl ColdStakeVariant {
    fn opcode(self) -> u8 {
        match self {
            ColdStakeVariant::Lof => OP_CHECKCOLDSTAKEVERIFY_LOF,
            ColdStakeVariant::V6 => OP_CHECKCOLDSTAKEVERIFY,
        }
    }
}

/// The two key hashes a P2CS output commits to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColdStakeHashes {
    /// May stake the output, never spend it.
    pub staker: [u8; 20],
    /// May spend the output.
    pub owner: [u8; 20],
}

/// Decode a Base58Check address, returning `(version, hash160)`.
///
/// Shares the checksum discipline of the P2PKH path: an unverified address is
/// how funds reach a hash nobody holds a key for, and a delegation locks the
/// coins behind *two* hashes, so a typo in either is equally unrecoverable.
fn decode_checked(address: &str) -> Result<(u8, [u8; 20]), Box<dyn Error>> {
    use sha2::{Digest, Sha256};

    let decoded = bs58::decode(address)
        .into_vec()
        .map_err(|e| format!("Invalid base58 address: {e}"))?;
    if decoded.len() != 25 {
        return Err(format!(
            "Invalid address length: {} bytes, expected 25 (1 version + 20 hash + 4 checksum)",
            decoded.len()
        )
        .into());
    }

    let (payload, checksum) = decoded.split_at(21);
    let expected = Sha256::digest(Sha256::digest(payload));
    if expected[..4] != checksum[..] {
        return Err(format!(
            "Invalid address checksum for {address} — the address is mistyped or corrupted"
        )
        .into());
    }

    let mut hash = [0u8; 20];
    hash.copy_from_slice(&payload[1..21]);
    Ok((payload[0], hash))
}

/// Base58Check-encode `hash160` under `version`.
fn encode_checked(version: u8, hash: &[u8; 20]) -> String {
    use sha2::{Digest, Sha256};

    let mut payload = Vec::with_capacity(25);
    payload.push(version);
    payload.extend_from_slice(hash);
    let checksum = Sha256::digest(Sha256::digest(&payload));
    payload.extend_from_slice(&checksum[..4]);
    bs58::encode(payload).into_string()
}

/// Encode a staking (`S...`) address from a key hash.
pub fn encode_staking_address(hash: &[u8; 20]) -> String {
    encode_checked(PIVX_STAKING_PREFIX, hash)
}

/// Decode a staking (`S...`) address to its key hash.
///
/// Rejects owner (`D...`) addresses: swapping the two arguments of a delegation
/// would hand spending authority to the intended staker, so the version byte is
/// enforced rather than ignored.
pub fn decode_staking_address(address: &str) -> Result<[u8; 20], Box<dyn Error>> {
    let (version, hash) = decode_checked(address)?;
    if version != PIVX_STAKING_PREFIX {
        return Err(format!(
            "Address {address} has version byte {version} — not a PIVX staking address, which \
             uses {PIVX_STAKING_PREFIX} and renders as `S...`"
        )
        .into());
    }
    Ok(hash)
}

/// Decode an owner (`D...`) transparent address to its key hash.
pub fn decode_owner_address(address: &str) -> Result<[u8; 20], Box<dyn Error>> {
    let (version, hash) = decode_checked(address)?;
    if version != PIVX_PUBKEY_PREFIX {
        return Err(format!(
            "Address {address} has version byte {version} — not a PIVX transparent address, \
             which uses {PIVX_PUBKEY_PREFIX} and renders as `D...`"
        )
        .into());
    }
    Ok(hash)
}

/// Build a P2CS `scriptPubKey` delegating to `staker`, spendable by `owner`.
///
/// Layout, matching Core's `GetScriptForStakeDelegationLOF` exactly:
///
/// ```text
/// OP_DUP OP_HASH160 OP_ROT OP_IF <verify-op> 0x14 <staker:20>
///                          OP_ELSE          0x14 <owner:20>
///                          OP_ENDIF OP_EQUALVERIFY OP_CHECKSIG
/// ```
///
/// The `OP_IF` branch carries the staking hash and the `OP_ELSE` branch the
/// owner hash — the redeeming script pushes a boolean to pick one. Getting that
/// order backwards would let the staker spend and leave the owner unable to.
pub fn build_p2cs_script(
    staker: &[u8; 20],
    owner: &[u8; 20],
    variant: ColdStakeVariant,
) -> Vec<u8> {
    let mut script = Vec::with_capacity(P2CS_SCRIPT_LEN);
    script.push(OP_DUP);
    script.push(OP_HASH160);
    script.push(OP_ROT);
    script.push(OP_IF);
    script.push(variant.opcode());
    script.push(PUSH_20);
    script.extend_from_slice(staker);
    script.push(OP_ELSE);
    script.push(PUSH_20);
    script.extend_from_slice(owner);
    script.push(OP_ENDIF);
    script.push(OP_EQUALVERIFY);
    script.push(OP_CHECKSIG);
    debug_assert_eq!(script.len(), P2CS_SCRIPT_LEN);
    script
}

/// Build a P2CS `scriptPubKey` from a staking address and an owner address.
pub fn p2cs_script_from_addresses(
    staking_address: &str,
    owner_address: &str,
    variant: ColdStakeVariant,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let staker = decode_staking_address(staking_address)?;
    let owner = decode_owner_address(owner_address)?;
    Ok(build_p2cs_script(&staker, &owner, variant))
}

/// Whether `script` is a well-formed P2CS output.
///
/// Mirrors Core's `CScript::IsPayToColdStaking`, including the exact-length
/// requirement — a 52-byte script with the right prefix is not P2CS.
pub fn is_p2cs(script: &[u8]) -> bool {
    script.len() == P2CS_SCRIPT_LEN
        && script[0] == OP_DUP
        && script[1] == OP_HASH160
        && script[2] == OP_ROT
        && script[3] == OP_IF
        && (script[4] == OP_CHECKCOLDSTAKEVERIFY || script[4] == OP_CHECKCOLDSTAKEVERIFY_LOF)
        && script[5] == PUSH_20
        && script[26] == OP_ELSE
        && script[27] == PUSH_20
        && script[48] == OP_ENDIF
        && script[49] == OP_EQUALVERIFY
        && script[50] == OP_CHECKSIG
}

/// Whether `script` is the LOF variant. Assumes [`is_p2cs`] already passed.
pub fn is_p2cs_lof(script: &[u8]) -> bool {
    is_p2cs(script) && script[4] == OP_CHECKCOLDSTAKEVERIFY_LOF
}

/// Extract both key hashes from a P2CS script.
pub fn parse_p2cs_script(script: &[u8]) -> Result<ColdStakeHashes, Box<dyn Error>> {
    if !is_p2cs(script) {
        return Err("Not a pay-to-cold-staking script".into());
    }
    let mut staker = [0u8; 20];
    let mut owner = [0u8; 20];
    staker.copy_from_slice(&script[STAKER_HASH_OFFSET..STAKER_HASH_OFFSET + 20]);
    owner.copy_from_slice(&script[OWNER_HASH_OFFSET..OWNER_HASH_OFFSET + 20]);
    Ok(ColdStakeHashes { staker, owner })
}

/// The staking and owner addresses a P2CS script pays, rendered in their
/// respective formats (`S...` and `D...`).
pub fn addresses_from_p2cs_script(script: &[u8]) -> Result<(String, String), Box<dyn Error>> {
    let h = parse_p2cs_script(script)?;
    Ok((
        encode_staking_address(&h.staker),
        encode_checked(PIVX_PUBKEY_PREFIX, &h.owner),
    ))
}

/// Build the `scriptSig` that redeems a P2CS output back to its owner.
///
/// Identical to a P2PKH `scriptSig` except for a single `OP_FALSE` between the
/// signature and the pubkey. That byte is the branch selector: `OP_ROT` lifts it
/// to the top of the stack and `OP_IF` pops it, so false takes `OP_ELSE` — the
/// owner hash — which `OP_EQUALVERIFY` then matches against `hash160(pubkey)`.
/// Pushing true instead selects the staking branch, which is the staker's path
/// and is not what a spend wants.
///
/// Matches MyPIVXWallet's `signInput({ isColdStake: true })`.
pub fn build_p2cs_owner_script_sig(sig_with_hashtype: &[u8], pubkey: &[u8]) -> Vec<u8> {
    let mut script_sig = Vec::with_capacity(sig_with_hashtype.len() + pubkey.len() + 3);
    script_sig.push(sig_with_hashtype.len() as u8);
    script_sig.extend_from_slice(sig_with_hashtype);
    script_sig.push(OP_FALSE);
    script_sig.push(pubkey.len() as u8);
    script_sig.extend_from_slice(pubkey);
    script_sig
}

/// P2PKH `scriptPubKey` for a key hash — the form a P2CS output is redeemed
/// *into* when an owner withdraws a delegation.
pub fn p2pkh_script_from_hash(hash: &[u8; 20]) -> Vec<u8> {
    let mut script = Vec::with_capacity(25);
    script.push(OP_DUP);
    script.push(OP_HASH160);
    script.push(PUSH_20);
    script.extend_from_slice(hash);
    script.push(OP_EQUALVERIFY);
    script.push(OP_CHECKSIG);
    script
}

/// Derive the owner key hash the kit signs with, from a BIP39 seed and HD slot.
///
/// Convenience wrapper so callers building a delegation do not have to
/// re-derive and re-decode their own address.
pub fn owner_hash_from_seed(
    bip39_seed: &[u8],
    change: u32,
    index: u32,
) -> Result<[u8; 20], Box<dyn Error>> {
    let (address, _pubkey, _priv) =
        keys::transparent_key_from_bip39_seed(bip39_seed, change, index)?;
    decode_owner_address(&address)
}
