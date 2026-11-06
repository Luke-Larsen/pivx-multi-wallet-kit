//! Dogecoin: derivation, addresses, fees, dust, and the one hazard that cannot
//! be guarded against.
//!
//! Dogecoin is a transparent Bitcoin-fork chain with no shielded pool, no cold
//! staking and, unlike Litecoin, **no segwit at all**: Dogecoin Core carries no
//! `bech32_hrp` field, so there is no `doge1...` form to support. It pays
//! `D...` (P2PKH, version 30) and `9.../A...` (P2SH, version 22).
//!
//! Two of its constants are traps, and both are asserted here rather than
//! trusted:
//!
//! * **Coinbase maturity is 240, not 30.** `chainparams.cpp` assigns
//!   `consensus.nCoinbaseMaturity = 30` effective from height 0, then
//!   `digishieldConsensus` raises it to 240 from 145000 and `auxpowConsensus`
//!   inherits that from 371337. Mainnet is past both. Reading only the first
//!   assignment gives a figure wrong by a factor of eight.
//! * **Dust is a flat amount, not a rate.** `CTxOut::IsDust` takes a `CAmount`
//!   and compares `nValue < dustLimit` with no script length involved.
//!
//! The derivation vector below was cross-checked against a from-scratch
//! BIP39/BIP32/secp256k1 implementation in Python sharing no code with this
//! crate, as were the PIVX and Litecoin vectors at the same time.

use pivx_wallet_kit::address::{OutputKind, address_to_destination, address_to_script};
use pivx_wallet_kit::fees;
use pivx_wallet_kit::params::{Chain, DOGECOIN, DustPolicy, PIVX};
use pivx_wallet_kit::transparent::builder::{
    Recipient, create_raw_transparent_transaction_to_many,
};
use pivx_wallet_kit::wallet::{self, SerializedUTXO, WalletData};
use pivx_wallet_kit::{keys, messages, simd};
use sha2::{Digest, Sha256};

mod common;

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// `m/44'/3'/0'/0/0` for the BIP39 reference phrase, cross-checked independently.
const DOGE_VECTOR: &str = "DBus3bamQjgJULBJtYXpEzDWQRwF5iwxgC";
/// The same phrase on PIVX. Note it is also a `D...` address: that is the point
/// of `pivx_and_dogecoin_addresses_are_indistinguishable` below.
const PIVX_VECTOR: &str = "DPo9TNvPwy2ZfmVM3CRCxbBvh6NojguWXJ";

const HASH20: [u8; 20] = [0x5e; 20];

fn seed() -> Vec<u8> {
    bip39::Mnemonic::parse_normalized(TEST_MNEMONIC).unwrap().to_seed("").to_vec()
}

fn b58check(version: u8, payload: &[u8]) -> String {
    let mut full = vec![version];
    full.extend_from_slice(payload);
    let checksum = Sha256::digest(Sha256::digest(&full));
    full.extend_from_slice(&checksum[..4]);
    bs58::encode(full).into_string()
}

// --- constants, against Dogecoin Core -----------------------------------------

#[test]
fn the_constants_are_the_ones_dogecoin_core_uses() {
    assert_eq!(DOGECOIN.coin_type, 3, "SLIP-44 3");
    assert_eq!(DOGECOIN.pubkey_prefix, 30, "PUBKEY_ADDRESS");
    assert_eq!(DOGECOIN.p2sh_prefixes, &[22], "SCRIPT_ADDRESS");
    assert_eq!(DOGECOIN.bech32_hrp, None, "Dogecoin has no segwit");
    assert_eq!(DOGECOIN.staking_prefix, None, "Dogecoin has no cold staking");
    assert_eq!(DOGECOIN.msg_magic, "Dogecoin Signed Message:\n");
}

#[test]
fn coinbase_maturity_is_the_post_digishield_figure() {
    // 30 is the pre-Digishield value and is what a reader who stops at the
    // first assignment in chainparams.cpp walks away with.
    assert_eq!(DOGECOIN.coinbase_maturity, 240);
    assert_ne!(
        DOGECOIN.coinbase_maturity, 30,
        "30 is consensus.nCoinbaseMaturity before Digishield raised it at height 145000"
    );
}

#[test]
fn the_fee_rate_is_ten_times_the_other_chains() {
    // DEFAULT_MIN_RELAY_TX_FEE = RECOMMENDED_MIN_TX_FEE / 10 = 100,000 sat/kB.
    // An ordinary rate, so nothing structural is needed for it.
    assert_eq!(DOGECOIN.fee_per_byte, 100);
    assert_eq!(DOGECOIN.fee_per_byte, PIVX.fee_per_byte * 10);
}

#[test]
fn dust_is_flat_and_ignores_output_size() {
    assert_eq!(
        DOGECOIN.dust,
        DustPolicy::Flat { relay: 100_000, mine: 1_000_000 }
    );

    // The property a rate cannot express.
    let thresholds: Vec<u64> = [22usize, 23, 25, 34, 51]
        .iter()
        .map(|&l| fees::dust_threshold(Chain::Dogecoin, l))
        .collect();
    assert!(
        thresholds.windows(2).all(|w| w[0] == w[1]),
        "Dogecoin's dust floor must not vary with script length, got {thresholds:?}"
    );
    // The mining limit, not the relay limit: an output that relays but is never
    // mined strands coins in a transaction that looked accepted.
    assert_eq!(fees::dust_threshold(Chain::Dogecoin, 25), 1_000_000);
}

// --- derivation and addresses -------------------------------------------------

#[test]
fn derivation_matches_the_independently_checked_vector() {
    let got = keys::get_transparent_address(Chain::Dogecoin, TEST_MNEMONIC).unwrap();
    assert_eq!(got, DOGE_VECTOR);
    assert!(got.starts_with('D'), "Dogecoin mainnet addresses start with D");

    // And the path really is coin type 3, not inherited from another chain.
    let at_zero = keys::transparent_address_at(Chain::Dogecoin, &seed(), 0, 0).unwrap();
    assert_eq!(at_zero, DOGE_VECTOR);
}

#[test]
fn rotated_slots_differ_from_each_other_and_from_other_chains() {
    let mut seen = std::collections::HashSet::new();
    for index in 0..6u32 {
        let a = keys::transparent_address_at(Chain::Dogecoin, &seed(), 0, index).unwrap();
        assert!(seen.insert(a.clone()), "slot 0/{index} repeated an address");
        assert!(a.starts_with('D'));
        // The same slot on PIVX must be a different address despite the shared
        // version byte, because the coin type differs.
        let p = keys::transparent_address_at(Chain::Pivx, &seed(), 0, index).unwrap();
        assert_ne!(a, p, "slot 0/{index} collided across chains");
    }
}

#[test]
fn p2pkh_and_p2sh_are_paid_with_the_right_scripts() {
    let p2pkh = address_to_destination(Chain::Dogecoin, DOGE_VECTOR).unwrap();
    assert_eq!(p2pkh.kind, OutputKind::P2pkh);
    assert_eq!(&p2pkh.script[..3], &[0x76, 0xa9, 0x14]);
    assert_eq!(&p2pkh.script[23..], &[0x88, 0xac]);

    let addr = b58check(22, &HASH20);
    let p2sh = address_to_destination(Chain::Dogecoin, &addr).unwrap();
    assert_eq!(p2sh.kind, OutputKind::P2sh);
    let expected: Vec<u8> = [&[0xa9, 0x14][..], &HASH20[..], &[0x87][..]].concat();
    assert_eq!(p2sh.script, expected);
}

#[test]
fn dogecoin_has_no_segwit_so_a_bech32_address_is_refused() {
    // There is no `doge1...`. Anything bech32-shaped must be turned away.
    for a in [
        "doge1qw508d6qejxtdg4y5r3zarvary0c5xw7kgmn4n9",
        "ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kgmn4n9",
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
    ] {
        assert!(
            address_to_script(Chain::Dogecoin, a).is_err(),
            "{a} must be refused on a chain with no segwit"
        );
    }
}

// --- the hazard that cannot be guarded ---------------------------------------

/// The one cross-chain mistake this crate cannot catch, asserted so the
/// limitation is explicit in the test suite rather than only in prose.
///
/// Both chains use Base58Check version byte 30, so the two addresses are the
/// same 25 bytes in the same layout. Every other cross-chain pairing here is
/// refused; this one is accepted by both, and there is no unambiguous
/// alternative form to redirect a caller to the way Litecoin's `3...` has `M...`.
#[test]
fn pivx_and_dogecoin_addresses_are_indistinguishable() {
    assert_eq!(
        DOGECOIN.pubkey_prefix, PIVX.pubkey_prefix,
        "if these ever diverge, the hazard is gone and the docs should say so"
    );

    // Each chain accepts the other's address, and produces the same script for
    // it. This is the failure, recorded as a fact rather than a bug.
    let on_doge = address_to_script(Chain::Dogecoin, PIVX_VECTOR)
        .expect("a PIVX address is accepted on Dogecoin, which is the hazard");
    let on_pivx = address_to_script(Chain::Pivx, DOGE_VECTOR)
        .expect("a Dogecoin address is accepted on PIVX, which is the hazard");
    assert_eq!(on_doge.len(), 25);
    assert_eq!(on_pivx.len(), 25);

    // Both vectors even look alike to a user.
    assert!(DOGE_VECTOR.starts_with('D') && PIVX_VECTOR.starts_with('D'));
}

#[test]
fn the_other_cross_chain_pairings_are_still_refused() {
    // Dogecoin's P2SH version (22) is its own, and Litecoin's forms are not
    // payable here, so the collision really is limited to PIVX P2PKH.
    let ltc = keys::get_transparent_address(Chain::Litecoin, TEST_MNEMONIC).unwrap();
    assert!(address_to_script(Chain::Dogecoin, &ltc).is_err(), "L... on Dogecoin");
    assert!(address_to_script(Chain::Litecoin, DOGE_VECTOR).is_err(), "D... on Litecoin");
    // Litecoin's M... P2SH (version 50) is not Dogecoin's 22.
    assert!(address_to_script(Chain::Dogecoin, &b58check(50, &HASH20)).is_err());
    // And Dogecoin's 9.../A... is not Litecoin's.
    assert!(address_to_script(Chain::Litecoin, &b58check(22, &HASH20)).is_err());
}

#[test]
fn message_signatures_do_distinguish_the_two_chains() {
    // The one place the shared version byte does not bite: the magic string
    // differs, so a signature is chain-specific even though the address is not.
    let (_, _, pk) = keys::transparent_key_from_bip39_seed(Chain::Dogecoin, &seed(), 0, 0).unwrap();
    let sig = messages::sign_message(Chain::Dogecoin, &pk, "hello").unwrap();

    assert!(messages::verify_message(Chain::Dogecoin, DOGE_VECTOR, "hello", &sig).unwrap());
    // Same bytes, verified under PIVX's magic, must not pass.
    let under_pivx = messages::verify_message(Chain::Pivx, DOGE_VECTOR, "hello", &sig);
    assert!(
        matches!(under_pivx, Ok(false) | Err(_)),
        "a Dogecoin signature must not verify as PIVX"
    );
}

// --- transactions -------------------------------------------------------------

fn wallet_with(amount: u64) -> WalletData {
    let mut w = wallet::import_wallet(Chain::Dogecoin, TEST_MNEMONIC, 5_900_000).unwrap();
    w.unspent_utxos = vec![SerializedUTXO {
        txid: "d".repeat(64),
        vout: 0,
        amount,
        script: String::new(),
        height: 5_900_000,
        ..Default::default()
    }];
    w
}

#[test]
fn a_send_builds_signs_and_verifies() {
    let mut w = wallet_with(500_000_000);
    let rs = vec![Recipient { address: DOGE_VECTOR.to_string(), amount: 100_000_000 }];
    let r = create_raw_transparent_transaction_to_many(Chain::Dogecoin, &mut w, &seed(), &rs)
        .expect("a Dogecoin send should build");

    let decoded = common::decode(&simd::hex::hex_string_to_bytes(&r.txhex));
    assert_eq!(decoded.outputs[0].value, 100_000_000);
    assert_eq!(
        decoded.outputs[0].script_pubkey,
        address_to_script(Chain::Dogecoin, DOGE_VECTOR).unwrap()
    );
    // The input side is P2PKH as on every other chain, so signatures verify the
    // same way.
    assert_eq!(common::verify_all_signatures(&decoded), decoded.inputs.len());

    // Value is conserved.
    let out: u64 = decoded.outputs.iter().map(|o| o.value).sum();
    assert_eq!(out + r.fee, 500_000_000);
}

#[test]
fn the_fee_covers_the_bytes_at_dogecoins_own_rate() {
    let mut w = wallet_with(2_000_000_000);
    let rs = vec![Recipient { address: DOGE_VECTOR.to_string(), amount: 500_000_000 }];
    let r = create_raw_transparent_transaction_to_many(Chain::Dogecoin, &mut w, &seed(), &rs)
        .unwrap();

    let bytes = simd::hex::hex_string_to_bytes(&r.txhex).len() as u64;
    let minimum = bytes * DOGECOIN.fee_per_byte;
    assert!(
        r.fee >= minimum,
        "fee {} does not cover {bytes} bytes at {} sat/B ({minimum} sat)",
        r.fee,
        DOGECOIN.fee_per_byte
    );
}

#[test]
fn an_output_under_the_flat_dust_floor_is_refused() {
    // 1,000,000 sat is a far higher bar than the other chains' 5,460, and it
    // does not move with script size.
    let floor = fees::dust_threshold(Chain::Dogecoin, 25);
    let mut w = wallet_with(2_000_000_000);
    let rs = vec![Recipient { address: DOGE_VECTOR.to_string(), amount: floor - 1 }];
    let err = create_raw_transparent_transaction_to_many(Chain::Dogecoin, &mut w, &seed(), &rs)
        .expect_err("below the flat floor must be refused");
    assert!(err.to_string().contains("dust threshold"), "got: {err}");

    let mut w = wallet_with(2_000_000_000);
    let rs = vec![Recipient { address: DOGE_VECTOR.to_string(), amount: floor }];
    create_raw_transparent_transaction_to_many(Chain::Dogecoin, &mut w, &seed(), &rs)
        .expect("exactly at the floor must build");
}

#[test]
fn a_wallet_records_its_own_chain_and_no_checkpoint() {
    // Dogecoin has no shielded pool, so there is no checkpoint table to consult
    // and the height given is the height recorded.
    let w = wallet::import_wallet(Chain::Dogecoin, TEST_MNEMONIC, 5_900_123).unwrap();
    assert_eq!(w.chain, Chain::Dogecoin);
    assert_eq!(w.last_block, 5_900_123);
    assert_eq!(w.birthday_height, 5_900_123);
    assert_eq!(w.get_transparent_address().unwrap(), DOGE_VECTOR);
}
