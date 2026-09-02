//! HD-slot address rotation on `Chain::Litecoin`, mirroring the core
//! properties `transparent_address_rotation.rs` pins for PIVX. The mechanism
//! (per-slot key derivation, `hdSlot` tagging, foreign-slot rejection) is
//! chain-agnostic; what's new here is that Litecoin's own coin type and
//! prefix are what actually get used end to end.

use pivx_wallet_kit::keys;
use pivx_wallet_kit::params::Chain;
use pivx_wallet_kit::simd;
use pivx_wallet_kit::transparent::builder::{
    Recipient, create_raw_transparent_transaction_from_utxos_to_many,
};
use pivx_wallet_kit::wallet::{self, HdSlot, SerializedUTXO};

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn seed() -> Vec<u8> {
    bip39::Mnemonic::parse_normalized(TEST_MNEMONIC).unwrap().to_seed("").to_vec()
}

fn address_at(change: u32, index: u32) -> String {
    keys::transparent_address_at(Chain::Litecoin, &seed(), change, index).unwrap()
}

fn at_slot_with_script(letter: &str, vout: u32, amount: u64, change: u32, index: u32) -> SerializedUTXO {
    let script = keys::address_to_p2pkh_script(Chain::Litecoin, &address_at(change, index)).unwrap();
    SerializedUTXO {
        txid: letter.repeat(64),
        vout,
        amount,
        script: simd::hex::bytes_to_hex_string(&script),
        height: 5_000_000,
        hd_slot: Some(HdSlot { change, index }),
        ..Default::default()
    }
}

#[test]
fn slot_zero_matches_the_default_transparent_address() {
    let w = wallet::import_wallet(Chain::Litecoin, TEST_MNEMONIC, 5_000_000).unwrap();
    assert_eq!(
        address_at(0, 0),
        w.get_transparent_address().unwrap(),
        "transparent_address_at(Litecoin, 0, 0) must match the wallet's own default address"
    );
    assert!(address_at(0, 0).starts_with('L'));
}

#[test]
fn every_slot_yields_a_distinct_address() {
    let mut seen = std::collections::HashSet::new();
    for change in 0..2 {
        for index in 0..5 {
            assert!(seen.insert(address_at(change, index)), "duplicate address at {change}/{index}");
        }
    }
}

/// Spending from the matching slot signs and builds; a wrong `fromChange` /
/// `fromIndex` is rejected before ever reaching the signer, the same
/// foreign-slot guard PIVX's rotation tests pin.
#[test]
fn spending_from_the_matching_slot_succeeds_and_a_mismatched_one_is_rejected() {
    let utxo = at_slot_with_script("a", 0, 50_000_000, 0, 3);
    let to = address_at(0, 0);
    let recipients = vec![Recipient { address: to, amount: 10_000_000 }];

    // Matching slot: succeeds.
    create_raw_transparent_transaction_from_utxos_to_many(
        Chain::Litecoin,
        &seed(),
        0,
        3,
        std::slice::from_ref(&utxo),
        &recipients,
    )
    .expect("spending from the slot that received the output must succeed");

    // Wrong slot: rejected rather than silently signed with the wrong key.
    let err = create_raw_transparent_transaction_from_utxos_to_many(
        Chain::Litecoin,
        &seed(),
        0,
        4,
        &[utxo],
        &recipients,
    )
    .expect_err("a foreign-slot UTXO must be rejected, not signed");
    assert!(err.to_string().contains("HD slot"), "unexpected error: {err}");
}
