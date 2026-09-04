//! `Chain::Litecoin` wallet creation: the birthday/checkpoint regression this
//! branch specifically had to avoid.
//!
//! `create_wallet_from_mnemonic` used to call `checkpoints::get_checkpoint`
//! unconditionally, which searches a PIVX-mainnet-only height table. Feeding
//! it a Litecoin height would have silently stamped `birthday_height`/
//! `last_block` with an unrelated PIVX-derived value instead of the real
//! height the caller passed in. These tests pin the fix: a non-PIVX wallet
//! remembers the exact height it was given.

use pivx_wallet_kit::params::Chain;
use pivx_wallet_kit::wallet;

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// A height far outside PIVX's embedded checkpoint range (2.7M-5.2M): if the
/// PIVX checkpoint table were consulted, this would fall back to its
/// earliest entry rather than the height actually passed in.
const LITECOIN_HEIGHT: u32 = 2_900_000;

#[test]
fn birthday_and_last_block_are_the_exact_height_passed_in() {
    let w = wallet::import_wallet(Chain::Litecoin, TEST_MNEMONIC, LITECOIN_HEIGHT).unwrap();
    assert_eq!(w.birthday_height, LITECOIN_HEIGHT as i32);
    assert_eq!(w.last_block, LITECOIN_HEIGHT as i32);
}

/// The PIVX path is unaffected: it still fast-forwards to the nearest
/// embedded checkpoint rather than starting from the raw height.
#[test]
fn pivx_still_uses_the_checkpoint_table() {
    let w = wallet::import_wallet(Chain::Pivx, TEST_MNEMONIC, LITECOIN_HEIGHT).unwrap();
    let (checkpoint_height, _) =
        pivx_wallet_kit::checkpoints::get_checkpoint(LITECOIN_HEIGHT as i32);
    assert_eq!(w.birthday_height, checkpoint_height);
    assert_eq!(w.last_block, checkpoint_height);
}

/// A wallet's `chain` field survives a JSON round-trip, and a Litecoin
/// wallet's transparent address renders under Litecoin's own prefix.
#[test]
fn chain_field_round_trips_through_serialization() {
    let w = wallet::import_wallet(Chain::Litecoin, TEST_MNEMONIC, LITECOIN_HEIGHT).unwrap();
    assert_eq!(w.chain, Chain::Litecoin);
    assert!(w.get_transparent_address().unwrap().starts_with('L'));

    let json = serde_json::to_string(&w).unwrap();
    let reloaded: pivx_wallet_kit::wallet::WalletData = serde_json::from_str(&json).unwrap();
    assert_eq!(reloaded.chain, Chain::Litecoin);
}

/// JSON serialized before the `chain` field existed has no such key at all;
/// deserializing it must default to `Chain::Pivx`, not fail.
#[test]
fn a_wallet_serialized_before_chain_existed_defaults_to_pivx() {
    let w = wallet::import_wallet(Chain::Pivx, TEST_MNEMONIC, 5_000_000).unwrap();
    let mut json: serde_json::Value = serde_json::to_value(&w).unwrap();
    json.as_object_mut().unwrap().remove("chain");

    let reloaded: pivx_wallet_kit::wallet::WalletData = serde_json::from_value(json).unwrap();
    assert_eq!(reloaded.chain, Chain::Pivx);
}
