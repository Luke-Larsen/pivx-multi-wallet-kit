//! A malformed txid must never reach a signature, on `Chain::Litecoin` too.
//!
//! `validate_outpoints` (see `outpoint_validation.rs`) is chain-agnostic
//! already; this exercises it end to end through the `chain`-parameterized
//! builder entry points to confirm the parameter threads all the way through
//! without disturbing the guard.

use pivx_wallet_kit::keys;
use pivx_wallet_kit::params::Chain;
use pivx_wallet_kit::transparent::builder::{
    Recipient, create_raw_transparent_transaction_from_utxos,
    create_raw_transparent_transaction_to_many, estimate_raw_transparent_fee_to_many,
};
use pivx_wallet_kit::wallet::{self, SerializedUTXO, WalletData};

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn seed() -> Vec<u8> {
    bip39::Mnemonic::parse_normalized(TEST_MNEMONIC).unwrap().to_seed("").to_vec()
}

fn to_address() -> String {
    keys::get_transparent_address(Chain::Litecoin, TEST_MNEMONIC).unwrap()
}

fn utxo(txid: &str, amount: u64) -> SerializedUTXO {
    SerializedUTXO {
        txid: txid.to_string(),
        vout: 0,
        amount,
        script: String::new(),
        height: 5_000_000,
        ..Default::default()
    }
}

fn wallet_with(utxos: Vec<SerializedUTXO>) -> WalletData {
    let mut w = wallet::import_wallet(Chain::Litecoin, TEST_MNEMONIC, 5_000_000).unwrap();
    w.unspent_utxos = utxos;
    w
}

fn one(amount: u64) -> Vec<Recipient> {
    vec![Recipient { address: to_address(), amount }]
}

fn malformed() -> Vec<(&'static str, String)> {
    vec![
        ("odd length", "a".repeat(63)),
        ("empty", String::new()),
        ("non-hex letter", "h".repeat(64)),
    ]
}

#[test]
fn a_well_formed_txid_is_accepted() {
    let txid = "ab".repeat(32);
    create_raw_transparent_transaction_from_utxos(
        Chain::Litecoin,
        &seed(),
        0,
        0,
        &[utxo(&txid, 500_000)],
        &to_address(),
        100_000,
    )
    .unwrap_or_else(|e| panic!("valid txid {txid} was rejected: {e}"));
}

#[test]
fn the_caller_supplied_builder_refuses_every_malformed_txid() {
    for (why, txid) in malformed() {
        let err = create_raw_transparent_transaction_from_utxos(
            Chain::Litecoin,
            &seed(),
            0,
            0,
            &[utxo(&txid, 500_000)],
            &to_address(),
            100_000,
        )
        .expect_err(&format!("{why}: a malformed txid was signed instead of refused"));
        assert!(err.to_string().contains("malformed txid"), "{why}: wrong error, got {err}");
    }
}

#[test]
fn the_wallet_state_builder_and_estimator_agree_on_rejection() {
    for (why, txid) in malformed() {
        let mut w = wallet_with(vec![utxo(&txid, 500_000)]);
        let estimate_err =
            estimate_raw_transparent_fee_to_many(Chain::Litecoin, &w, &one(100_000)).is_err();
        let build_err =
            create_raw_transparent_transaction_to_many(Chain::Litecoin, &mut w, &seed(), &one(100_000))
                .is_err();
        assert!(estimate_err, "{why}: estimator accepted it");
        assert!(build_err, "{why}: builder accepted it");
    }
}
