//! What a "send max" control may offer, on `Chain::Litecoin`. No cold-staking
//! or coinstake concept exists on Litecoin, so this is the plain subset of
//! `max_sendable.rs`'s coverage: whatever `max_sendable_transparent` returns,
//! the builder must accept, using ordinary transparent UTXOs only.

use pivx_wallet_kit::keys;
use pivx_wallet_kit::params::Chain;
use pivx_wallet_kit::transparent::builder::{
    Recipient, TransparentTransactionResult, create_raw_transparent_transaction_to_many,
    max_sendable_transparent,
};
use pivx_wallet_kit::wallet::{self, SerializedUTXO, WalletData};
use std::error::Error;

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn seed() -> Vec<u8> {
    bip39::Mnemonic::parse_normalized(TEST_MNEMONIC).unwrap().to_seed("").to_vec()
}

fn ordinary(letter: &str, vout: u32, amount: u64) -> SerializedUTXO {
    SerializedUTXO {
        txid: letter.repeat(64),
        vout,
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

fn to_address() -> String {
    keys::get_transparent_address(Chain::Litecoin, TEST_MNEMONIC).unwrap()
}

fn recipients(amount: u64) -> Vec<Recipient> {
    vec![Recipient { address: to_address(), amount }]
}

fn build(
    utxos: Vec<SerializedUTXO>,
    rs: &[Recipient],
) -> Result<TransparentTransactionResult, Box<dyn Error>> {
    let mut w = wallet_with(utxos);
    create_raw_transparent_transaction_to_many(Chain::Litecoin, &mut w, &seed(), rs)
}

#[test]
fn the_maximum_is_buildable() {
    let utxos =
        vec![ordinary("a", 0, 10_000_000), ordinary("b", 1, 3_000_000), ordinary("c", 2, 500_000)];

    let max = max_sendable_transparent(Chain::Litecoin, &wallet_with(utxos.clone()), 1);
    assert!(max > 0);

    build(utxos, &recipients(max)).expect("the advertised maximum must be spendable");
}

#[test]
fn one_satoshi_above_the_maximum_is_refused() {
    let utxos = vec![ordinary("a", 0, 10_000_000), ordinary("b", 1, 3_000_000)];

    let max = max_sendable_transparent(Chain::Litecoin, &wallet_with(utxos.clone()), 1);
    let err = build(utxos, &recipients(max + 1)).expect_err("max + 1 must not build");
    assert!(err.to_string().contains("Insufficient"), "unexpected error: {err}");
}

#[test]
fn nothing_spendable_is_zero() {
    assert_eq!(max_sendable_transparent(Chain::Litecoin, &wallet_with(vec![]), 1), 0);

    let tiny = wallet_with(vec![ordinary("a", 0, 1_000)]);
    assert_eq!(max_sendable_transparent(Chain::Litecoin, &tiny, 1), 0);
}

#[test]
fn more_recipients_lower_the_maximum() {
    let utxos = vec![ordinary("a", 0, 10_000_000), ordinary("b", 1, 3_000_000)];
    let w = wallet_with(utxos);

    let one = max_sendable_transparent(Chain::Litecoin, &w, 1);
    let four = max_sendable_transparent(Chain::Litecoin, &w, 4);
    assert!(four < one, "four recipients cost more to pay than one");
}
