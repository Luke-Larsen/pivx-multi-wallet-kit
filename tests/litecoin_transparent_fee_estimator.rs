//! `estimate_raw_transparent_fee_to_many` must agree with the builder on
//! `Chain::Litecoin`, the same guarantee `transparent_fee_estimator.rs` pins
//! for PIVX. Both chains share `select_transparent_utxos`, so this mostly
//! confirms the `chain` parameter reaches every call on that shared path.

use pivx_wallet_kit::params::Chain;
use pivx_wallet_kit::transparent::builder::{
    Recipient, create_raw_transparent_transaction_to_many, estimate_raw_transparent_fee_to_many,
};
use pivx_wallet_kit::wallet::{self, SerializedUTXO, WalletData};

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn wallet_with(utxos: Vec<SerializedUTXO>) -> WalletData {
    let mut w = wallet::import_wallet(Chain::Litecoin, TEST_MNEMONIC, 5_000_000).unwrap();
    w.unspent_utxos = utxos;
    w
}

fn utxo(letter: &str, vout: u32, amount: u64) -> SerializedUTXO {
    SerializedUTXO {
        txid: letter.repeat(64),
        vout,
        amount,
        script: String::new(),
        height: 5_000_000,
        ..Default::default()
    }
}

fn seed() -> Vec<u8> {
    bip39::Mnemonic::parse_normalized(TEST_MNEMONIC)
        .unwrap()
        .to_seed("")
        .to_vec()
}

fn payee(index: u32) -> String {
    pivx_wallet_kit::keys::transparent_key_from_bip39_seed(Chain::Litecoin, &seed(), 0, 100 + index)
        .unwrap()
        .0
}

fn recipients(n: u32, each: u64) -> Vec<Recipient> {
    (0..n).map(|i| Recipient { address: payee(i), amount: each }).collect()
}

#[test]
fn estimate_matches_what_the_builder_charges() {
    for n in 1..=4u32 {
        for utxo_count in 1..=3usize {
            let utxos: Vec<SerializedUTXO> =
                (0..utxo_count).map(|i| utxo("a", i as u32, 50_000_000)).collect();
            let rs = recipients(n, 1_000_000);

            let mut w = wallet_with(utxos);
            let quoted = match estimate_raw_transparent_fee_to_many(Chain::Litecoin, &w, &rs) {
                Ok(f) => f,
                Err(_) => continue,
            };
            let built = create_raw_transparent_transaction_to_many(
                Chain::Litecoin,
                &mut w,
                &seed(),
                &rs,
            )
            .unwrap();

            assert_eq!(
                quoted, built.fee,
                "{n} recipients / {utxo_count} utxos: quoted {quoted} but charged {}",
                built.fee
            );
        }
    }
}

#[test]
fn estimate_grows_when_selection_needs_more_inputs() {
    let w = wallet_with(vec![
        utxo("a", 0, 10_000_000),
        utxo("b", 1, 10_000_000),
        utxo("c", 2, 10_000_000),
    ]);

    let one_input =
        estimate_raw_transparent_fee_to_many(Chain::Litecoin, &w, &recipients(1, 5_000_000)).unwrap();
    let two_inputs =
        estimate_raw_transparent_fee_to_many(Chain::Litecoin, &w, &recipients(1, 15_000_000)).unwrap();
    let three_inputs =
        estimate_raw_transparent_fee_to_many(Chain::Litecoin, &w, &recipients(1, 25_000_000)).unwrap();

    assert!(
        one_input < two_inputs && two_inputs < three_inputs,
        "fee should grow with input count: {one_input} / {two_inputs} / {three_inputs}"
    );
}

/// The estimator must reject exactly what the builder rejects, on Litecoin
/// too: no recipients, a zero amount, or a malformed address.
#[test]
fn estimate_rejects_everything_the_builder_rejects() {
    let good = payee(0);
    let cases: Vec<(&str, Vec<Recipient>)> = vec![
        ("empty recipient list", vec![]),
        ("zero amount", vec![Recipient { address: good.clone(), amount: 0 }]),
        (
            "malformed address",
            vec![Recipient { address: "not-an-address".into(), amount: 1_000 }],
        ),
        (
            "a pivx address is not a litecoin one",
            vec![Recipient {
                address: pivx_wallet_kit::keys::get_transparent_address(
                    Chain::Pivx,
                    TEST_MNEMONIC,
                )
                .unwrap(),
                amount: 1_000,
            }],
        ),
    ];

    for (name, rs) in cases {
        let mut w = wallet_with(vec![utxo("a", 0, 50_000_000)]);
        let estimate_err = estimate_raw_transparent_fee_to_many(Chain::Litecoin, &w, &rs).is_err();
        let build_err =
            create_raw_transparent_transaction_to_many(Chain::Litecoin, &mut w, &seed(), &rs)
                .is_err();
        assert!(estimate_err, "{name}: estimator accepted it");
        assert!(build_err, "{name}: builder accepted it");
    }
}
