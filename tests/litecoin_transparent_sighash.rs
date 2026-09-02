//! Signature-level verification for the raw v1 builder, on `Chain::Litecoin`.
//!
//! The reusable core (`compute_sighash`, `sign_and_serialize`, the varint
//! writer) is exercised by `transparent_sighash.rs` already and takes no
//! chain-specific literal at all; what's new for Litecoin is the coin type in
//! the derivation path and the P2PKH prefix used to build/verify addresses.
//! This test proves the shared builder produces a genuinely valid,
//! independently-verifiable Litecoin-shaped (legacy v1) transaction, not just
//! one that happens to compile.

mod common;
use common::{decode as parse_tx, verify_all_signatures};

use pivx_wallet_kit::keys;
use pivx_wallet_kit::params::Chain;
use pivx_wallet_kit::simd;
use pivx_wallet_kit::transparent::builder::create_raw_transparent_transaction_from_utxos;
use pivx_wallet_kit::wallet::SerializedUTXO;

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn seed() -> Vec<u8> {
    bip39::Mnemonic::parse_normalized(TEST_MNEMONIC)
        .unwrap()
        .to_seed("")
        .to_vec()
}

fn utxo(txid_byte: &str, vout: u32, amount: u64) -> SerializedUTXO {
    SerializedUTXO {
        txid: txid_byte.repeat(64),
        vout,
        amount,
        script: String::new(),
        height: 5_000_000,
        ..Default::default()
    }
}

/// Baseline: build, sign, and independently verify a Litecoin send with
/// change. The verifier reconstructs the prevout script from the pubkey in
/// each `scriptSig`, exactly what a validating node has, so a bug in
/// `compute_sighash` cannot hide by being reused on both sides.
#[test]
fn a_litecoin_transaction_is_valid_and_pays_the_right_address() {
    let bip39_seed = seed();
    let to = keys::get_transparent_address(Chain::Litecoin, TEST_MNEMONIC).unwrap();
    assert!(to.starts_with('L'));
    let utxos = vec![utxo("b", 1, 100_000_000)];

    let result = create_raw_transparent_transaction_from_utxos(
        Chain::Litecoin,
        &bip39_seed,
        0,
        5,
        &utxos,
        &to,
        50_000_000,
    )
    .expect("builder should produce a signed tx");

    let tx = parse_tx(&simd::hex::hex_string_to_bytes(&result.txhex));

    assert_eq!(tx.version, 1, "Litecoin's raw path is legacy v1, same as PIVX's workaround path");
    assert_eq!(tx.locktime, 0);
    assert_eq!(tx.inputs.len(), 1);
    assert_eq!(tx.outputs.len(), 2, "expected recipient + change");
    assert!(tx.consumed_all, "serialized bytes must parse to exactly their own length");

    assert_eq!(verify_all_signatures(&tx), 1);

    let to_script = keys::address_to_p2pkh_script(Chain::Litecoin, &to).unwrap();
    let recipient = tx
        .outputs
        .iter()
        .find(|o| o.script_pubkey == to_script)
        .expect("no output pays the requested Litecoin address");
    assert_eq!(recipient.value, 50_000_000);

    let out_total: u64 = tx.outputs.iter().map(|o| o.value).sum();
    assert_eq!(100_000_000 - out_total, result.fee);
}

/// A signature built for the Litecoin key must not verify against the PIVX
/// address for the same seed: the two chains derive genuinely different keys
/// per BIP44 (`m/44'/2'/...` vs `m/44'/119'/...`), not just different
/// encodings of the same one.
#[test]
fn litecoin_and_pivx_derive_different_signing_keys() {
    let bip39_seed = seed();
    let (ltc_addr, ltc_pubkey, _) =
        keys::transparent_key_from_bip39_seed(Chain::Litecoin, &bip39_seed, 0, 0).unwrap();
    let (pivx_addr, pivx_pubkey, _) =
        keys::transparent_key_from_bip39_seed(Chain::Pivx, &bip39_seed, 0, 0).unwrap();

    assert_ne!(ltc_addr, pivx_addr);
    assert_ne!(ltc_pubkey, pivx_pubkey, "different coin-type paths must derive different keys");
}

/// No-change path: the whole UTXO minus fee goes to one output.
#[test]
fn no_change_path_is_valid() {
    let bip39_seed = seed();
    let to = keys::get_transparent_address(Chain::Litecoin, TEST_MNEMONIC).unwrap();
    let utxos = vec![utxo("c", 0, 100_000_000)];

    let fee = pivx_wallet_kit::fees::estimate_raw_transparent_fee(Chain::Litecoin, 1, 2);
    let amount = 100_000_000 - fee;

    let result = create_raw_transparent_transaction_from_utxos(
        Chain::Litecoin,
        &bip39_seed,
        0,
        5,
        &utxos,
        &to,
        amount,
    )
    .expect("builder should produce a signed tx");

    let tx = parse_tx(&simd::hex::hex_string_to_bytes(&result.txhex));
    assert_eq!(tx.outputs.len(), 1, "no change expected");
    assert_eq!(verify_all_signatures(&tx), 1);
}
