//! The fee model must never under-estimate the transaction it prices.
//!
//! `fee_covers_relay_minimum.rs` establishes this for PIVX. It has to be
//! re-established for Litecoin rather than assumed, and re-established again
//! now that a Litecoin output can be one of four sizes instead of always 34
//! bytes. An estimate that comes in under the real serialized size produces a
//! transaction a node refuses, and the refusal happens after the user has
//! pressed send.
//!
//! Two things make the real size move, and both are exercised here:
//!
//! * **Signature length.** A DER-encoded ECDSA signature is 70 to 72 bytes
//!   depending on the leading bits of r and s. The per-input allowance has to
//!   cover the longest one, not the typical one, so this walks many HD slots
//!   until it has seen more than one transaction size and asserts it did.
//! * **Output form.** P2SH is 2 bytes under the P2PKH baseline, P2WPKH 3
//!   under, P2WSH 9 over. The last of those is the dangerous one: it is the
//!   only form that can push the real size past a flat P2PKH estimate.
//!
//! The assertion is against the kit's own advertised rate rather than
//! Litecoin's 1 sat/byte relay floor. The floor is ten times lower, so a
//! transaction could under-estimate its own size badly and still relay, and
//! the bug would sit there until the day it did not. Holding the model to its
//! own stated rate is the tighter and more useful invariant.

mod common;

use pivx_wallet_kit::address::address_to_script;
use pivx_wallet_kit::params::{Chain, LITECOIN};
use pivx_wallet_kit::transparent::builder::{
    Recipient, create_raw_transparent_transaction_from_utxos_to_many,
    create_raw_transparent_transaction_to_many,
};
use pivx_wallet_kit::wallet::{self, SerializedUTXO, WalletData};
use pivx_wallet_kit::{keys, simd};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

const HASH20: [u8; 20] = [0x9c; 20];
const HASH32: [u8; 32] = [0x7d; 32];

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

/// Every destination form a Litecoin send can pay, as (label, address).
fn every_form() -> Vec<(&'static str, String)> {
    vec![
        ("P2PKH", keys::get_transparent_address(Chain::Litecoin, TEST_MNEMONIC).unwrap()),
        ("P2SH", b58check(50, &HASH20)),
        ("P2WPKH", bech32_v0("ltc", &HASH20)),
        ("P2WSH", bech32_v0("ltc", &HASH32)),
    ]
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

fn wallet_with(utxos: Vec<SerializedUTXO>) -> WalletData {
    let mut w = wallet::import_wallet(Chain::Litecoin, TEST_MNEMONIC, 5_000_000).unwrap();
    w.unspent_utxos = utxos;
    w
}

/// The invariant: the fee charged covers the bytes actually produced, at the
/// rate the chain's params advertise.
fn assert_fee_covers_size(label: &str, txhex: &str, fee: u64) {
    let bytes = simd::hex::hex_string_to_bytes(txhex).len() as u64;
    let minimum = bytes * LITECOIN.fee_per_byte;
    assert!(
        fee >= minimum,
        "{label}: fee {fee} sat does not cover {bytes} bytes at {} sat/B ({minimum} sat). \
         The size model under-estimated, which is the direction that strands a transaction.",
        LITECOIN.fee_per_byte
    );
}

#[test]
fn every_output_form_is_paid_for() {
    for (label, addr) in every_form() {
        let mut w = wallet_with(vec![utxo("a", 0, 10_000_000)]);
        let rs = vec![Recipient { address: addr.clone(), amount: 1_000_000 }];
        let r = create_raw_transparent_transaction_to_many(Chain::Litecoin, &mut w, &seed(), &rs)
            .unwrap_or_else(|e| panic!("{label} send should build: {e}"));
        assert_fee_covers_size(label, &r.txhex, r.fee);
    }
}

#[test]
fn a_transaction_paying_every_form_at_once_is_paid_for() {
    // The mixed case, where a flat per-output allowance is least likely to
    // happen to land on the right answer.
    let forms = every_form();
    let rs: Vec<Recipient> = forms
        .iter()
        .map(|(_, a)| Recipient { address: a.clone(), amount: 500_000 })
        .collect();

    let mut w = wallet_with(vec![utxo("b", 0, 50_000_000)]);
    let r = create_raw_transparent_transaction_to_many(Chain::Litecoin, &mut w, &seed(), &rs)
        .expect("mixed-form send should build");
    assert_fee_covers_size("all forms at once", &r.txhex, r.fee);

    // And the outputs really are the four distinct scripts, not four copies of
    // one: a test that silently paid P2PKH four times would prove nothing.
    let decoded = common::decode(&simd::hex::hex_string_to_bytes(&r.txhex));
    let mut seen: HashSet<Vec<u8>> = HashSet::new();
    for (_, a) in &forms {
        seen.insert(address_to_script(Chain::Litecoin, a).unwrap());
    }
    assert_eq!(seen.len(), 4);
    for script in &seen {
        assert!(
            decoded.outputs.iter().any(|o| &o.script_pubkey == script),
            "a form's script is missing from the transaction"
        );
    }
}

#[test]
fn the_estimate_holds_as_signature_length_varies() {
    // DER signatures are 70 to 72 bytes depending on the key and nonce. The
    // per-input allowance must cover the longest, so walk HD slots until the
    // serialized size has been seen to move, then assert it did.
    let mut sizes = HashSet::new();
    let to = b58check(50, &HASH20);

    for index in 0..40u32 {
        let from = keys::transparent_address_at(Chain::Litecoin, &seed(), 0, index).unwrap();
        let script = address_to_script(Chain::Litecoin, &from).unwrap();
        let utxos = vec![SerializedUTXO {
            txid: "cd".repeat(32),
            vout: 0,
            amount: 10_000_000,
            script: simd::hex::bytes_to_hex_string(&script),
            height: 5_000_000,
            ..Default::default()
        }];
        let rs = vec![Recipient { address: to.clone(), amount: 5_000_000 }];

        let r = create_raw_transparent_transaction_from_utxos_to_many(
            Chain::Litecoin,
            &seed(),
            0,
            index,
            &utxos,
            &rs,
        )
        .unwrap_or_else(|e| panic!("slot 0/{index} should build: {e}"));

        sizes.insert(simd::hex::hex_string_to_bytes(&r.txhex).len());
        assert_fee_covers_size(&format!("hd slot 0/{index}"), &r.txhex, r.fee);
    }

    assert!(
        sizes.len() > 1,
        "signature length never varied across 40 keys, so this test is not exercising the \
         thing it claims to exercise"
    );
}

#[test]
fn the_estimate_holds_as_input_count_grows() {
    let to = bech32_v0("ltc", &HASH32); // the largest output form
    for n in 1..=12usize {
        let utxos: Vec<SerializedUTXO> = (0..n)
            .map(|i| utxo(&format!("{:x}", i % 16), i as u32, 2_000_000))
            .collect();
        let mut w = wallet_with(utxos);
        // Force every input to be selected by asking for nearly the whole balance.
        let rs = vec![Recipient { address: to.clone(), amount: (n as u64) * 2_000_000 - 500_000 }];
        let Ok(r) = create_raw_transparent_transaction_to_many(Chain::Litecoin, &mut w, &seed(), &rs)
        else {
            continue;
        };
        assert_fee_covers_size(&format!("{n} inputs"), &r.txhex, r.fee);
    }
}

#[test]
fn the_estimate_holds_when_change_is_dropped_as_dust() {
    // Dropping dust change raises the fee actually paid and shrinks the
    // transaction by one output. Both move the invariant in the safe
    // direction, but only a test proves the accounting stayed consistent.
    let to = b58check(48, &HASH20);
    for change_target in [0u64, 1, 500, 5_459] {
        let mut w = wallet_with(vec![utxo("f", 0, 10_000_000)]);
        let fee_est = pivx_wallet_kit::fees::estimate_raw_transparent_fee_for_scripts(
            Chain::Litecoin,
            1,
            &[25, 25],
        );
        let amount = 10_000_000 - fee_est - change_target;
        let rs = vec![Recipient { address: to.clone(), amount }];
        let Ok(r) = create_raw_transparent_transaction_to_many(Chain::Litecoin, &mut w, &seed(), &rs)
        else {
            continue;
        };
        assert_fee_covers_size(&format!("dust change {change_target}"), &r.txhex, r.fee);

        // Value conservation: inputs equal outputs plus fee, exactly.
        let decoded = common::decode(&simd::hex::hex_string_to_bytes(&r.txhex));
        let out_total: u64 = decoded.outputs.iter().map(|o| o.value).sum();
        assert_eq!(
            out_total + r.fee,
            10_000_000,
            "value leaked or was conjured at dust change {change_target}"
        );
    }
}

#[test]
fn value_is_conserved_across_every_form() {
    // The single most important arithmetic property in the crate: coins in
    // equals coins out plus fee. Checked per form, because output sizing
    // changed and the fee is derived from it.
    for (label, addr) in every_form() {
        let mut w = wallet_with(vec![utxo("a", 0, 10_000_000), utxo("b", 1, 3_000_000)]);
        let rs = vec![Recipient { address: addr, amount: 7_500_000 }];
        let r = create_raw_transparent_transaction_to_many(Chain::Litecoin, &mut w, &seed(), &rs)
            .unwrap_or_else(|e| panic!("{label}: {e}"));

        let decoded = common::decode(&simd::hex::hex_string_to_bytes(&r.txhex));
        let out_total: u64 = decoded.outputs.iter().map(|o| o.value).sum();
        let in_total: u64 = r
            .spent
            .iter()
            .map(|s| if s.vout == 0 { 10_000_000 } else { 3_000_000 })
            .sum();

        assert_eq!(out_total + r.fee, in_total, "{label}: value not conserved");
        assert_eq!(r.amount, 7_500_000, "{label}: reported amount wrong");
        // Every signature still verifies: paying a new script form must not
        // disturb the input side.
        assert_eq!(common::verify_all_signatures(&decoded), decoded.inputs.len());
    }
}

// ---------------------------------------------------------------------------

/// Minimal BIP173 encoder, independent of the `bech32` crate the kit uses.
/// Mirrors `litecoin_output_forms.rs`; kept local so this file stands alone.
fn bech32_v0(hrp: &str, program: &[u8]) -> String {
    const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    fn polymod(values: &[u8]) -> u32 {
        const GEN: [u32; 5] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3];
        let mut chk: u32 = 1;
        for v in values {
            let b = chk >> 25;
            chk = ((chk & 0x1ff_ffff) << 5) ^ (*v as u32);
            for (i, g) in GEN.iter().enumerate() {
                if (b >> i) & 1 == 1 {
                    chk ^= g;
                }
            }
        }
        chk
    }
    let mut data = vec![0u8];
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in program {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            data.push(((acc >> bits) & 31) as u8);
        }
    }
    if bits > 0 {
        data.push(((acc << (5 - bits)) & 31) as u8);
    }
    let mut values: Vec<u8> = hrp.bytes().map(|c| c >> 5).collect();
    values.push(0);
    values.extend(hrp.bytes().map(|c| c & 31));
    values.extend_from_slice(&data);
    values.extend_from_slice(&[0; 6]);
    let pm = polymod(&values) ^ 1;

    let mut s = String::from(hrp);
    s.push('1');
    for d in &data {
        s.push(CHARSET[*d as usize] as char);
    }
    for i in 0..6 {
        s.push(CHARSET[((pm >> (5 * (5 - i))) & 31) as usize] as char);
    }
    s
}
