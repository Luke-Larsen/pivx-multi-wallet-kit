//! Paying every address form a Litecoin node will pay.
//!
//! The kit spends P2PKH and nothing else, and for a while it paid P2PKH and
//! nothing else too. Those are different claims. The first is about the keys we
//! hold; the second was an accident of the address parser, and it left a wallet
//! that could receive Litecoin and send it to other legacy wallets but not to
//! an exchange, because deposit addresses are `ltc1...` or `M...`.
//!
//! Getting this wrong is expensive in one direction only. Refusing an address
//! we could have paid is an inconvenience. Building a script from an address we
//! misread pays coins into an output nobody can ever spend, and it is
//! discovered after the money is gone. So the rejection cases below matter at
//! least as much as the acceptance ones.
//!
//! The bech32 expectations here come from an independent encoder written at the
//! bottom of this file, not from the `bech32` crate the kit calls. A decoder
//! checked against itself agrees with itself even when both are wrong, which is
//! the whole reason `tests/common` reimplements transaction parsing rather than
//! reusing the builder's. The witness programs and the scripts they must
//! produce are fixed by BIP141 and written out literally.

mod common;

use pivx_wallet_kit::address::{OutputKind, address_to_destination, address_to_script};
use pivx_wallet_kit::params::Chain;
use pivx_wallet_kit::transparent::builder::{
    Recipient, create_raw_transparent_transaction_to_many, max_sendable_transparent_to,
};
use pivx_wallet_kit::wallet::{self, SerializedUTXO, WalletData};
use pivx_wallet_kit::{fees, keys, simd};
use sha2::{Digest, Sha256};
use std::error::Error;

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// The 20-byte program from the BIP173 worked example, reused here so the
/// values below can be checked against the BIP by eye.
const HASH20: [u8; 20] = [
    0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23,
    0xf1, 0x43, 0x3b, 0xd6,
];

const HASH32: [u8; 32] = [0x5a; 32];

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

// ---------------------------------------------------------------------------
// Acceptance: the four forms, and the exact scripts BIP141/BIP16 specify
// ---------------------------------------------------------------------------

#[test]
fn p2pkh_is_unchanged() {
    let addr = keys::get_transparent_address(Chain::Litecoin, TEST_MNEMONIC).unwrap();
    let d = address_to_destination(Chain::Litecoin, &addr).unwrap();
    assert_eq!(d.kind, OutputKind::P2pkh);
    assert_eq!(d.script.len(), 25);
    assert_eq!(&d.script[..3], &[0x76, 0xa9, 0x14]);
    assert_eq!(&d.script[23..], &[0x88, 0xac]);
}

#[test]
fn p2sh_pays_litecoins_own_version_byte() {
    let expected: Vec<u8> = [&[0xa9, 0x14][..], &HASH20[..], &[0x87][..]].concat();

    let addr = b58check(50, &HASH20);
    let d = address_to_destination(Chain::Litecoin, &addr).expect("M... must be accepted");
    assert_eq!(d.kind, OutputKind::P2sh);
    assert_eq!(d.script, expected);
    assert_eq!(d.script.len(), 23);
    assert!(addr.starts_with('M'), "this is the form wallets display");
}

/// Regression for the one cross-chain hole the first cut of this module left
/// open, found by the security review.
///
/// Litecoin Core accepts `SCRIPT_ADDRESS = 5` (`3...`) as well as
/// `SCRIPT_ADDRESS2 = 50` (`M...`), and the first implementation accepted both
/// because Litecoin does. But 5 is byte-identical to **Bitcoin's**
/// `SCRIPT_ADDRESS`: same prefix, same 20-byte hash, same checksum, no hrp and
/// no network tag. A `3...` string carries nothing that says which chain it is
/// for, which is precisely why Litecoin introduced the `M...` form.
///
/// The realistic loss: a user copies the Bitcoin deposit address from an
/// exchange page instead of the Litecoin one, sitting inches away in the same
/// UI. It decodes cleanly, prices cleanly, signs cleanly, and the LTC lands at
/// a script hash the exchange only watches on Bitcoin. Nothing looked wrong at
/// any point.
///
/// Before bech32 support this could not happen, because only version 48 was
/// accepted. Accepting 5 newly created the hazard, so it is refused by default.
#[test]
fn the_ambiguous_legacy_p2sh_form_is_refused() {
    let addr = b58check(5, &HASH20);
    assert!(addr.starts_with('3'), "this is the Bitcoin-shaped form");

    let err = address_to_destination(Chain::Litecoin, &addr)
        .expect_err("a version byte shared with Bitcoin must not be paid on a guess");
    let msg = err.to_string();

    assert!(
        msg.contains("shares with another chain"),
        "the error must say why it is refused, not just that it is: {msg}"
    );
}

#[test]
fn refusing_the_ambiguous_form_offers_the_unambiguous_one() {
    // A dead end would push users toward pasting it somewhere less careful.
    // The payload is a plain hash160, so the same destination re-encodes
    // losslessly into Litecoin's own form, and the error names it.
    let ambiguous = b58check(5, &HASH20);
    let expected = b58check(50, &HASH20);

    let err = address_to_destination(Chain::Litecoin, &ambiguous).unwrap_err();
    let msg = err.to_string();

    assert!(
        msg.contains(&expected),
        "error should name the {expected} equivalent so the user can act on it: {msg}"
    );

    // And that suggestion must itself be payable, and pay the identical script.
    let suggested = address_to_destination(Chain::Litecoin, &expected).unwrap();
    let direct: Vec<u8> = [&[0xa9, 0x14][..], &HASH20[..], &[0x87][..]].concat();
    assert_eq!(
        suggested.script, direct,
        "the form we recommend must pay exactly what the original asked for"
    );
}

#[test]
fn p2wpkh_builds_the_script_bip141_specifies() {
    let addr = independent_bech32::encode_segwit_v0("ltc", &HASH20);
    let d = address_to_destination(Chain::Litecoin, &addr).unwrap();

    assert_eq!(d.kind, OutputKind::P2wpkh);
    // OP_0 PUSH20 <program>
    let expected: Vec<u8> = [&[0x00, 0x14][..], &HASH20[..]].concat();
    assert_eq!(d.script, expected);
    assert_eq!(d.script.len(), 22);
}

#[test]
fn p2wsh_builds_the_script_bip141_specifies() {
    let addr = independent_bech32::encode_segwit_v0("ltc", &HASH32);
    let d = address_to_destination(Chain::Litecoin, &addr).unwrap();

    assert_eq!(d.kind, OutputKind::P2wsh);
    let expected: Vec<u8> = [&[0x00, 0x20][..], &HASH32[..]].concat();
    assert_eq!(d.script, expected);
    assert_eq!(d.script.len(), 34);
}

#[test]
fn bech32_is_case_insensitive_as_a_whole() {
    let lower = independent_bech32::encode_segwit_v0("ltc", &HASH20);
    let upper = lower.to_ascii_uppercase();

    let a = address_to_script(Chain::Litecoin, &lower).unwrap();
    let b = address_to_script(Chain::Litecoin, &upper).unwrap();
    assert_eq!(a, b, "BIP173 allows either case, as long as it is not mixed");

    // Mixed case is explicitly invalid and must not be quietly accepted.
    let mut mixed = lower.clone();
    mixed.replace_range(4..5, &lower[4..5].to_ascii_uppercase());
    if mixed != lower {
        assert!(
            address_to_script(Chain::Litecoin, &mixed).is_err(),
            "mixed-case bech32 must be refused"
        );
    }
}

#[test]
fn script_len_constants_match_the_scripts_actually_built() {
    // The fee and dust models size outputs from `OutputKind::script_len`.
    // If that disagrees with the builder, every send to that form is mispriced.
    let cases = [
        (b58check(48, &HASH20), OutputKind::P2pkh),
        (b58check(50, &HASH20), OutputKind::P2sh),
        (independent_bech32::encode_segwit_v0("ltc", &HASH20), OutputKind::P2wpkh),
        (independent_bech32::encode_segwit_v0("ltc", &HASH32), OutputKind::P2wsh),
    ];
    for (addr, kind) in cases {
        let d = address_to_destination(Chain::Litecoin, &addr).unwrap();
        assert_eq!(d.kind, kind);
        assert_eq!(d.kind.script_len(), d.script.len(), "{kind:?}");
    }
}

// ---------------------------------------------------------------------------
// Rejection: the cases that would silently burn coins
// ---------------------------------------------------------------------------

#[test]
fn a_litecoin_segwit_address_is_refused_on_pivx() {
    let addr = independent_bech32::encode_segwit_v0("ltc", &HASH20);
    let err = address_to_script(Chain::Pivx, &addr).expect_err("PIVX has no segwit");
    let msg = err.to_string();
    assert!(msg.contains("segwit"), "error should say why: {msg}");
}

#[test]
fn a_bitcoin_segwit_address_is_refused_on_litecoin() {
    // Same witness program, different chain. Decodes perfectly; paying it
    // would put Litecoin into a Bitcoin script.
    let addr = independent_bech32::encode_segwit_v0("bc", &HASH20);
    let err = address_to_script(Chain::Litecoin, &addr).expect_err("wrong chain");
    let msg = err.to_string();
    assert!(msg.contains("wrong chain") || msg.contains("'bc'"), "got: {msg}");
}

#[test]
fn a_pivx_shield_address_is_refused_on_litecoin() {
    // `ps1...` is bech32-shaped, so it reaches the segwit decoder and must be
    // turned away on hrp rather than mistaken for a Litecoin destination.
    let shield = "ps1qqpqq9syrk8ajn5j9g8r5g0w8tqxk7pqsk8vqhz6qx9x5n5ypcvmgxp2f5x8s3q2t8hxv";
    assert!(address_to_script(Chain::Litecoin, shield).is_err());
}

#[test]
fn taproot_and_unknown_witness_versions_are_refused() {
    // Litecoin has no taproot. A version we do not understand must never be
    // paid: under current rules an unknown witness program is spendable by
    // anyone, so a "successful" send would be a donation.
    for version in [1u8, 2, 16] {
        let addr = independent_bech32::encode_segwit("ltc", version, &HASH20);
        let err = address_to_script(Chain::Litecoin, &addr)
            .expect_err("witness version {version} must be refused");
        assert!(
            err.to_string().contains("version"),
            "error should name the version: {err}"
        );
    }
}

#[test]
fn wrong_witness_program_lengths_are_refused() {
    for len in [2usize, 19, 21, 31, 33, 40] {
        let program = vec![0x11u8; len];
        let addr = independent_bech32::encode_segwit_v0("ltc", &program);
        assert!(
            address_to_script(Chain::Litecoin, &addr).is_err(),
            "a {len}-byte witness v0 program must be refused"
        );
    }
}

#[test]
fn a_corrupted_bech32_checksum_is_refused() {
    let good = independent_bech32::encode_segwit_v0("ltc", &HASH20);
    for i in (good.len() - 6)..good.len() {
        let mut bad = good.clone();
        let c = bad.as_bytes()[i];
        let swap = if c == b'q' { 'p' } else { 'q' };
        bad.replace_range(i..i + 1, &swap.to_string());
        assert!(
            address_to_script(Chain::Litecoin, &bad).is_err(),
            "a corrupted checksum character must be refused: {bad}"
        );
    }
}

#[test]
fn p2sh_is_still_refused_on_pivx() {
    // PIVX declares no P2SH prefixes, so its parser must behave exactly as it
    // did before this file existed.
    let addr = b58check(13, &HASH20);
    assert!(address_to_script(Chain::Pivx, &addr).is_err());
    // And Litecoin's P2SH must not be payable as PIVX either.
    assert!(address_to_script(Chain::Pivx, &b58check(50, &HASH20)).is_err());
}

// ---------------------------------------------------------------------------
// End to end: a real signed transaction paying each form
// ---------------------------------------------------------------------------

fn wallet_holding(amount: u64) -> WalletData {
    let mut w = wallet::import_wallet(Chain::Litecoin, TEST_MNEMONIC, 5_000_000).unwrap();
    w.unspent_utxos = vec![SerializedUTXO {
        txid: "b".repeat(64),
        vout: 0,
        amount,
        script: String::new(),
        height: 5_000_000,
        ..Default::default()
    }];
    w
}

fn send_to(address: &str, amount: u64) -> Result<(Vec<u8>, u64), Box<dyn Error>> {
    let mut w = wallet_holding(10_000_000);
    let rs = vec![Recipient { address: address.to_string(), amount }];
    let r = create_raw_transparent_transaction_to_many(Chain::Litecoin, &mut w, &seed(), &rs)?;
    Ok((simd::hex::hex_string_to_bytes(&r.txhex), r.fee))
}

#[test]
fn a_send_to_each_form_produces_the_right_output_script() {
    let cases = [
        (b58check(48, &HASH20), 25usize),
        (b58check(50, &HASH20), 23),
        (independent_bech32::encode_segwit_v0("ltc", &HASH20), 22),
        (independent_bech32::encode_segwit_v0("ltc", &HASH32), 34),
    ];

    for (addr, script_len) in cases {
        let (tx, _fee) = send_to(&addr, 1_000_000).expect("send should build");
        let decoded = common::decode(&tx);

        let expected = address_to_script(Chain::Litecoin, &addr).unwrap();
        assert_eq!(decoded.outputs[0].script_pubkey, expected, "for {addr}");
        assert_eq!(decoded.outputs[0].script_pubkey.len(), script_len, "for {addr}");
        assert_eq!(decoded.outputs[0].value, 1_000_000);

        // The inputs are still ours and still P2PKH, so the signature must
        // verify exactly as it does for a legacy send. Paying a new script
        // form changes the output side only.
        assert_eq!(common::verify_all_signatures(&decoded), decoded.inputs.len());
    }
}

#[test]
fn the_fee_is_sized_by_the_real_output_script() {
    // A P2WPKH output is 3 bytes smaller than a P2PKH one and a P2WSH output
    // 9 bytes larger. Charging the flat P2PKH figure for a P2WSH recipient
    // under-pays, which is the direction that strands a transaction.
    let p2pkh = send_to(&b58check(48, &HASH20), 1_000_000).unwrap().1;
    let p2sh = send_to(&b58check(50, &HASH20), 1_000_000).unwrap().1;
    let p2wpkh = send_to(&independent_bech32::encode_segwit_v0("ltc", &HASH20), 1_000_000)
        .unwrap()
        .1;
    let p2wsh = send_to(&independent_bech32::encode_segwit_v0("ltc", &HASH32), 1_000_000)
        .unwrap()
        .1;

    let rate = 10; // Litecoin fee_per_byte
    assert_eq!(p2pkh - p2sh, 2 * rate, "P2SH output is 2 bytes smaller");
    assert_eq!(p2pkh - p2wpkh, 3 * rate, "P2WPKH output is 3 bytes smaller");
    assert_eq!(p2wsh - p2pkh, 9 * rate, "P2WSH output is 9 bytes larger");
}

#[test]
fn max_sendable_is_sized_by_the_destination() {
    let w = wallet_holding(10_000_000);

    let to_p2pkh = b58check(48, &HASH20);
    let to_p2wsh = independent_bech32::encode_segwit_v0("ltc", &HASH32);

    let max_p2pkh = max_sendable_transparent_to(Chain::Litecoin, &w, &[to_p2pkh.as_str()]);
    let max_p2wsh = max_sendable_transparent_to(Chain::Litecoin, &w, &[to_p2wsh.as_str()]);

    // The bulkier output costs more fee, so less is sendable.
    assert!(max_p2wsh < max_p2pkh);
    assert_eq!(max_p2pkh - max_p2wsh, 9 * 10);

    // Whatever it offers must actually build, which is the contract that makes
    // the figure safe to put in a UI.
    for (addr, max) in [(&to_p2pkh, max_p2pkh), (&to_p2wsh, max_p2wsh)] {
        send_to(addr, max).unwrap_or_else(|e| panic!("max of {max} must be buildable: {e}"));
    }
}

#[test]
fn max_sendable_returns_zero_for_an_address_this_chain_cannot_pay() {
    let w = wallet_holding(10_000_000);
    let bitcoin = independent_bech32::encode_segwit_v0("bc", &HASH20);
    assert_eq!(
        max_sendable_transparent_to(Chain::Litecoin, &w, &[bitcoin.as_str()]),
        0
    );
}

#[test]
fn dust_is_measured_against_the_forms_own_script() {
    // Dust rises with output size, so the floor differs per form. A P2WSH
    // output must clear a higher bar than a P2WPKH one.
    let p2wpkh_floor = fees::dust_threshold(Chain::Litecoin, 22);
    let p2wsh_floor = fees::dust_threshold(Chain::Litecoin, 34);
    assert!(p2wsh_floor > p2wpkh_floor);

    let to_p2wsh = independent_bech32::encode_segwit_v0("ltc", &HASH32);
    let err = send_to(&to_p2wsh, p2wsh_floor - 1).expect_err("below the floor must be refused");
    assert!(err.to_string().contains("dust threshold"), "got: {err}");

    send_to(&to_p2wsh, p2wsh_floor).expect("exactly at the floor must build");
}

// ---------------------------------------------------------------------------
// An independent bech32 encoder, per BIP173
// ---------------------------------------------------------------------------
//
// Shares no code with the `bech32` crate the kit decodes with, so agreement
// between the two is evidence rather than tautology.
mod independent_bech32 {
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

    fn hrp_expand(hrp: &str) -> Vec<u8> {
        let mut v: Vec<u8> = hrp.bytes().map(|c| c >> 5).collect();
        v.push(0);
        v.extend(hrp.bytes().map(|c| c & 31));
        v
    }

    /// 8-bit to 5-bit regrouping, padding the final group with zeroes.
    fn convert_bits(data: &[u8]) -> Vec<u8> {
        let mut acc: u32 = 0;
        let mut bits: u32 = 0;
        let mut out = Vec::new();
        for &b in data {
            acc = (acc << 8) | b as u32;
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                out.push(((acc >> bits) & 31) as u8);
            }
        }
        if bits > 0 {
            out.push(((acc << (5 - bits)) & 31) as u8);
        }
        out
    }

    /// Encode a segwit address at an explicit witness version.
    ///
    /// Version 0 uses the BIP173 checksum constant (1); versions 1 and above
    /// use BIP350's (0x2bc830a3). Both are implemented so the rejection tests
    /// can hand the kit a well-formed address it still has to refuse.
    pub fn encode_segwit(hrp: &str, witness_version: u8, program: &[u8]) -> String {
        let mut data = vec![witness_version];
        data.extend(convert_bits(program));

        let konst: u32 = if witness_version == 0 { 1 } else { 0x2bc8_30a3 };
        let mut values = hrp_expand(hrp);
        values.extend_from_slice(&data);
        values.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        let pm = polymod(&values) ^ konst;

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

    pub fn encode_segwit_v0(hrp: &str, program: &[u8]) -> String {
        encode_segwit(hrp, 0, program)
    }

    #[test]
    fn matches_the_bip173_worked_example() {
        // BIP173's own vector: hrp "bc", witness v0, the 20-byte program used
        // throughout this file. If this line is wrong, every expectation
        // built on this module is worthless.
        let program: [u8; 20] = [
            0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c, 0x45, 0xd1, 0xb3,
            0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6,
        ];
        assert_eq!(
            encode_segwit_v0("bc", &program),
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        );
    }
}
