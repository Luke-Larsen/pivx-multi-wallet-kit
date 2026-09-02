//! Litecoin legacy P2PKH address validation.
//!
//! Mirrors `address_validation.rs`, but for `Chain::Litecoin`: the
//! Base58Check codec and P2PKH script shape are shared with PIVX (see
//! `src/base58check.rs`), so the only thing under test here is that the
//! Litecoin prefix (`0x30`, producing `L...`) is what actually gets checked,
//! not PIVX's `0x1e` by accident.

use pivx_wallet_kit::keys;
use pivx_wallet_kit::params::{Chain, LITECOIN, PIVX_PUBKEY_PREFIX};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn valid_address() -> String {
    keys::get_transparent_address(Chain::Litecoin, TEST_MNEMONIC).unwrap()
}

fn b58check(payload: &[u8]) -> String {
    let checksum = Sha256::digest(Sha256::digest(payload));
    let mut full = payload.to_vec();
    full.extend_from_slice(&checksum[..4]);
    bs58::encode(full).into_string()
}

fn decode_raw(address: &str) -> Vec<u8> {
    bs58::decode(address).into_vec().unwrap()
}

/// Litecoin's well-known convention: mainnet legacy P2PKH addresses start
/// with `L`. If this ever fails, `LITECOIN.pubkey_prefix` no longer encodes
/// to the expected leading character.
#[test]
fn a_derived_address_starts_with_l() {
    let addr = valid_address();
    assert!(
        addr.starts_with('L'),
        "expected a Litecoin address starting with 'L', got {addr}"
    );
}

#[test]
fn accepts_a_valid_address() {
    let addr = valid_address();
    let script = keys::address_to_p2pkh_script(Chain::Litecoin, &addr)
        .expect("valid address must be accepted");

    assert_eq!(script.len(), 25);
    assert_eq!(&script[..3], &[0x76, 0xa9, 0x14]);
    assert_eq!(&script[23..], &[0x88, 0xac]);
    assert_eq!(&script[3..23], &decode_raw(&addr)[1..21]);
}

#[test]
fn rejects_a_checksum_typo() {
    let addr = valid_address();
    let mut raw = decode_raw(&addr);
    raw[1] ^= 0x01;
    let typo = bs58::encode(&raw).into_string();
    assert!(keys::address_to_p2pkh_script(Chain::Litecoin, &typo).is_err());
}

/// A PIVX address must not be accepted as Litecoin, and vice versa: the two
/// chains share a codec but must not share an address space.
#[test]
fn pivx_and_litecoin_addresses_are_not_interchangeable() {
    let pivx_addr = keys::get_transparent_address(Chain::Pivx, TEST_MNEMONIC).unwrap();
    let ltc_addr = keys::get_transparent_address(Chain::Litecoin, TEST_MNEMONIC).unwrap();
    assert_ne!(pivx_addr, ltc_addr, "same key must render differently per chain");

    let err = keys::address_to_p2pkh_script(Chain::Litecoin, &pivx_addr)
        .expect_err("a PIVX address must not be accepted as a Litecoin one");
    assert!(err.to_string().contains("version byte"));

    let err = keys::address_to_p2pkh_script(Chain::Pivx, &ltc_addr)
        .expect_err("a Litecoin address must not be accepted as a PIVX one");
    assert!(err.to_string().contains("version byte"));
}

/// Every version byte other than Litecoin's must be refused against
/// `Chain::Litecoin`, exhaustively, the same guarantee `address_validation.rs`
/// pins for PIVX.
#[test]
fn accepts_only_the_litecoin_pubkey_version_byte() {
    let pkh = decode_raw(&valid_address())[1..21].to_vec();
    let mut accepted = Vec::new();

    for version in 0u8..=255 {
        let mut payload = vec![version];
        payload.extend_from_slice(&pkh);
        if keys::address_to_p2pkh_script(Chain::Litecoin, &b58check(&payload)).is_ok() {
            accepted.push(version);
        }
    }

    assert_eq!(
        accepted,
        vec![LITECOIN.pubkey_prefix],
        "exactly one version byte should be accepted"
    );
    assert_ne!(
        LITECOIN.pubkey_prefix, PIVX_PUBKEY_PREFIX,
        "the two chains must not share a prefix"
    );
}

/// Round-trip: a script built from a derived key's hash must match the script
/// built from that key's Litecoin address.
#[test]
fn script_matches_hash_of_the_derived_pubkey() {
    let mnemonic = bip39::Mnemonic::parse_normalized(TEST_MNEMONIC).unwrap();
    let seed = mnemonic.to_seed("");

    for index in [0u32, 1, 5, 99] {
        let (address, pubkey, _priv) =
            keys::transparent_key_from_bip39_seed(Chain::Litecoin, &seed, 0, index).unwrap();
        let script = keys::address_to_p2pkh_script(Chain::Litecoin, &address).unwrap();
        let expected = Ripemd160::digest(Sha256::digest(&pubkey));
        assert_eq!(
            &script[3..23],
            &expected[..],
            "index {index}: script hash does not match hash160(pubkey)"
        );
    }
}

/// Structurally malformed input must error rather than panic.
#[test]
fn rejects_malformed_input_without_panicking() {
    let cases = ["", "0", "L", "IlO0", &"1".repeat(200)];
    for c in cases {
        assert!(keys::address_to_p2pkh_script(Chain::Litecoin, c).is_err());
    }
}
