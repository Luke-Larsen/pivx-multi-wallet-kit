//! The assumptions the per-input fee allowance rests on.
//!
//! Every transparent fee estimate in this crate budgets 150 bytes per input.
//! That number is only correct because of three things that are true today and
//! nowhere asserted:
//!
//! 1. derived public keys are **compressed** (33 bytes, not 65),
//! 2. ECDSA signatures are **low-S normalized**, capping DER at 71 bytes,
//! 3. the scriptSig layout is `push(sig+sighash) || push(pubkey)`.
//!
//! Worst case that gives `32 + 4 + 1 + (1 + 72 + 1 + 33) + 4 = 148` bytes, so
//! the allowance has **2 bytes of headroom per input**. That is a thin margin
//! resting on three unstated facts, and if any of them changed the failure
//! would be a fee too small for the transaction it pays for: the node rejects
//! it, and the user finds out after pressing send.
//!
//! An uncompressed public key alone would take an input to 180 bytes and
//! under-pay by 30 bytes per input, silently, on every send.
//!
//! So this file states the three facts as assertions and measures real signed
//! transactions against the allowance. It exists because of MWK-1: a constant
//! that was plausible, unverified, and wrong shipped to an external adopter,
//! and the doc comment above it had already asked for exactly the check nobody
//! performed.

mod common;

use pivx_wallet_kit::params::Chain;
use pivx_wallet_kit::transparent::builder::{
    Recipient, create_raw_transparent_transaction_from_utxos_to_many,
};
use pivx_wallet_kit::wallet::SerializedUTXO;
use pivx_wallet_kit::{address, fees, keys, simd};

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// Bytes the fee model budgets per transparent input.
const MODELLED_INPUT_BYTES: usize = 150;

/// Largest a DER-encoded, low-S ECDSA signature can be on its own. Low-S
/// normalization is what caps it here: without it the S value can carry a
/// leading zero byte and push this to 72.
const MAX_DER_SIG_BYTES: usize = 71;

/// The same signature as it appears in a scriptSig, with the SIGHASH byte.
const MAX_SIG_WITH_SIGHASH: usize = MAX_DER_SIG_BYTES + 1;

/// A compressed secp256k1 point.
const COMPRESSED_PUBKEY_BYTES: usize = 33;

fn seed() -> Vec<u8> {
    bip39::Mnemonic::parse_normalized(TEST_MNEMONIC).unwrap().to_seed("").to_vec()
}

#[test]
fn derived_public_keys_are_compressed_on_both_chains() {
    // 65 bytes here would add 32 to every input and break the allowance
    // silently, because nothing else in the crate looks at this length.
    for chain in [Chain::Pivx, Chain::Litecoin] {
        for index in 0..25u32 {
            let (_, pubkey, _) =
                keys::transparent_key_from_bip39_seed(chain, &seed(), 0, index).unwrap();
            assert_eq!(
                pubkey.len(),
                COMPRESSED_PUBKEY_BYTES,
                "{chain:?} slot 0/{index}: uncompressed keys would under-pay every input by 32 bytes"
            );
            // A compressed point starts 0x02 or 0x03; 0x04 is the uncompressed
            // marker and would mean the length check above passed by accident.
            assert!(
                pubkey[0] == 0x02 || pubkey[0] == 0x03,
                "{chain:?} slot 0/{index}: leading byte {:#04x} is not a compressed point",
                pubkey[0]
            );
        }
    }
}

#[test]
fn the_worst_case_input_fits_the_allowance() {
    // Stated as arithmetic so a future change to any term is visible here
    // rather than only in a mainnet rejection.
    let script_sig = 1 + MAX_SIG_WITH_SIGHASH + 1 + COMPRESSED_PUBKEY_BYTES;
    let input = 32 + 4 + 1 + script_sig + 4;

    assert_eq!(script_sig, 107);
    assert_eq!(input, 148);
    assert!(
        input <= MODELLED_INPUT_BYTES,
        "worst-case input is {input} bytes against a {MODELLED_INPUT_BYTES}-byte allowance"
    );
}

#[test]
fn real_signed_inputs_never_exceed_the_allowance() {
    // The arithmetic above is a claim about the format. This measures what the
    // signer actually emits, across enough keys for signature length to vary.
    let mut max_seen = 0usize;
    let mut sig_lengths = std::collections::HashSet::new();

    for chain in [Chain::Pivx, Chain::Litecoin] {
        let to = keys::get_transparent_address(chain, TEST_MNEMONIC).unwrap();

        for index in 0..60u32 {
            let from = keys::transparent_address_at(chain, &seed(), 0, index).unwrap();
            let script = address::address_to_script(chain, &from).unwrap();
            let utxos = vec![SerializedUTXO {
                txid: "ab".repeat(32),
                vout: 0,
                amount: 10_000_000,
                script: simd::hex::bytes_to_hex_string(&script),
                height: 5_000_000,
                ..Default::default()
            }];
            let rs = vec![Recipient { address: to.clone(), amount: 5_000_000 }];

            let r = create_raw_transparent_transaction_from_utxos_to_many(
                chain, &seed(), 0, index, &utxos, &rs,
            )
            .unwrap_or_else(|e| panic!("{chain:?} slot 0/{index}: {e}"));

            let decoded = common::decode(&simd::hex::hex_string_to_bytes(&r.txhex));
            for txin in &decoded.inputs {
                // 32 txid + 4 vout + the scriptSig length prefix + scriptSig + 4 sequence.
                let prefix = if txin.script_sig.len() < 0xfd { 1 } else { 3 };
                let size = 32 + 4 + prefix + txin.script_sig.len() + 4;
                max_seen = max_seen.max(size);
                assert!(
                    size <= MODELLED_INPUT_BYTES,
                    "{chain:?} slot 0/{index}: a real input serialized to {size} bytes, over the \
                     {MODELLED_INPUT_BYTES}-byte allowance"
                );

                // Recover the signature length from the scriptSig to confirm
                // this loop is seeing variation rather than one lucky key.
                // `split_script_sig` returns the DER bytes with the trailing
                // SIGHASH byte already removed, and a flag for the cold-staking
                // selector, which an ordinary P2PKH spend never carries.
                let (sig_der, pubkey, cold_stake_selector) =
                    common::split_script_sig(&txin.script_sig);
                assert!(
                    !cold_stake_selector,
                    "an ordinary transparent spend must not carry a P2CS selector"
                );
                assert_eq!(pubkey.len(), COMPRESSED_PUBKEY_BYTES);
                assert!(
                    sig_der.len() <= MAX_DER_SIG_BYTES,
                    "signature of {} DER bytes exceeds the {MAX_DER_SIG_BYTES}-byte cap the \
                     allowance assumes; low-S normalization may no longer be in effect",
                    sig_der.len()
                );
                sig_lengths.insert(sig_der.len());
            }
        }
    }

    assert!(
        sig_lengths.len() > 1,
        "signature length never varied across 120 signatures, so this measured one case, not the \
         range: {sig_lengths:?}"
    );
    // Guard against the allowance quietly becoming enormous relative to
    // reality, which would be a different bug (over-charging every user).
    assert!(
        max_seen + 5 >= MODELLED_INPUT_BYTES,
        "largest real input was {max_seen} bytes against a {MODELLED_INPUT_BYTES}-byte allowance; \
         the model has drifted far from the format it claims to price"
    );
}

#[test]
fn the_dust_model_and_the_fee_model_agree_on_what_an_input_costs() {
    // `dust_threshold` prices the cost of spending an output at 148 bytes
    // while the fee estimator budgets 150. Both are defensible, but they are
    // two numbers for one thing, and a future edit is likely to move one and
    // not the other. Pin the relationship so that edit has to be deliberate.
    let dust_spend_size = 148usize;
    assert!(
        dust_spend_size <= MODELLED_INPUT_BYTES,
        "the dust model must not assume a cheaper input than the fee model budgets"
    );

    // And confirm the dust figure is actually the one in use, by reproducing
    // a known threshold from it rather than trusting the comment.
    let script_len = 25usize;
    let txout = 8 + 1 + script_len;
    let expected = (30_000u64 * (txout + dust_spend_size) as u64) / 1000;
    assert_eq!(expected, 5_460);
    assert_eq!(fees::dust_threshold(Chain::Litecoin, script_len), expected);
    assert_eq!(fees::dust_threshold(Chain::Pivx, script_len), expected);
}
