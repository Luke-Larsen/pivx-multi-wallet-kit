//! Withdrawing a delegation: P2CS inputs → an ordinary P2PKH output.
//!
//! Two things distinguish this from every other transparent spend, and both are
//! silent failures if wrong:
//!
//! 1. The sighash commits to the **P2CS** `scriptPubKey`, not a P2PKH one. Sign
//!    against the wrong prevout script and the signature is well-formed,
//!    verifies against nothing the network will check, and the transaction is
//!    rejected — with the coins still locked.
//! 2. The redeem script carries `OP_FALSE` to select the owner branch. Omit it
//!    and the script takes the staking branch, comparing the owner's key hash
//!    against the staker's.
//!
//! So the verifier here uses the real P2CS script as the prevout. A signature
//! that validates under it could not have been produced against a P2PKH
//! preimage, which is what makes this test meaningful rather than circular.

use pivx_wallet_kit::keys;
use pivx_wallet_kit::simd;
use pivx_wallet_kit::transparent::coldstake::{
    ColdStakeVariant, build_p2cs_script, create_coldstake_withdrawal,
    create_delegation_transaction, encode_staking_address, estimate_coldstake_withdrawal_fee,
    is_p2cs,
};
use pivx_wallet_kit::wallet::{self, SerializedUTXO, WalletData};
use sha2::{Digest, Sha256};

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

const STAKER: [u8; 20] = [0xAA; 20];

fn seed() -> Vec<u8> {
    bip39::Mnemonic::parse_normalized(TEST_MNEMONIC).unwrap().to_seed("").to_vec()
}

fn owner_hash(change: u32, index: u32) -> [u8; 20] {
    pivx_wallet_kit::transparent::coldstake::owner_hash_from_seed(&seed(), change, index).unwrap()
}

/// A delegated UTXO owned by the key at `change/index`.
fn delegated_utxo(letter: &str, vout: u32, amount: u64, change: u32, index: u32) -> SerializedUTXO {
    let script = build_p2cs_script(&STAKER, &owner_hash(change, index), ColdStakeVariant::Lof);
    SerializedUTXO {
        txid: letter.repeat(64),
        vout,
        amount,
        script: simd::hex::bytes_to_hex_string(&script),
        height: 5_000_000,
    }
}

fn wallet_with(utxos: Vec<SerializedUTXO>) -> WalletData {
    let mut w = wallet::import_wallet(TEST_MNEMONIC, 5_000_000).unwrap();
    w.unspent_utxos = utxos;
    w
}

// --- decoding, independent of the builder -----------------------------------

struct Decoded {
    version: u32,
    inputs: Vec<([u8; 32], u32, Vec<u8>, u32)>,
    outputs: Vec<(u64, Vec<u8>)>,
    locktime: u32,
    consumed_all: bool,
}

fn decode(bytes: &[u8]) -> Decoded {
    let varint = |p: &mut usize| -> u64 {
        let f = bytes[*p];
        match f {
            0xfd => { let v = u16::from_le_bytes(bytes[*p+1..*p+3].try_into().unwrap()) as u64; *p += 3; v }
            0xfe => { let v = u32::from_le_bytes(bytes[*p+1..*p+5].try_into().unwrap()) as u64; *p += 5; v }
            0xff => { let v = u64::from_le_bytes(bytes[*p+1..*p+9].try_into().unwrap()); *p += 9; v }
            n => { *p += 1; n as u64 }
        }
    };
    let version = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let mut p = 4usize;
    let n_in = varint(&mut p);
    let mut inputs = Vec::new();
    for _ in 0..n_in {
        let txid: [u8; 32] = bytes[p..p+32].try_into().unwrap(); p += 32;
        let vout = u32::from_le_bytes(bytes[p..p+4].try_into().unwrap()); p += 4;
        let sl = varint(&mut p) as usize;
        let script_sig = bytes[p..p+sl].to_vec(); p += sl;
        let seq = u32::from_le_bytes(bytes[p..p+4].try_into().unwrap()); p += 4;
        inputs.push((txid, vout, script_sig, seq));
    }
    let n_out = varint(&mut p);
    let mut outputs = Vec::new();
    for _ in 0..n_out {
        let value = u64::from_le_bytes(bytes[p..p+8].try_into().unwrap()); p += 8;
        let sl = varint(&mut p) as usize;
        outputs.push((value, bytes[p..p+sl].to_vec())); p += sl;
    }
    let locktime = u32::from_le_bytes(bytes[p..p+4].try_into().unwrap()); p += 4;
    Decoded { version, inputs, outputs, locktime, consumed_all: p == bytes.len() }
}

fn write_varint(out: &mut Vec<u8>, n: u64) {
    match n {
        0..=0xfc => out.push(n as u8),
        0xfd..=0xffff => { out.push(0xfd); out.extend_from_slice(&(n as u16).to_le_bytes()); }
        0x10000..=0xffff_ffff => { out.push(0xfe); out.extend_from_slice(&(n as u32).to_le_bytes()); }
        _ => { out.push(0xff); out.extend_from_slice(&n.to_le_bytes()); }
    }
}

fn sighash_all(tx: &Decoded, signing_index: usize, prevout_script: &[u8]) -> [u8; 32] {
    let mut pre = Vec::new();
    pre.extend_from_slice(&tx.version.to_le_bytes());
    write_varint(&mut pre, tx.inputs.len() as u64);
    for (i, (txid, vout, _, seq)) in tx.inputs.iter().enumerate() {
        pre.extend_from_slice(txid);
        pre.extend_from_slice(&vout.to_le_bytes());
        if i == signing_index {
            write_varint(&mut pre, prevout_script.len() as u64);
            pre.extend_from_slice(prevout_script);
        } else {
            pre.push(0x00);
        }
        pre.extend_from_slice(&seq.to_le_bytes());
    }
    write_varint(&mut pre, tx.outputs.len() as u64);
    for (value, script) in &tx.outputs {
        pre.extend_from_slice(&value.to_le_bytes());
        write_varint(&mut pre, script.len() as u64);
        pre.extend_from_slice(script);
    }
    pre.extend_from_slice(&tx.locktime.to_le_bytes());
    pre.extend_from_slice(&1u32.to_le_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(Sha256::digest(&pre)));
    out
}

/// Split a cold-staking redeem script: `<sig> OP_FALSE <pubkey>`.
fn split_coldstake_script_sig(script_sig: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let sig_push = script_sig[0] as usize;
    let sig_with_type = &script_sig[1..1 + sig_push];
    let (sig_der, hash_type) = sig_with_type.split_at(sig_with_type.len() - 1);
    assert_eq!(hash_type[0], 0x01, "expected SIGHASH_ALL");

    let selector_pos = 1 + sig_push;
    assert_eq!(
        script_sig[selector_pos], 0x00,
        "expected OP_FALSE selecting the owner branch"
    );

    let key_off = selector_pos + 1;
    let key_push = script_sig[key_off] as usize;
    let pubkey = &script_sig[key_off + 1..key_off + 1 + key_push];
    assert_eq!(key_off + 1 + key_push, script_sig.len(), "trailing bytes after pubkey");
    (sig_der.to_vec(), pubkey.to_vec())
}

/// Verify every input against the P2CS script it actually spends.
fn verify_against_p2cs(tx: &Decoded, prevout_scripts: &[Vec<u8>]) -> usize {
    let secp = secp256k1::Secp256k1::verification_only();
    for (i, (_, _, script_sig, _)) in tx.inputs.iter().enumerate() {
        let (sig_der, pubkey_bytes) = split_coldstake_script_sig(script_sig);
        let sighash = sighash_all(tx, i, &prevout_scripts[i]);
        let msg = secp256k1::Message::from_digest(sighash);
        let sig = secp256k1::ecdsa::Signature::from_der(&sig_der).unwrap();
        let pk = secp256k1::PublicKey::from_slice(&pubkey_bytes).unwrap();
        secp.verify_ecdsa(&msg, &sig, &pk).unwrap_or_else(|e| {
            panic!("input {i}: signature does not commit to the P2CS script it spends ({e})")
        });
    }
    tx.inputs.len()
}

fn to_address() -> String {
    keys::get_transparent_address(TEST_MNEMONIC).unwrap()
}

// --- tests ------------------------------------------------------------------

/// The core guarantee: the signature validates against the P2CS prevout script,
/// and the redeem script selects the owner branch.
#[test]
fn withdrawal_signs_against_the_p2cs_script() {
    let utxo = delegated_utxo("a", 0, 500_000_000, 0, 0);
    let prevout = simd::hex::hex_string_to_bytes(&utxo.script);
    assert!(is_p2cs(&prevout));

    let result = create_coldstake_withdrawal(
        &seed(), 0, 0, std::slice::from_ref(&utxo), &to_address(), 200_000_000,
    )
    .expect("withdrawal should build");

    let tx = decode(&simd::hex::hex_string_to_bytes(&result.txhex));
    assert!(tx.consumed_all, "trailing or missing bytes");
    assert_eq!(tx.inputs.len(), 1);
    assert_eq!(tx.outputs.len(), 2, "destination + change");

    // Destination is an ordinary P2PKH output — the delegation is over.
    assert_eq!(tx.outputs[0].1.len(), 25);
    assert!(!is_p2cs(&tx.outputs[0].1));
    assert_eq!(tx.outputs[0].0, 200_000_000);

    assert_eq!(verify_against_p2cs(&tx, &[prevout]), 1);

    let out_total: u64 = tx.outputs.iter().map(|(v, _)| v).sum();
    assert_eq!(500_000_000 - out_total, result.fee);
}

/// A signature made against a P2PKH preimage must NOT validate under the P2CS
/// prevout. This is what proves the previous test is not passing by accident —
/// the two preimages genuinely differ.
#[test]
fn a_p2pkh_preimage_would_not_satisfy_the_p2cs_input() {
    let utxo = delegated_utxo("b", 0, 500_000_000, 0, 0);
    let p2cs = simd::hex::hex_string_to_bytes(&utxo.script);

    let result = create_coldstake_withdrawal(
        &seed(), 0, 0, std::slice::from_ref(&utxo), &to_address(), 200_000_000,
    )
    .unwrap();
    let tx = decode(&simd::hex::hex_string_to_bytes(&result.txhex));

    // Correct prevout verifies.
    assert_eq!(verify_against_p2cs(&tx, &[p2cs.clone()]), 1);

    // The P2PKH script for the same owner key does not.
    let p2pkh = pivx_wallet_kit::transparent::coldstake::p2pkh_script_from_hash(&owner_hash(0, 0));
    assert_ne!(p2pkh, p2cs);
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_against_p2cs(&tx, &[p2pkh]);
    }))
    .is_err();
    assert!(
        panicked,
        "the signature verified under a P2PKH preimage too — the sighash is not committing to \
         the P2CS script"
    );
}

/// End to end: delegate, then spend that exact output back. The delegation's
/// own output becomes the withdrawal's input, so the two halves must agree on
/// the script byte-for-byte.
#[test]
fn delegate_then_withdraw_round_trip() {
    let staking = encode_staking_address(&STAKER);
    let mut w = wallet_with(vec![SerializedUTXO {
        txid: "c".repeat(64),
        vout: 0,
        amount: 500_000_000,
        script: String::new(),
        height: 5_000_000,
    }]);

    let delegation =
        create_delegation_transaction(&mut w, &seed(), &staking, 300_000_000, ColdStakeVariant::Lof)
            .expect("delegation should build");
    let dtx = decode(&simd::hex::hex_string_to_bytes(&delegation.txhex));
    let (value, p2cs_script) = dtx.outputs[0].clone();
    assert!(is_p2cs(&p2cs_script), "delegation output should be P2CS");

    // Feed that output straight back in as a delegated UTXO.
    let delegated = SerializedUTXO {
        txid: "d".repeat(64), // stand-in for the delegation's txid
        vout: 0,
        amount: value,
        script: simd::hex::bytes_to_hex_string(&p2cs_script),
        height: 5_000_001,
    };

    let withdrawal = create_coldstake_withdrawal(
        &seed(), 0, 0, std::slice::from_ref(&delegated), &to_address(), 100_000_000,
    )
    .expect("withdrawing the delegation we just built should work");

    let wtx = decode(&simd::hex::hex_string_to_bytes(&withdrawal.txhex));
    assert_eq!(verify_against_p2cs(&wtx, &[p2cs_script]), 1);
    assert!(!is_p2cs(&wtx.outputs[0].1), "withdrawal output should be plain P2PKH");
}

/// Several delegated inputs, each committing to its own script at its own
/// position.
#[test]
fn withdrawal_across_several_delegated_inputs() {
    let utxos = vec![
        delegated_utxo("a", 0, 200_000_000, 0, 0),
        delegated_utxo("b", 1, 200_000_000, 0, 0),
        delegated_utxo("c", 2, 200_000_000, 0, 0),
    ];
    let prevouts: Vec<Vec<u8>> = utxos
        .iter()
        .map(|u| simd::hex::hex_string_to_bytes(&u.script))
        .collect();

    let result =
        create_coldstake_withdrawal(&seed(), 0, 0, &utxos, &to_address(), 500_000_000).unwrap();
    let tx = decode(&simd::hex::hex_string_to_bytes(&result.txhex));

    assert_eq!(tx.inputs.len(), 3);
    assert_eq!(verify_against_p2cs(&tx, &prevouts), 3);
}

/// Withdrawal from a non-default HD slot, since a delegation's owner need not be
/// index 0.
#[test]
fn withdrawal_from_a_non_default_hd_slot() {
    let utxo = delegated_utxo("e", 0, 500_000_000, 0, 7);
    let prevout = simd::hex::hex_string_to_bytes(&utxo.script);

    let result = create_coldstake_withdrawal(
        &seed(), 0, 7, std::slice::from_ref(&utxo), &to_address(), 200_000_000,
    )
    .expect("slot 0/7 owns this delegation");
    let tx = decode(&simd::hex::hex_string_to_bytes(&result.txhex));
    assert_eq!(verify_against_p2cs(&tx, &[prevout]), 1);
}

/// Tampering after signing must invalidate.
#[test]
fn altering_a_withdrawal_invalidates_it() {
    let utxo = delegated_utxo("f", 0, 500_000_000, 0, 0);
    let prevout = simd::hex::hex_string_to_bytes(&utxo.script);
    let result = create_coldstake_withdrawal(
        &seed(), 0, 0, std::slice::from_ref(&utxo), &to_address(), 200_000_000,
    )
    .unwrap();

    let mut tx = decode(&simd::hex::hex_string_to_bytes(&result.txhex));
    assert_eq!(verify_against_p2cs(&tx, &[prevout.clone()]), 1);

    tx.outputs[0].0 += 1; // one satoshi
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_against_p2cs(&tx, &[prevout]);
    }))
    .is_err();
    assert!(panicked, "verifier accepted a tampered withdrawal");
}

#[test]
fn withdrawal_fee_exceeds_the_p2pkh_equivalent() {
    for n in 1..=4usize {
        let cold = estimate_coldstake_withdrawal_fee(n);
        let p2pkh = pivx_wallet_kit::fees::estimate_raw_transparent_fee(n, 2);
        assert!(cold > p2pkh, "{n} inputs: {cold} should exceed {p2pkh}");
        // Exactly one extra byte per input, at 10 sat/byte.
        assert_eq!(cold - p2pkh, (n as u64) * 10);
    }
}

#[test]
fn rejects_invalid_withdrawals() {
    let to = to_address();
    let good = delegated_utxo("a", 0, 500_000_000, 0, 0);

    // No UTXOs.
    assert!(create_coldstake_withdrawal(&seed(), 0, 0, &[], &to, 1_000).is_err());

    // Zero amount.
    assert!(
        create_coldstake_withdrawal(&seed(), 0, 0, std::slice::from_ref(&good), &to, 0).is_err()
    );

    // Missing script — the sighash needs it and it cannot be inferred.
    let mut no_script = good.clone();
    no_script.script = String::new();
    let err = create_coldstake_withdrawal(&seed(), 0, 0, &[no_script], &to, 1_000)
        .expect_err("a UTXO with no script must be rejected")
        .to_string();
    assert!(err.contains("no script"), "got: {err}");

    // A P2PKH script is not a delegation.
    let mut p2pkh_utxo = good.clone();
    p2pkh_utxo.script = simd::hex::bytes_to_hex_string(
        &pivx_wallet_kit::transparent::coldstake::p2pkh_script_from_hash(&owner_hash(0, 0)),
    );
    assert!(
        create_coldstake_withdrawal(&seed(), 0, 0, &[p2pkh_utxo], &to, 1_000).is_err(),
        "a P2PKH input must not be accepted as a delegation"
    );

    // Owned by a different key: signing it would produce a transaction the
    // network rejects, so it fails up front instead.
    let foreign = delegated_utxo("b", 0, 500_000_000, 0, 9);
    let err = create_coldstake_withdrawal(&seed(), 0, 0, &[foreign], &to, 1_000)
        .expect_err("a delegation owned by another key must be rejected")
        .to_string();
    assert!(err.contains("cannot sign"), "got: {err}");

    // Insufficient funds.
    let small = delegated_utxo("c", 0, 1_000_000, 0, 0);
    assert!(create_coldstake_withdrawal(&seed(), 0, 0, &[small], &to, 900_000_000).is_err());

    // Duplicate outpoints.
    assert!(
        create_coldstake_withdrawal(&seed(), 0, 0, &[good.clone(), good.clone()], &to, 1_000)
            .is_err(),
        "duplicate outpoints must be rejected on the withdrawal path too"
    );

    // Corrupted destination address.
    let bad_to = {
        let mut raw = bs58::decode(&to).into_vec().unwrap();
        raw[5] ^= 0x01;
        bs58::encode(raw).into_string()
    };
    assert!(
        create_coldstake_withdrawal(&seed(), 0, 0, std::slice::from_ref(&good), &bad_to, 1_000)
            .is_err()
    );
}

/// A V6-variant delegation must be withdrawable too — both variants are
/// spendable by the same owner path.
#[test]
fn withdraws_a_v6_variant_delegation() {
    let script = build_p2cs_script(&STAKER, &owner_hash(0, 0), ColdStakeVariant::V6);
    let utxo = SerializedUTXO {
        txid: "a".repeat(64),
        vout: 0,
        amount: 500_000_000,
        script: simd::hex::bytes_to_hex_string(&script),
        height: 5_000_000,
    };

    let result = create_coldstake_withdrawal(
        &seed(), 0, 0, std::slice::from_ref(&utxo), &to_address(), 200_000_000,
    )
    .expect("a V6 delegation should be withdrawable");
    let tx = decode(&simd::hex::hex_string_to_bytes(&result.txhex));
    assert_eq!(verify_against_p2cs(&tx, &[script]), 1);
}
