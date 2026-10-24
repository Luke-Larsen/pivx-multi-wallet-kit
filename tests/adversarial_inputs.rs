//! Hostile and malformed input, on the assumption that nothing reaching this
//! crate is trustworthy.
//!
//! UTXOs arrive from block explorers. Addresses and amounts arrive from a
//! JavaScript caller, which means ultimately from a text field. Neither is
//! validated by anything upstream of here, so every one of them is an input to
//! be attacked rather than a value to be believed.
//!
//! The failure that matters is not a panic. A panic in WASM aborts and the
//! user sees an error, which is unpleasant but safe. The failure that matters
//! is **a broadcastable transaction built from input we misread**, because the
//! money is gone before anyone knows. So these tests care about two outcomes
//! and no others: either a clear error, or a transaction that is correct. What
//! is never acceptable is a transaction that is wrong.
//!
//! The fuzzing here is a seeded xorshift loop rather than a property-testing
//! crate. That keeps the dependency count where it is, and makes every failure
//! reproducible from the seed printed in the assertion.

mod common;

use pivx_wallet_kit::address::address_to_script;
use pivx_wallet_kit::params::Chain;
use pivx_wallet_kit::transparent::builder::{
    Recipient, create_raw_transparent_transaction_to_many, max_sendable_transparent_to,
};
use pivx_wallet_kit::wallet::{self, SerializedUTXO, WalletData};
use pivx_wallet_kit::{keys, simd};

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn seed_bytes() -> Vec<u8> {
    bip39::Mnemonic::parse_normalized(TEST_MNEMONIC).unwrap().to_seed("").to_vec()
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

fn wallet_with(chain: Chain, utxos: Vec<SerializedUTXO>) -> WalletData {
    let mut w = wallet::import_wallet(chain, TEST_MNEMONIC, 5_000_000).unwrap();
    w.unspent_utxos = utxos;
    w
}

fn good_address(chain: Chain) -> String {
    keys::get_transparent_address(chain, TEST_MNEMONIC).unwrap()
}

/// Deterministic xorshift64*, so a failure is reproducible from its seed.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

// ---------------------------------------------------------------------------
// Address parsing: the new attack surface
// ---------------------------------------------------------------------------

#[test]
fn address_parsing_never_panics_on_arbitrary_bytes() {
    // The contract is "error or correct", never a crash and never a script
    // built from something we did not understand.
    let mut rng = Rng(0x1234_5678_9abc_def0);
    let alphabet: Vec<char> =
        "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1lIO0 \t\n:/\0é中"
            .chars()
            .collect();

    for iteration in 0..20_000 {
        let len = rng.below(90);
        let s: String = (0..len).map(|_| alphabet[rng.below(alphabet.len())]).collect();

        for chain in [Chain::Pivx, Chain::Litecoin] {
            // Must not panic. If it returns a script, that script must be a
            // shape we recognise, never arbitrary bytes.
            if let Ok(script) = address_to_script(chain, &s) {
                let recognised = script.len() == 25 || script.len() == 23 || script.len() == 22 || script.len() == 34;
                assert!(
                    recognised,
                    "iteration {iteration} (seed 0x123456789abcdef0), chain {chain:?}, input \
                     {s:?} produced a {}-byte script that matches no known output form",
                    script.len()
                );
            }
        }
    }
}

#[test]
fn addresses_with_whitespace_or_control_characters_are_refused() {
    // A pasted address commonly carries a trailing newline or a zero-width
    // character. Silently trimming would be worse than refusing: it invites
    // the caller to stop sanitising, and the one case where the stray
    // character was meaningful becomes a wrong payment.
    for chain in [Chain::Pivx, Chain::Litecoin] {
        let good = good_address(chain);
        assert!(address_to_script(chain, &good).is_ok(), "control: {good}");

        let hostile = [
            format!(" {good}"),
            format!("{good} "),
            format!("{good}\n"),
            format!("{good}\t"),
            format!("{good}\0"),
            format!("{good}\u{200b}"), // zero-width space
            format!("{}\u{feff}", good), // BOM
            good.replace('a', "а"),      // Cyrillic homoglyph, if present
        ];
        for h in hostile {
            if h == good {
                continue;
            }
            assert!(
                address_to_script(chain, &h).is_err(),
                "{chain:?}: {h:?} must be refused, not silently normalised"
            );
        }
    }
}

#[test]
fn an_enormous_address_string_is_refused_not_chewed_on() {
    for chain in [Chain::Pivx, Chain::Litecoin] {
        for len in [1_000usize, 100_000] {
            let huge = "L".repeat(len);
            assert!(address_to_script(chain, &huge).is_err());
            let huge_bech = format!("ltc1{}", "q".repeat(len));
            assert!(address_to_script(chain, &huge_bech).is_err());
        }
    }
}

#[test]
fn every_cross_chain_pairing_is_refused() {
    // The single most expensive mistake available: paying the right amount to
    // a well-formed address on the wrong chain.
    let pivx = good_address(Chain::Pivx);
    let ltc = good_address(Chain::Litecoin);

    assert!(address_to_script(Chain::Pivx, &ltc).is_err(), "LTC address on PIVX");
    assert!(address_to_script(Chain::Litecoin, &pivx).is_err(), "PIVX address on LTC");

    // And through the builder, not just the parser, since that is the path a
    // consumer actually reaches.
    let mut w = wallet_with(Chain::Litecoin, vec![utxo("a", 0, 10_000_000)]);
    let rs = vec![Recipient { address: pivx.clone(), amount: 1_000_000 }];
    assert!(create_raw_transparent_transaction_to_many(Chain::Litecoin, &mut w, &seed_bytes(), &rs).is_err());
}

// ---------------------------------------------------------------------------
// Amounts: overflow and conservation
// ---------------------------------------------------------------------------

#[test]
fn recipient_amounts_that_overflow_are_refused() {
    let chain = Chain::Litecoin;
    let to = good_address(chain);
    let mut w = wallet_with(chain, vec![utxo("a", 0, 10_000_000)]);

    let rs = vec![
        Recipient { address: to.clone(), amount: u64::MAX },
        Recipient { address: to.clone(), amount: u64::MAX },
    ];
    let err = create_raw_transparent_transaction_to_many(chain, &mut w, &seed_bytes(), &rs)
        .expect_err("summing two u64::MAX amounts must not wrap");
    assert!(
        err.to_string().to_lowercase().contains("overflow"),
        "error should name the overflow: {err}"
    );
}

#[test]
fn utxo_totals_that_overflow_are_refused() {
    // A hostile or broken explorer can report absurd values. Wrapping here
    // would make the wallet believe it holds coins it does not.
    let chain = Chain::Litecoin;
    let w = wallet_with(
        chain,
        vec![utxo("a", 0, u64::MAX), utxo("b", 1, u64::MAX), utxo("c", 2, u64::MAX)],
    );
    let to = good_address(chain);

    // Must not panic and must not report a wrapped maximum.
    let max = max_sendable_transparent_to(chain, &w, &[to.as_str()]);
    assert_eq!(max, 0, "an overflowing UTXO set must yield 0, not a wrapped value");

    // WalletData deliberately is not Clone (it carries secret material), so
    // rebuild rather than copy.
    let mut w2 = wallet_with(
        chain,
        vec![utxo("a", 0, u64::MAX), utxo("b", 1, u64::MAX), utxo("c", 2, u64::MAX)],
    );
    let rs = vec![Recipient { address: to, amount: 1_000_000 }];
    let _ = create_raw_transparent_transaction_to_many(chain, &mut w2, &seed_bytes(), &rs);
    // Either outcome is acceptable; a panic or a wrapped total is not.
}

#[test]
fn value_is_conserved_under_fuzzed_amounts() {
    // The invariant that must hold no matter what the caller asks for:
    // whatever is built, inputs equal outputs plus fee, exactly.
    let chain = Chain::Litecoin;
    let to = good_address(chain);
    let mut rng = Rng(0x0bad_c0ff_ee12_3456);

    for iteration in 0..600 {
        let n_utxos = 1 + rng.below(5);
        let utxos: Vec<SerializedUTXO> = (0..n_utxos)
            .map(|i| {
                let amount = 1 + (rng.next() % 50_000_000);
                utxo(&format!("{:x}", i % 16), i as u32, amount)
            })
            .collect();
        let in_total: u64 = utxos.iter().map(|u| u.amount).sum();
        let by_outpoint: std::collections::HashMap<(String, u32), u64> =
            utxos.iter().map(|u| ((u.txid.clone(), u.vout), u.amount)).collect();

        let mut w = wallet_with(chain, utxos);
        let amount = 1 + (rng.next() % (in_total + 1_000_000));
        let rs = vec![Recipient { address: to.clone(), amount }];

        let Ok(r) = create_raw_transparent_transaction_to_many(chain, &mut w, &seed_bytes(), &rs)
        else {
            continue; // refusing is always allowed
        };

        let decoded = common::decode(&simd::hex::hex_string_to_bytes(&r.txhex));
        let out_total: u64 = decoded.outputs.iter().map(|o| o.value).sum();
        let spent_total: u64 = r
            .spent
            .iter()
            .map(|s| by_outpoint[&(s.txid.clone(), s.vout)])
            .sum();

        assert_eq!(
            out_total + r.fee,
            spent_total,
            "iteration {iteration} (seed 0x0badc0ffee123456): value not conserved. \
             requested {amount}, spent {spent_total}, out {out_total}, fee {}",
            r.fee
        );
        assert!(
            out_total <= spent_total,
            "iteration {iteration}: outputs exceed inputs, coins conjured from nothing"
        );
        assert_eq!(r.amount, amount, "iteration {iteration}: reported amount disagrees");
        assert_eq!(
            common::verify_all_signatures(&decoded),
            decoded.inputs.len(),
            "iteration {iteration}: a signature does not verify"
        );
    }
}

#[test]
fn no_transaction_ever_spends_an_outpoint_twice() {
    // A repeated outpoint is a double-spend the network rejects outright, and
    // it is the kind of thing a fuzzed or hostile UTXO set produces.
    let chain = Chain::Litecoin;
    let to = good_address(chain);
    let mut rng = Rng(0xfeed_face_dead_beef);

    for _ in 0..300 {
        let n = 1 + rng.below(6);
        let utxos: Vec<SerializedUTXO> = (0..n)
            .map(|i| utxo(&format!("{:x}", rng.below(4)), (i % 3) as u32, 1 + rng.next() % 9_000_000))
            .collect();
        let mut w = wallet_with(chain, utxos);
        let rs = vec![Recipient { address: to.clone(), amount: 1_000_000 }];

        let Ok(r) = create_raw_transparent_transaction_to_many(chain, &mut w, &seed_bytes(), &rs)
        else {
            continue;
        };
        let decoded = common::decode(&simd::hex::hex_string_to_bytes(&r.txhex));
        let mut seen = std::collections::HashSet::new();
        for txin in &decoded.inputs {
            assert!(
                seen.insert((txin.prev_txid, txin.prev_vout)),
                "the same outpoint was spent twice in one transaction"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Explorer-supplied script data
// ---------------------------------------------------------------------------

#[test]
fn absurd_utxo_script_data_does_not_crash_selection() {
    let chain = Chain::Litecoin;
    let to = good_address(chain);

    let hostile_scripts = [
        String::new(),
        "zz".repeat(32),              // not hex
        "ab".repeat(10_000),          // enormous
        "a".to_string(),              // odd length
        "00".to_string(),             // trivially short
        "ff".repeat(520),             // past the script size limit
    ];

    for s in hostile_scripts {
        let mut u = utxo("a", 0, 10_000_000);
        u.script = s.clone();
        let mut w = wallet_with(chain, vec![u]);
        let rs = vec![Recipient { address: to.clone(), amount: 1_000_000 }];
        // Must not panic. Success or a clear error are both fine.
        let _ = create_raw_transparent_transaction_to_many(chain, &mut w, &seed_bytes(), &rs);
    }
}

#[test]
fn a_zero_amount_recipient_is_refused() {
    let chain = Chain::Litecoin;
    let mut w = wallet_with(chain, vec![utxo("a", 0, 10_000_000)]);
    let rs = vec![Recipient { address: good_address(chain), amount: 0 }];
    assert!(create_raw_transparent_transaction_to_many(chain, &mut w, &seed_bytes(), &rs).is_err());
}

#[test]
fn an_empty_recipient_list_is_refused() {
    let chain = Chain::Litecoin;
    let mut w = wallet_with(chain, vec![utxo("a", 0, 10_000_000)]);
    assert!(create_raw_transparent_transaction_to_many(chain, &mut w, &seed_bytes(), &[]).is_err());
}

// ---------------------------------------------------------------------------
// Regressions for what this file found
// ---------------------------------------------------------------------------

/// Found by `absurd_utxo_script_data_does_not_crash_selection`.
///
/// `hex_string_to_bytes` is an unchecked SIMD decoder: odd-length input trips a
/// debug assertion and, in release, silently drops the trailing nibble so the
/// script is classified on bytes nobody supplied. `parse_blockbook_utxos`
/// guarded against it at ingest, but `setUtxos` takes entries straight from a
/// JS caller and the docs specifically tell cold-staking consumers to join
/// `script` on themselves from a second explorer call, which never passes
/// through that guard.
#[test]
fn malformed_script_hex_is_reduced_to_unknown_not_decoded() {
    for raw in ["a", "abc", "zz", "xyz!", "ABCDEF0", "\u{feff}00"] {
        assert_eq!(
            wallet::sanitize_script_hex(raw),
            "",
            "{raw:?} is not decodable hex and must read as unknown"
        );
    }
    // Well-formed hex survives, normalised to lower case.
    assert_eq!(wallet::sanitize_script_hex("AABB"), "aabb");
    assert_eq!(wallet::sanitize_script_hex(""), "");
}

#[test]
fn a_utxo_carrying_malformed_script_hex_is_not_classified_as_delegated() {
    // The classification decides whether an output is excluded from ordinary
    // spending, so it must not run on garbage.
    for raw in ["a", "zz", "abc"] {
        let mut u = utxo("a", 0, 10_000_000);
        u.script = raw.to_string();
        assert!(
            !wallet::is_delegated_utxo(&u),
            "{raw:?} must read as unknown, not be decoded into a classification"
        );
    }
}

/// Found by `an_enormous_address_string_is_refused_not_chewed_on`, which took
/// over a minute before this was bounded.
///
/// Base58 decoding is quadratic: each digit multiplies a growing big-integer
/// accumulator. A 100,000-character paste is roughly 10^10 operations, which
/// is a denial of service on a function sitting directly behind an address
/// field. Nothing past the ceiling can be a valid address however long it is
/// decoded for, so length is checked before decoding rather than after.
#[test]
fn an_overlong_address_is_rejected_quickly() {
    use std::time::Instant;

    for chain in [Chain::Pivx, Chain::Litecoin] {
        for len in [10_000usize, 200_000] {
            for prefix in ["L", "D", "ltc1"] {
                let huge = format!("{prefix}{}", "q".repeat(len));
                let started = Instant::now();
                assert!(address_to_script(chain, &huge).is_err());
                let elapsed = started.elapsed();
                assert!(
                    elapsed.as_millis() < 250,
                    "{chain:?}: a {len}-character address took {elapsed:?} to refuse; the \
                     length guard is not bounding the decode"
                );
            }
        }
    }
}

#[test]
fn addresses_of_a_plausible_length_still_work() {
    // The guard must not be so tight that it refuses real addresses.
    for chain in [Chain::Pivx, Chain::Litecoin] {
        let good = good_address(chain);
        assert!(good.len() <= 40, "a real address is short: {} chars", good.len());
        assert!(address_to_script(chain, &good).is_ok());
    }
}
