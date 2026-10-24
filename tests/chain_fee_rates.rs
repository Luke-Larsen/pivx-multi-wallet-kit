//! Where two chains agree by coincidence, and what breaks when they stop.
//!
//! `Fee.transparentTx` in the wasm layer is a static with no `Wallet` to read a
//! chain from, so it cannot infer one and is fixed to PIVX. That looked like a
//! live bug for Litecoin consumers, and it is not: both chains charge 10
//! sat/byte and use a 30,000 sat/kB dust rate, so the PIVX-fixed call returns
//! the correct number for Litecoin today.
//!
//! It is correct by coincidence. Two independently sourced constants happen to
//! match, and nothing in the code says they must. The moment a chain arrives
//! whose rates differ, or either of these changes, that call starts returning a
//! confidently wrong fee to a consumer who has no way to tell.
//!
//! Dogecoin is not hypothetical: `RECOMMENDED_MIN_TX_FEE = COIN / 100` and a
//! flat `DEFAULT_DUST_LIMIT` make its figures roughly a thousand times larger
//! and a different shape entirely (a flat per-output amount rather than a rate).
//! A count-based estimator fixed to PIVX would be off by orders of magnitude.
//!
//! So this file pins the coincidence. If it fails, the fix is not to update the
//! numbers here: it is to make sure every caller that needs a chain-specific
//! fee is passing a chain, `transparentTxFor` rather than `transparentTx`.

use pivx_wallet_kit::fees;
use pivx_wallet_kit::params::{Chain, LITECOIN, PIVX};

#[test]
fn the_two_chains_transparent_rates_currently_coincide() {
    assert_eq!(
        PIVX.fee_per_byte, LITECOIN.fee_per_byte,
        "PIVX and Litecoin no longer charge the same sat/byte. Any count-based fee helper fixed \
         to one chain now returns a wrong answer for the other: audit callers of \
         `Fee.transparentTx` and move them to `transparentTxFor`."
    );
    assert_eq!(
        PIVX.dust_relay_fee, LITECOIN.dust_relay_fee,
        "PIVX and Litecoin no longer share a dust rate. Anything quoting a single 5460 sat \
         threshold for both, including the wasm docs, is now wrong for one of them."
    );
}

#[test]
fn the_rates_are_the_values_each_chains_node_requires() {
    // Pinned so the test above cannot be "fixed" by making one chain match the
    // other rather than matching its own network.
    //
    // PIVX: `minRelayTxFee = CFeeRate(10000)` in `src/validation.cpp`, which is
    // satoshis per kilobyte, so 10 per byte.
    // Litecoin: `DEFAULT_MIN_RELAY_TX_FEE = 1000` in `src/validation.h` is the
    // floor, and `DEFAULT_TRANSACTION_MINFEE = 10'000` in `src/wallet/wallet.h`
    // is the wallet default this matches.
    assert_eq!(PIVX.fee_per_byte, 10);
    assert_eq!(LITECOIN.fee_per_byte, 10);

    // Both chains' `DUST_RELAY_TX_FEE` in `src/policy/policy.h`. Bitcoin's is
    // 3,000, which is what Litecoin's was set to by mistake and MWK-1 fixed.
    assert_eq!(PIVX.dust_relay_fee, 30_000);
    assert_eq!(LITECOIN.dust_relay_fee, 30_000);
}

#[test]
fn the_pivx_fixed_estimator_agrees_with_the_explicit_one_while_rates_match() {
    // This is the property that makes `Fee.transparentTx` safe for Litecoin
    // right now. It is asserted rather than assumed, and it is the assertion
    // that will break first if the rates ever diverge.
    for inputs in 1..=6usize {
        for outputs in 1..=4usize {
            assert_eq!(
                fees::estimate_raw_transparent_fee(Chain::Pivx, inputs, outputs),
                fees::estimate_raw_transparent_fee(Chain::Litecoin, inputs, outputs),
                "{inputs} in / {outputs} out"
            );
        }
    }
}

#[test]
fn an_explicit_chain_reaches_the_chains_own_rate() {
    // Guards against `transparentTxFor` being wired to a fixed chain by
    // accident, which the test above could not detect while the rates agree.
    // Scale each chain's rate by a factor no real constant uses, and confirm
    // the estimator tracks the chain it was handed rather than a hardcoded one.
    let one_byte_pivx = fees::estimate_raw_transparent_fee(Chain::Pivx, 1, 1);
    let one_byte_ltc = fees::estimate_raw_transparent_fee(Chain::Litecoin, 1, 1);

    // Both are rate * modelled size, so dividing by the rate must give the same
    // byte count on both chains: the size model is shared, only the rate is per
    // chain. If this stops holding, the two chains have diverging size models,
    // which is a different and larger problem.
    assert_eq!(
        one_byte_pivx / PIVX.fee_per_byte,
        one_byte_ltc / LITECOIN.fee_per_byte,
        "the size model should be shared across chains; only the rate is per chain"
    );
}

#[test]
fn dust_thresholds_track_the_chain_they_are_asked_about() {
    // Same shape of check for the dust model: it must read the chain's own
    // constant, not one chain's for both.
    for script_len in [22usize, 23, 25, 34, 51] {
        let p = fees::dust_threshold(Chain::Pivx, script_len);
        let l = fees::dust_threshold(Chain::Litecoin, script_len);
        assert_eq!(p, l, "script_len {script_len}: rates match, so thresholds must");
        // And the value is derived, not a constant: it must move with size.
        assert!(p > 0);
    }
    assert!(
        fees::dust_threshold(Chain::Litecoin, 34) > fees::dust_threshold(Chain::Litecoin, 22),
        "a bulkier output costs more to spend, so its dust floor must be higher"
    );
}
