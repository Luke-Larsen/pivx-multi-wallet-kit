//! Dust is a policy, not a number, because the chains genuinely disagree.
//!
//! Bitcoin prices an output by what it would cost to spend, so the threshold
//! scales with the output's size. PIVX and Litecoin inherit that. Dogecoin sets
//! a flat floor and ignores size: its `CTxOut::IsDust` takes a `CAmount` and
//! compares `nValue < dustLimit`, where Bitcoin's takes a `CFeeRate`. The
//! signature change is deliberate and commented as such in their source.
//!
//! A rate cannot express a flat limit, which is why `ChainParams::dust` is an
//! enum. Note this is only true of dust: every chain here prices *fees* as a
//! rate, so `fee_per_byte` stays a plain number. Conflating the two is an easy
//! mistake and was made once already while planning Dogecoin support.
//!
//! The `Flat` branch has no chain using it yet, so these tests exercise it
//! through `dust_threshold_for` directly. Shipping an untested branch that
//! later decides whether a user's output is refused is exactly how the Litecoin
//! dust constant went wrong the first time.

use pivx_wallet_kit::fees::{dust_threshold, dust_threshold_for, is_dust};
use pivx_wallet_kit::params::{Chain, DustPolicy, LITECOIN, PIVX};

/// Dogecoin's figures, for the flat cases below.
/// `DEFAULT_DUST_LIMIT = RECOMMENDED_MIN_TX_FEE` (COIN/100) and
/// `DEFAULT_HARD_DUST_LIMIT = DEFAULT_DUST_LIMIT / 10`, both in `policy/policy.h`.
const DOGE_MINE: u64 = 1_000_000;
const DOGE_RELAY: u64 = 100_000;

/// Which of the two is the higher matters to the test below, so it is checked
/// at compile time rather than asserted at runtime where it folds to a constant.
const _: () = assert!(DOGE_MINE > DOGE_RELAY);

#[test]
fn neither_existing_chain_changed() {
    // The refactor's whole claim. 5460 sat for a 25-byte P2PKH output and 6240
    // for a 51-byte cold-staking one, exactly as before.
    for chain in [Chain::Pivx, Chain::Litecoin] {
        assert_eq!(dust_threshold(chain, 25), 5_460, "{chain:?} P2PKH");
        assert_eq!(dust_threshold(chain, 51), 6_240, "{chain:?} P2CS");
        assert_eq!(dust_threshold(chain, 22), 5_370, "{chain:?} P2WPKH");
        assert_eq!(dust_threshold(chain, 34), 5_730, "{chain:?} P2WSH");
    }
    assert_eq!(PIVX.dust, DustPolicy::PerByte { sat_per_kb: 30_000 });
    assert_eq!(LITECOIN.dust, DustPolicy::PerByte { sat_per_kb: 30_000 });
}

#[test]
fn a_rate_policy_scales_with_output_size() {
    let policy = DustPolicy::PerByte { sat_per_kb: 30_000 };
    let small = dust_threshold_for(policy, 22);
    let large = dust_threshold_for(policy, 34);
    assert!(large > small, "a bulkier output costs more to spend, so it must clear a higher bar");
    // 12 extra script bytes at 30 sat/byte.
    assert_eq!(large - small, 12 * 30);
}

#[test]
fn a_flat_policy_ignores_output_size_entirely() {
    // The property a rate cannot express, and the reason this is an enum.
    let policy = DustPolicy::Flat { relay: DOGE_RELAY, mine: DOGE_MINE };
    let thresholds: Vec<u64> = [0usize, 22, 23, 25, 34, 51, 520]
        .iter()
        .map(|&len| dust_threshold_for(policy, len))
        .collect();
    assert!(
        thresholds.windows(2).all(|w| w[0] == w[1]),
        "a flat limit must not vary with script length, got {thresholds:?}"
    );
}

#[test]
fn a_flat_policy_enforces_the_mining_limit_not_the_relay_limit() {
    // The deliberate choice. An output above the relay limit but below the
    // mining limit propagates and then never confirms, which leaves a user with
    // coins stranded in a transaction that looked accepted. Refusing to build
    // it is the failure they can actually act on.
    let policy = DustPolicy::Flat { relay: DOGE_RELAY, mine: DOGE_MINE };
    assert_eq!(dust_threshold_for(policy, 25), DOGE_MINE);
    assert_ne!(
        dust_threshold_for(policy, 25),
        DOGE_RELAY,
        "enforcing only the relay limit would permit outputs that relay and never confirm"
    );
}

#[test]
fn is_dust_follows_the_threshold_on_both_existing_chains() {
    for chain in [Chain::Pivx, Chain::Litecoin] {
        let floor = dust_threshold(chain, 25);
        assert!(is_dust(chain, floor - 1, 25), "{chain:?}: just under the floor is dust");
        assert!(!is_dust(chain, floor, 25), "{chain:?}: exactly at the floor is not dust");
        assert!(is_dust(chain, 0, 25), "{chain:?}: zero is dust");
    }
}

#[test]
fn a_zero_rate_yields_no_floor_rather_than_panicking() {
    // Not a configuration any real chain uses, but the arithmetic should not
    // divide or overflow its way into something surprising if one ever did.
    assert_eq!(dust_threshold_for(DustPolicy::PerByte { sat_per_kb: 0 }, 25), 0);
    assert_eq!(dust_threshold_for(DustPolicy::Flat { relay: 0, mine: 0 }, 25), 0);
}
