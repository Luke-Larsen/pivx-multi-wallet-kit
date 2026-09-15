//! Litecoin's dust rate is Litecoin's, not Bitcoin's.
//!
//! `LITECOIN.dust_relay_fee` shipped as 3,000, which is Bitcoin Core's
//! `DUST_RELAY_TX_FEE`. Litecoin Core's is 30,000 (`src/policy/policy.h`), the
//! same figure PIVX uses. The two chains agree on the relay *floor*
//! (`DEFAULT_MIN_RELAY_TX_FEE` 1,000) and disagree by ten times on the dust
//! rate, so a constant borrowed from the wrong one looks entirely plausible
//! sitting next to its neighbours.
//!
//! The cost of getting it wrong is not a rejected constant, it is a rejected
//! transaction. At 3,000 the crate put the P2PKH floor at 546 sat while a node
//! held it at 5,460, so any change output landing between the two was emitted
//! rather than dropped, and the finished transaction came back from the
//! network as `-26: dust` with nothing in the wallet to explain why.
//!
//! Every local test passed throughout, because none of them compared the
//! crate's threshold to the network's. This file does that, and then checks
//! the two places the number actually changes behaviour: change that must be
//! dropped, and a recipient that must be refused.

mod common;

use pivx_wallet_kit::params::{Chain, LITECOIN, PIVX};
use pivx_wallet_kit::transparent::builder::{
    Recipient, create_raw_transparent_transaction_to_many,
};
use pivx_wallet_kit::wallet::{self, SerializedUTXO, WalletData};
use pivx_wallet_kit::{fees, keys, simd};
use std::error::Error;

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// `DUST_RELAY_TX_FEE` in `src/policy/policy.h` of Litecoin Core master.
const LITECOIN_CORE_DUST_RELAY_TX_FEE: u64 = 30_000;

/// The same constant in Bitcoin Core, which is what this crate had. Present so
/// that a future edit back to Bitcoin's value fails a named assertion rather
/// than silently passing a range check.
const BITCOIN_CORE_DUST_RELAY_TX_FEE: u64 = 3_000;

/// A 25-byte P2PKH output priced at Litecoin's dust rate: 30,000 * (8 + 1 + 25
/// + 148) / 1000. This is the figure `GetDustThreshold` yields on a real node.
const P2PKH_DUST_SAT: u64 = 5_460;

fn seed() -> Vec<u8> {
    bip39::Mnemonic::parse_normalized(TEST_MNEMONIC).unwrap().to_seed("").to_vec()
}

fn address() -> String {
    keys::get_transparent_address(Chain::Litecoin, TEST_MNEMONIC).unwrap()
}

fn wallet_holding(amount: u64) -> WalletData {
    let mut w = wallet::import_wallet(Chain::Litecoin, TEST_MNEMONIC, 5_000_000).unwrap();
    w.unspent_utxos = vec![SerializedUTXO {
        txid: "a".repeat(64),
        vout: 0,
        amount,
        script: String::new(),
        height: 5_000_000,
        ..Default::default()
    }];
    w
}

fn send(utxo_amount: u64, pay: u64) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut w = wallet_holding(utxo_amount);
    let rs = vec![Recipient { address: address(), amount: pay }];
    let r = create_raw_transparent_transaction_to_many(Chain::Litecoin, &mut w, &seed(), &rs)?;
    Ok(simd::hex::hex_string_to_bytes(&r.txhex))
}

#[test]
fn litecoin_dust_rate_comes_from_litecoin_core() {
    assert_eq!(
        LITECOIN.dust_relay_fee, LITECOIN_CORE_DUST_RELAY_TX_FEE,
        "LITECOIN.dust_relay_fee must be Litecoin Core's DUST_RELAY_TX_FEE"
    );
    assert_ne!(
        LITECOIN.dust_relay_fee, BITCOIN_CORE_DUST_RELAY_TX_FEE,
        "this is Bitcoin Core's dust rate, not Litecoin's: Litecoin is ten times higher"
    );
}

#[test]
fn both_chains_price_dust_the_same() {
    // Not a coincidence worth hiding: PIVX and Litecoin both carry 30,000, so
    // a P2PKH output has the same floor on either chain. Documentation that
    // quotes 5460 is therefore correct for both.
    assert_eq!(LITECOIN.dust_relay_fee, PIVX.dust_relay_fee);
    assert_eq!(
        fees::dust_threshold(Chain::Litecoin, 25),
        fees::dust_threshold(Chain::Pivx, 25)
    );
}

#[test]
fn p2pkh_dust_threshold_matches_a_real_node() {
    assert_eq!(fees::dust_threshold(Chain::Litecoin, 25), P2PKH_DUST_SAT);

    // The old value put the floor here. Anything in between was the bug.
    assert!(fees::is_dust(Chain::Litecoin, 546, 25));
    assert!(fees::is_dust(Chain::Litecoin, P2PKH_DUST_SAT - 1, 25));
    assert!(!fees::is_dust(Chain::Litecoin, P2PKH_DUST_SAT, 25));
}

#[test]
fn change_a_node_would_call_dust_is_dropped_into_the_fee() {
    // The fee model always budgets for a change output, so change is exactly
    // `utxo - pay - fee` and can be aimed precisely.
    let utxo = 1_000_000;
    let fee = fees::estimate_raw_transparent_fee(Chain::Litecoin, 1, 2);
    let change = 1_000;
    let pay = utxo - fee - change;

    // Sits in the gap between the crate's old floor and the network's.
    assert!(change > 546 && change < P2PKH_DUST_SAT);

    let tx = send(utxo, pay).expect("send should build");
    let decoded = common::decode(&tx);

    assert_eq!(
        decoded.outputs.len(),
        1,
        "change of {change} sat is below Litecoin's {P2PKH_DUST_SAT} sat dust threshold and must \
         go to the miner, not into an output that makes the whole transaction unrelayable"
    );
    assert_eq!(decoded.outputs[0].value, pay);
}

#[test]
fn change_above_the_threshold_is_still_emitted() {
    // The guard against overcorrecting: real change must survive.
    let utxo = 1_000_000;
    let fee = fees::estimate_raw_transparent_fee(Chain::Litecoin, 1, 2);
    let change = P2PKH_DUST_SAT + 1;
    let pay = utxo - fee - change;

    let tx = send(utxo, pay).expect("send should build");
    let decoded = common::decode(&tx);

    assert_eq!(decoded.outputs.len(), 2, "change above the threshold belongs in an output");
    assert_eq!(decoded.outputs[1].value, change);
}

#[test]
fn a_recipient_a_node_would_call_dust_is_refused() {
    // 2,000 sat cleared the old 546 floor and would have been built into a
    // transaction the network then rejected. It has to fail here instead.
    let err = send(1_000_000, 2_000).expect_err("a dust recipient must be refused");
    let msg = err.to_string();

    assert!(
        msg.contains("dust threshold"),
        "error should name the dust threshold, got: {msg}"
    );
    assert!(
        msg.contains(&P2PKH_DUST_SAT.to_string()),
        "error should quote the real {P2PKH_DUST_SAT} sat minimum, got: {msg}"
    );
}
