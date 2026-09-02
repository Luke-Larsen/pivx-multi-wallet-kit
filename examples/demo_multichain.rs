//! Live side-by-side demo: derive addresses, sign/verify a message, and
//! build a signed raw transaction for both PIVX and Litecoin from the same
//! seed, using synthetic UTXOs (no network access).
//!
//! Usage: cargo run --example demo_multichain

use pivx_wallet_kit::params::Chain;
use pivx_wallet_kit::transparent::builder::{
    Recipient, create_raw_transparent_transaction_from_utxos,
    create_raw_transparent_transaction_from_utxos_to_many,
};
use pivx_wallet_kit::wallet::SerializedUTXO;
use pivx_wallet_kit::{keys, messages};

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn demo(chain: Chain, label: &str) {
    println!("=== {label} ===");

    let bip39_seed = bip39::Mnemonic::parse_normalized(MNEMONIC)
        .unwrap()
        .to_seed("");

    // Derive the default transparent address + key.
    let (address, _pubkey, privkey) =
        keys::transparent_key_from_bip39_seed(chain, &bip39_seed, 0, 0).unwrap();
    println!("address:      {address}");

    // Sign and verify a message with the chain's own magic string.
    let message = format!("hello from {label}");
    let signature = messages::sign_message(chain, &privkey, &message).unwrap();
    let verified = messages::verify_message(chain, &address, &message, &signature).unwrap();
    println!("signature:    {signature}");
    println!("verified:     {verified}");

    // Build a raw signed transaction spending a synthetic UTXO.
    let utxo = SerializedUTXO {
        txid: "a".repeat(64),
        vout: 0,
        amount: 100_000_000,
        script: String::new(),
        height: 5_000_000,
        ..Default::default()
    };
    let recipient_seed = bip39::Mnemonic::parse_normalized(
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
    )
    .unwrap()
    .to_seed("");
    let (to_address, _, _) =
        keys::transparent_key_from_bip39_seed(chain, &recipient_seed, 0, 0).unwrap();

    let result = create_raw_transparent_transaction_from_utxos(
        chain,
        &bip39_seed,
        0,
        0,
        &[utxo],
        &to_address,
        50_000_000,
    )
    .unwrap();
    println!("send to:      {to_address}");
    println!("fee:          {} sat", result.fee);
    println!("tx bytes:     {}", result.txhex.len() / 2);
    println!("tx hex:       {}...{}", &result.txhex[..32], &result.txhex[result.txhex.len() - 16..]);

    // Multi-recipient, to show the shared builder handles it identically.
    let recipients = vec![
        Recipient { address: to_address.clone(), amount: 30_000_000 },
        Recipient { address: address.clone(), amount: 10_000_000 },
    ];
    let multi = create_raw_transparent_transaction_from_utxos_to_many(
        chain,
        &bip39_seed,
        0,
        0,
        &[SerializedUTXO {
            txid: "b".repeat(64),
            vout: 1,
            amount: 100_000_000,
            script: String::new(),
            height: 5_000_000,
            ..Default::default()
        }],
        &recipients,
    );
    println!("multi-out ok: {}", multi.is_ok());
    println!();
}

fn main() {
    demo(Chain::Pivx, "PIVX");
    demo(Chain::Litecoin, "Litecoin");

    // Cross-chain isolation: a signature made for one chain must not verify
    // under the other chain's magic/address.
    let bip39_seed = bip39::Mnemonic::parse_normalized(MNEMONIC).unwrap().to_seed("");
    let (pivx_addr, _, pivx_priv) =
        keys::transparent_key_from_bip39_seed(Chain::Pivx, &bip39_seed, 0, 0).unwrap();
    let sig = messages::sign_message(Chain::Pivx, &pivx_priv, "cross-chain check").unwrap();
    let cross_verify =
        messages::verify_message(Chain::Litecoin, &pivx_addr, "cross-chain check", &sig)
            .unwrap_or(false);
    println!(
        "=== Cross-chain isolation ===\na PIVX signature verified as Litecoin: {cross_verify} (must be false)"
    );
}
