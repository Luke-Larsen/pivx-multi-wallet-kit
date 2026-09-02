//! One-off: generate a fresh, securely-random test wallet and print its
//! PIVX + Litecoin transparent addresses (never the mnemonic/private keys).
//!
//! Usage: cargo run --example generate_test_wallet

use pivx_wallet_kit::keys;
use pivx_wallet_kit::params::Chain;
use rand_core::RngCore;

fn main() {
    let mut entropy = [0u8; 32]; // 24-word mnemonic
    rand_core::OsRng.fill_bytes(&mut entropy);
    let mnemonic = bip39::Mnemonic::from_entropy(&entropy).unwrap();
    let bip39_seed = mnemonic.to_seed("");

    let (pivx_addr, _, _) =
        keys::transparent_key_from_bip39_seed(Chain::Pivx, &bip39_seed, 0, 0).unwrap();
    let (ltc_addr, _, _) =
        keys::transparent_key_from_bip39_seed(Chain::Litecoin, &bip39_seed, 0, 0).unwrap();

    // Mnemonic goes to a local file only, never stdout.
    let out_path = std::env::var("WALLET_OUT").unwrap_or_else(|_| "/tmp/test_wallet.txt".into());
    std::fs::write(&out_path, mnemonic.to_string()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&out_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    println!("PIVX address:     {pivx_addr}");
    println!("Litecoin address: {ltc_addr}");
    println!("mnemonic saved to: {out_path} (mode 600, not printed here)");
}
