//! Base58Check: the version-byte-prefixed, checksummed address codec shared
//! by every Bitcoin-descended chain this kit supports.
//!
//! Lives outside `keys`/`transparent::coldstake` so neither has to depend on
//! the other just to share it: both encode/decode the identical 25-byte
//! `version || hash160 || checksum` shape, differing only in which version
//! byte a caller passes.

use sha2::{Digest, Sha256};
use std::error::Error;

/// Decode a Base58Check address, returning `(version, hash160)`.
///
/// Validates length and the double-SHA256 checksum; does not check the
/// version byte against any particular chain/address-kind, since callers
/// (P2PKH, cold-staking) each accept a different set of versions.
pub(crate) fn decode_checked(address: &str) -> Result<(u8, [u8; 20]), Box<dyn Error>> {
    let decoded = bs58::decode(address)
        .into_vec()
        .map_err(|e| format!("Invalid base58 address: {e}"))?;
    if decoded.len() != 25 {
        return Err(format!(
            "Invalid address length: {} bytes, expected 25 (1 version + 20 hash + 4 checksum)",
            decoded.len()
        )
        .into());
    }

    let (payload, checksum) = decoded.split_at(21);
    let expected = Sha256::digest(Sha256::digest(payload));
    if expected[..4] != checksum[..] {
        return Err(format!(
            "Invalid address checksum for {address}: the address is mistyped or corrupted"
        )
        .into());
    }

    let mut hash = [0u8; 20];
    hash.copy_from_slice(&payload[1..21]);
    Ok((payload[0], hash))
}

/// Base58Check-encode `hash160` under `version`.
pub(crate) fn encode_checked(version: u8, hash: &[u8; 20]) -> String {
    let mut payload = Vec::with_capacity(25);
    payload.push(version);
    payload.extend_from_slice(hash);
    let checksum = Sha256::digest(Sha256::digest(&payload));
    payload.extend_from_slice(&checksum[..4]);
    bs58::encode(payload).into_string()
}
