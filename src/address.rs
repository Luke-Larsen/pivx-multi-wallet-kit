//! Turning a destination address into the script that pays it.
//!
//! The kit derives and spends P2PKH outputs only: every key it holds is a
//! plain pubkey hash, every input it signs is P2PKH, and change always comes
//! back to its own P2PKH address. That is a statement about the *input* side
//! and it does not constrain who we can pay.
//!
//! The output side has to accept whatever the recipient uses. On Litecoin that
//! means `M...` P2SH addresses and `ltc1...` native segwit, because exchange
//! deposit addresses and every modern wallet's default receive address are one
//! of those. A wallet that can only pay `L...` can receive funds and send them
//! to other legacy wallets, which is a demo, not a wallet.
//!
//! Litecoin's older `3...` P2SH form is the exception, and it is refused. Its
//! version byte is byte-identical to Bitcoin's, so the address cannot say which
//! chain it belongs to, and the two sit side by side in every exchange deposit
//! UI. The error names the equivalent `M...` address so a legitimate payment is
//! one copy-paste away rather than a dead end.
//!
//! Paying a script we cannot ourselves spend is normal and safe: we are
//! building the recipient's output, and only they need to satisfy it.
//!
//! What this module refuses is the dangerous case. An address belonging to
//! another chain, or a form the chain does not have, is rejected rather than
//! coerced into a script, because a wrong guess here produces a
//! well-formed transaction that pays coins nobody can ever spend, and it is
//! only discovered after the money is gone.

use crate::params::Chain;
use std::error::Error;

/// Longest string any decoder here will look at.
///
/// BIP173 caps a segwit address at 90 characters; Base58Check addresses are 34.
/// The ceiling exists because both decoders cost more than linear in their
/// input, so an unbounded string is a denial of service on a function that sits
/// directly behind a paste field.
const MAX_ADDRESS_LEN: usize = 96;

/// The output form an address asks to be paid with.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OutputKind {
    /// `OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG`, 25 bytes.
    P2pkh,
    /// `OP_HASH160 <20> OP_EQUAL`, 23 bytes.
    P2sh,
    /// `OP_0 <20>`, 22 bytes.
    P2wpkh,
    /// `OP_0 <32>`, 34 bytes.
    P2wsh,
}

impl OutputKind {
    /// Serialized script length, which is what the fee and dust models need.
    pub const fn script_len(self) -> usize {
        match self {
            OutputKind::P2pkh => 25,
            OutputKind::P2sh => 23,
            OutputKind::P2wpkh => 22,
            OutputKind::P2wsh => 34,
        }
    }
}

/// A destination, decoded and validated against `chain`.
#[derive(Clone, Debug)]
pub struct Destination {
    pub kind: OutputKind,
    pub script: Vec<u8>,
}

/// Decode `address` and build the scriptPubKey that pays it on `chain`.
///
/// Accepts every address form the chain's own node would pay: P2PKH always,
/// plus P2SH and native segwit where [`crate::params::ChainParams`] declares
/// the chain has them. A chain that declares neither behaves exactly as it did
/// when this function was P2PKH-only.
pub fn address_to_destination(
    chain: Chain,
    address: &str,
) -> Result<Destination, Box<dyn Error>> {
    let params = chain.params();

    // Bound the work before any decoder sees it. BIP173 caps a segwit address
    // at 90 characters and a Base58Check address is 34, so nothing past this
    // can be valid, and both decoders get more expensive with length.
    if address.len() > MAX_ADDRESS_LEN {
        return Err(format!(
            "Address is {} characters; no address form on any supported chain exceeds \
             {MAX_ADDRESS_LEN}.",
            address.len()
        )
        .into());
    }

    // Segwit first: a bech32 string is not valid Base58Check, so trying it the
    // other way round produces a checksum error that explains nothing.
    if looks_like_bech32(address) {
        return decode_segwit(chain, address);
    }

    let (version, hash) = crate::base58check::decode_checked(address)?;

    if version == params.pubkey_prefix {
        return Ok(Destination {
            kind: OutputKind::P2pkh,
            script: p2pkh_script(&hash),
        });
    }

    if params.p2sh_prefixes.contains(&version) {
        return Ok(Destination {
            kind: OutputKind::P2sh,
            script: p2sh_script(&hash),
        });
    }

    // A version byte this chain accepts but does not own. Litecoin's legacy
    // `3...` P2SH prefix is byte-identical to Bitcoin's, so the string alone
    // cannot say which chain it is for, and the two are adjacent in every
    // exchange's deposit UI. Paying it is a coin flip: if the recipient watches
    // the other chain, the coins are gone and nothing about the transaction
    // looked wrong.
    //
    // Refuse, but do not leave the user stuck. The payload is a plain hash160,
    // so the same destination re-encodes losslessly into this chain's
    // unambiguous form, and naming it turns a dead end into one copy-paste.
    if params.p2sh_prefixes_ambiguous.contains(&version) {
        let unambiguous = params
            .p2sh_prefixes
            .first()
            .map(|p| crate::base58check::encode_checked(*p, &hash));
        let suggestion = match unambiguous {
            Some(a) => format!(
                " If you meant {chain:?}, the same destination in {chain:?}'s own form is {a} \
                 (verify it against the source you copied from before sending)."
            ),
            None => String::new(),
        };
        return Err(format!(
            "Address {address} uses version byte {version}, which {chain:?} accepts but shares \
             with another chain, so it is impossible to tell from the address which chain it \
             belongs to. Refusing to guess: paying the wrong one loses the coins \
             permanently.{suggestion}"
        )
        .into());
    }

    // Name what the chain does take, so a user pasting an address from the
    // wrong wallet is told which wallet they reached for.
    let mut accepted = format!("{}", params.pubkey_prefix);
    for p in params.p2sh_prefixes {
        accepted.push_str(&format!(", {p}"));
    }
    Err(format!(
        "Address {address} has version byte {version}, which is not a {chain:?} address. \
         {chain:?} uses version {accepted}. Paying it anyway would create an output no one \
         can spend."
    )
    .into())
}

/// As [`address_to_destination`], returning only the script.
pub fn address_to_script(chain: Chain, address: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(address_to_destination(chain, address)?.script)
}

/// Whether `address` is shaped like a bech32 string, so the segwit decoder
/// gets to produce the error message rather than Base58Check's checksum.
///
/// The load-bearing check is case: BIP173 forbids mixing upper and lower in
/// one string, while a Base58Check address for any chain here is inherently
/// mixed (its version byte forces a leading `L`, `M`, `D` or `3`). Without
/// that rule this misfires, because plenty of Base58 addresses contain a `1`
/// and happen to end in characters the bech32 alphabet also uses: the PIVX
/// address `DCHBhKiS7Lbps1YC4TMAPNxvG76vHSXCEj` is one, and it got routed to
/// the wrong decoder until this said otherwise.
fn looks_like_bech32(address: &str) -> bool {
    let has_upper = address.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = address.chars().any(|c| c.is_ascii_lowercase());
    if has_upper && has_lower {
        return false;
    }

    let lower = address.to_ascii_lowercase();
    let Some(sep) = lower.rfind('1') else {
        return false;
    };
    // An hrp of at least one character, and a data part long enough to hold
    // the 6-character checksum.
    if sep == 0 || lower.len() - sep - 1 < 6 {
        return false;
    }
    lower[sep + 1..]
        .chars()
        .all(|c| c.is_ascii_alphanumeric() && !matches!(c, '1' | 'b' | 'i' | 'o'))
}

fn decode_segwit(chain: Chain, address: &str) -> Result<Destination, Box<dyn Error>> {
    let Some(expected_hrp) = chain.params().bech32_hrp else {
        return Err(format!(
            "Address {address} looks like a segwit (bech32) address, which {chain:?} does not \
             have. Check the address belongs to the wallet's chain."
        )
        .into());
    };

    let (hrp, witness_version, program) = bech32::segwit::decode(address)
        .map_err(|e| format!("Address {address} is not a valid segwit address: {e}"))?;

    if !hrp.as_str().eq_ignore_ascii_case(expected_hrp) {
        return Err(format!(
            "Address {address} is a segwit address for '{}', not {chain:?}, which uses '{}'. \
             Paying it would send coins onto the wrong chain.",
            hrp.as_str(),
            expected_hrp
        )
        .into());
    }

    // Witness v0 only. v1 (taproot) does not exist on Litecoin, and paying an
    // unknown witness version creates an output that is anyone-can-spend under
    // current rules: exactly the silent loss this module exists to prevent.
    if witness_version.to_u8() != 0 {
        return Err(format!(
            "Address {address} is witness version {}, and this kit pays version 0 only. \
             Refusing rather than paying an output whose spending rules are not yet defined.",
            witness_version.to_u8()
        )
        .into());
    }

    match program.len() {
        20 => Ok(Destination {
            kind: OutputKind::P2wpkh,
            script: witness_v0_script(&program),
        }),
        32 => Ok(Destination {
            kind: OutputKind::P2wsh,
            script: witness_v0_script(&program),
        }),
        other => Err(format!(
            "Address {address} carries a {other}-byte witness program; version 0 defines only \
             20 (P2WPKH) and 32 (P2WSH)."
        )
        .into()),
    }
}

/// `OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG`
fn p2pkh_script(hash: &[u8; 20]) -> Vec<u8> {
    let mut script = Vec::with_capacity(25);
    script.extend_from_slice(&[0x76, 0xa9, 0x14]);
    script.extend_from_slice(hash);
    script.extend_from_slice(&[0x88, 0xac]);
    script
}

/// `OP_HASH160 <20> OP_EQUAL`
fn p2sh_script(hash: &[u8; 20]) -> Vec<u8> {
    let mut script = Vec::with_capacity(23);
    script.extend_from_slice(&[0xa9, 0x14]);
    script.extend_from_slice(hash);
    script.push(0x87);
    script
}

/// `OP_0 <program>`, for a 20- or 32-byte witness v0 program.
fn witness_v0_script(program: &[u8]) -> Vec<u8> {
    let mut script = Vec::with_capacity(2 + program.len());
    script.push(0x00);
    script.push(program.len() as u8);
    script.extend_from_slice(program);
    script
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_lengths_match_what_we_build() {
        // The fee and dust models size outputs from `script_len`, so a
        // mismatch between the constant and the builder silently misprices
        // every send to that address form.
        let cases: [(OutputKind, Vec<u8>); 4] = [
            (OutputKind::P2pkh, p2pkh_script(&[0x11; 20])),
            (OutputKind::P2sh, p2sh_script(&[0x22; 20])),
            (OutputKind::P2wpkh, witness_v0_script(&[0x33; 20])),
            (OutputKind::P2wsh, witness_v0_script(&[0x44; 32])),
        ];
        for (kind, script) in cases {
            assert_eq!(kind.script_len(), script.len(), "{kind:?}");
        }
    }

    #[test]
    fn bech32_shape_detection() {
        assert!(looks_like_bech32("ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"));
        assert!(looks_like_bech32("LTC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4"));
        // Base58Check addresses must not be routed to the segwit decoder.
        assert!(!looks_like_bech32("LUWPbpM43E2p7ZSh8cyTBEkvpHmr3cB8Ez"));
        assert!(!looks_like_bech32("DPo9TNvPwy2ZfmVM3CRCxbBvh6NojguWXJ"));
        // The one that actually caught this out: a `1`, and a tail drawn only
        // from characters bech32 also uses.
        assert!(!looks_like_bech32("DCHBhKiS7Lbps1YC4TMAPNxvG76vHSXCEj"));
        assert!(!looks_like_bech32(""));
        assert!(!looks_like_bech32("1abc"));
        // Mixed case is invalid bech32, so it is never routed there.
        assert!(!looks_like_bech32("ltc1QW508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"));
    }
}
