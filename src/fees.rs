//! Component-based fee estimation for PIVX transactions.

/// Estimate the fee (in satoshis) for a transaction by component count.
///
/// Flat rate of 1000 sat/byte applied to a conservative size model:
/// - 948 bytes per Sapling output
/// - 384 bytes per Sapling input
/// - 180 bytes per transparent input (signed P2PKH)
/// - 34 bytes per transparent output
/// - 100 bytes of transaction overhead
#[inline]
pub fn estimate_fee(
    transparent_input_count: u64,
    transparent_output_count: u64,
    sapling_input_count: u64,
    sapling_output_count: u64,
) -> u64 {
    const FEE_PER_BYTE: u64 = 1000;
    FEE_PER_BYTE
        * (sapling_output_count * 948
            + sapling_input_count * 384
            + transparent_input_count * 180
            + transparent_output_count * 34
            + 100)
}

/// Legacy v1 transparent-only fee estimator (10 sat/byte).
///
/// Used by the raw P2PKH builder that bypasses the librustpivx v3 transaction
/// format. Matches the pre-kit agent-kit behaviour: ~150 bytes/input, ~34
/// bytes/output, ~10 bytes overhead.
#[inline]
pub fn estimate_raw_transparent_fee(input_count: usize, output_count: usize) -> u64 {
    estimate_raw_transparent_fee_with_extra(input_count, output_count, 0)
}

/// Bytes a serialized P2CS output costs beyond the flat per-output allowance.
///
/// The 34-byte figure above models a P2PKH output: 8 value + 1 length + 25
/// script. A cold-staking output carries a 51-byte script, so it serializes to
/// 60 bytes. Charging the flat rate for one would under-estimate the fee, and
/// under-estimating is the direction that strands a transaction unconfirmed.
pub const P2CS_OUTPUT_EXTRA_BYTES: usize = 26;

/// As [`estimate_raw_transparent_fee`], plus `extra_bytes` of output payload
/// the flat per-output figure does not cover.
///
/// Exists because the flat model assumes every output is P2PKH-sized. Rather
/// than let callers with larger scripts silently under-pay, they declare the
/// difference — see [`P2CS_OUTPUT_EXTRA_BYTES`].
#[inline]
pub fn estimate_raw_transparent_fee_with_extra(
    input_count: usize,
    output_count: usize,
    extra_bytes: usize,
) -> u64 {
    let est_size = input_count * 150 + output_count * 34 + extra_bytes + 10;
    (est_size as u64) * 10
}
