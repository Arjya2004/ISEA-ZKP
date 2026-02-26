/**
 * range_proof.circom
 * 
 * CRCS Circuit 2: Range Proof (Greater-Than Check)
 * 
 * Proves that a private value x is greater than a public threshold,
 * without revealing x.
 * 
 * This uses circomlib's comparator components which work on n-bit values.
 * For BN254, attribute values must fit within the chosen bit-width.
 * 
 * We use 64-bit comparisons which supports values up to 2^64 - 1.
 * This covers any practical attribute value (age, income in paise, etc.)
 * 
 * Dependencies: circomlib
 */

pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

/**
 * RangeProof: Prove x > threshold without revealing x.
 * 
 * Private inputs:
 *   - x: the attribute value to prove about
 * 
 * Public inputs:
 *   - threshold: the comparison value
 * 
 * Public outputs:
 *   - out: 1 if x > threshold, 0 otherwise (enforced to be 1)
 * 
 * Bit width: 64 bits (supports values up to ~1.8 * 10^19)
 * Constraints: ~450 (bit decomposition + comparison)
 */
template RangeProof(n) {
    // Private input
    signal input x;

    // Public input
    signal input threshold;

    // Output signal (will be constrained to 1)
    signal output out;

    // Use GreaterThan: checks if in[0] > in[1]
    component gt = GreaterThan(n);
    gt.in[0] <== x;
    gt.in[1] <== threshold;

    // Force the proof to only be valid if x > threshold
    // If x <= threshold, the circuit will produce out = 0 and the constraint fails
    gt.out === 1;

    out <== gt.out;
}

// Use 64-bit range proof by default
component main {public [threshold]} = RangeProof(64);
